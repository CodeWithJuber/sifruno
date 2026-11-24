package hostaccounts

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type client struct {
	socket     string
	http       *http.Client
	slow       *http.Client // the WordPress install, which takes minutes
	long       *http.Client // backups, restores, drills and prunes: up to two hours
	configured bool
}

func NewClient(socket string) Service {
	c := &client{socket: socket, configured: runtime.GOOS == "linux" && validSocketName(socket)}
	c.http = &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return connectBroker(ctx, c.socket) }}}
	slow := *c.http
	slow.Timeout = wordpressTimeout + 2*time.Minute
	c.slow = &slow
	long := *c.http
	long.Timeout = backupTimeout + 2*time.Minute
	c.long = &long
	return c
}
func validSocketName(s string) bool {
	return s != "" && len(s) <= 100 && filepath.IsAbs(s) && filepath.Clean(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}
func (c *client) Capability(ctx context.Context) (Capability, error) {
	if ctx == nil {
		return Capability{}, ErrInvalid
	}
	if !c.configured {
		return unavailable("linux_broker_not_configured"), nil
	}
	var out Capability
	err := c.request(ctx, "GET", "/v1/capability", nil, &out)
	if err != nil {
		return unavailable("linux_broker_unavailable"), nil
	}
	return out, nil
}
func (c *client) List(ctx context.Context) ([]Account, error) {
	var out struct {
		Items []Account `json:"items"`
	}
	err := c.requestBounded(ctx, "GET", "/v1/accounts", nil, &out, maxListResponseBytes)
	if err != nil {
		return nil, err
	}
	if out.Items == nil {
		out.Items = []Account{}
	}
	if len(out.Items) > MaxAccounts {
		return nil, ErrUnavailable
	}
	return out.Items, nil
}
func (c *client) Create(ctx context.Context, in CreateInput, actor string) (Account, error) {
	if !validCreate(in, actor) {
		return Account{}, ErrInvalid
	}
	var out Account
	// A create writes the account's slice limits and may reload systemd,
	// which can take minutes on a busy host, so it has the slow limit.
	err := c.send(ctx, c.slow, "POST", "/v1/accounts", struct {
		Input CreateInput `json:"input"`
		Actor string      `json:"actor"`
	}{in, actor}, &out, maxResponseBytes)
	return out, err
}
func (c *client) SetState(ctx context.Context, id string, in StateInput, actor string) (Account, error) {
	if !idPattern.MatchString(id) || !validState(in, actor) {
		return Account{}, ErrInvalid
	}
	var out Account
	// Suspending or resuming an account with a live site rewrites the web
	// server's config, which can take minutes on a busy host. A 422
	// web_rejected answer means that config failed its test and was restored:
	// the account is unchanged.
	err := c.send(ctx, c.slow, "POST", "/v1/accounts/"+id+"/state", struct {
		Input StateInput `json:"input"`
		Actor string     `json:"actor"`
	}{in, actor}, &out, maxResponseBytes)
	return out, err
}
func (c *client) SetPlan(ctx context.Context, id string, in PlanInput, actor string) (Account, error) {
	if !idPattern.MatchString(id) || !validPlan(in, actor) {
		return Account{}, ErrInvalid
	}
	var out Account
	// New limits for an account with a live site rewrite the web server's
	// config, which can take minutes on a busy host. A 422 web_rejected
	// answer means that config failed its test and was restored, and 503
	// unavailable that the limits could not be applied: either way the
	// account is unchanged.
	err := c.send(ctx, c.slow, "POST", "/v1/accounts/"+id+"/plan", struct {
		Input PlanInput `json:"input"`
		Actor string    `json:"actor"`
	}{in, actor}, &out, maxResponseBytes)
	return out, err
}
func (c *client) Delete(ctx context.Context, id string, in DeleteInput, actor string) (Account, error) {
	if !idPattern.MatchString(id) || !validDelete(in, actor) {
		return Account{}, ErrInvalid
	}
	var out Account
	// A delete first rewrites the web server's config, which can take
	// minutes on a busy host. A 409 delete_busy answer means the account's
	// processes kept running, so nothing was removed: ErrDeleteBusy.
	err := c.send(ctx, c.slow, "POST", "/v1/accounts/"+id+"/delete", struct {
		Input DeleteInput `json:"input"`
		Actor string      `json:"actor"`
	}{in, actor}, &out, maxResponseBytes)
	return out, err
}

// AdoptPublicHTML asks the broker to record the account's current
// public_html as its site folder. A 409 conflict answer means the folder is
// missing, a link, or not the account's, or the revision moved; 503
// recovery means what only root controls changed too. Either way nothing
// changed.
func (c *client) AdoptPublicHTML(ctx context.Context, id string, in AdoptInput, actor string) (Account, error) {
	if !idPattern.MatchString(id) || !validAdopt(in, actor) {
		return Account{}, ErrInvalid
	}
	var out Account
	err := c.request(ctx, "POST", "/v1/accounts/"+id+"/public-html", struct {
		Input AdoptInput `json:"input"`
		Actor string     `json:"actor"`
	}{in, actor}, &out)
	return out, err
}

// maxResponseBytes bounds every broker answer except the account list, whose
// size grows with the inventory: one account is well under 16 KiB of JSON,
// with its site's aliases and its certificate's domains (up to 16 names of
// 253 bytes each).
const maxResponseBytes = 256 << 10
const maxListResponseBytes = MaxAccounts * (16 << 10)

func (c *client) SSHKeys(ctx context.Context, id string) (SSHKeysResult, error) {
	if !idPattern.MatchString(id) {
		return SSHKeysResult{}, ErrInvalid
	}
	var out SSHKeysResult
	err := c.request(ctx, "GET", "/v1/accounts/"+id+"/ssh-keys", nil, &out)
	return out, err
}

func (c *client) SetSSHKeys(ctx context.Context, id string, in SSHKeysInput, actor string) (SSHKeysResult, error) {
	if _, _, ok := normalizeSSHKeys(in.Keys); !ok || !idPattern.MatchString(id) || in.ExpectedRevision == 0 || !validText(in.Reason, 500) || !validText(actor, 120) {
		return SSHKeysResult{}, ErrInvalid
	}
	if in.Keys == nil {
		in.Keys = []string{}
	}
	var out SSHKeysResult
	err := c.request(ctx, "POST", "/v1/accounts/"+id+"/ssh-keys", struct {
		Input SSHKeysInput `json:"input"`
		Actor string       `json:"actor"`
	}{in, actor}, &out)
	return out, err
}

// SetWeb asks the broker to make the account's site live. A 422
// web_rejected answer means the new config failed its test and was restored:
// the account is unchanged.
func (c *client) SetWeb(ctx context.Context, id string, in WebInput, actor string) (WebResult, error) {
	if !idPattern.MatchString(id) || !validWebState(WebState{PHPVersion: in.PHPVersion, QuotaMiB: in.QuotaMiB}) || in.ExpectedRevision == 0 || !validText(in.Reason, 500) || !validText(actor, 120) {
		return WebResult{}, ErrInvalid
	}
	var out WebResult
	// The apply can take minutes on a busy host (the broker allows four).
	err := c.send(ctx, c.slow, "POST", "/v1/accounts/"+id+"/web", struct {
		Input WebInput `json:"input"`
		Actor string   `json:"actor"`
	}{in, actor}, &out, maxResponseBytes)
	return out, err
}

// SetCertificate asks the broker to install a certificate and key for the
// account's live site. A 422 certificate_rejected answer means the leaf does
// not name the account's domain or is not valid now; 422 web_rejected means
// the config with it failed its test and was restored. Either way the
// account is unchanged.
func (c *client) SetCertificate(ctx context.Context, id string, in CertificateInput, actor string) (CertificateResult, error) {
	if !idPattern.MatchString(id) || !validCertificateInput(in, actor) {
		return CertificateResult{}, ErrInvalid
	}
	var out CertificateResult
	// The install runs the web apply, which can take minutes on a busy host.
	err := c.exchange(ctx, c.slow, "POST", "/v1/accounts/"+id+"/certificate", struct {
		Input CertificateInput `json:"input"`
		Actor string           `json:"actor"`
	}{in, actor}, maxCertificateRequestBytes, &out, maxResponseBytes)
	return out, err
}

// InstallWordPress asks the broker to install WordPress into the account's
// live site. A failed WP-CLI step comes back as an *InstallError.
func (c *client) InstallWordPress(ctx context.Context, id string, in WordPressInput, actor string) (WordPressResult, error) {
	if !idPattern.MatchString(id) || in.ExpectedRevision == 0 || !validSecret(in.AdminPassword) || !validSecret(in.DBPassword) || !validText(actor, 120) {
		return WordPressResult{}, ErrInvalid
	}
	var out WordPressResult
	err := c.send(ctx, c.slow, "POST", "/v1/accounts/"+id+"/wordpress", struct {
		Input WordPressInput `json:"input"`
		Actor string         `json:"actor"`
	}{in, actor}, &out, maxResponseBytes)
	return out, err
}

// InstallPlaceholder asks the broker to put the placeholder page into the
// account's live site if its public_html is empty. A failed PHP run comes
// back as an *InstallError for the "placeholder" step.
func (c *client) InstallPlaceholder(ctx context.Context, id string, in PlaceholderInput, actor string) (PlaceholderResult, error) {
	if !idPattern.MatchString(id) || in.ExpectedRevision == 0 || !validText(actor, 120) {
		return PlaceholderResult{}, ErrInvalid
	}
	var out PlaceholderResult
	err := c.send(ctx, c.slow, "POST", "/v1/accounts/"+id+"/placeholder", struct {
		Input PlaceholderInput `json:"input"`
		Actor string           `json:"actor"`
	}{in, actor}, &out, maxResponseBytes)
	return out, err
}

// BackupStatus reads the broker's backup key, readiness and target. The
// first call makes the key pair and the repository password.
func (c *client) BackupStatus(ctx context.Context) (BackupStatus, error) {
	var out BackupStatus
	err := c.request(ctx, "GET", "/v1/backup", nil, &out)
	return out, err
}

// SetBackupTarget points backups at an SFTP storage server. A failed step
// (the server not reached, a repository the password does not open) comes
// back as a *BackupError, with nothing changed.
func (c *client) SetBackupTarget(ctx context.Context, in BackupTargetInput, actor string) (BackupTargetResult, error) {
	if _, ok := validBackupTarget(in, actor); !ok {
		return BackupTargetResult{}, ErrInvalid
	}
	var out BackupTargetResult
	err := c.send(ctx, c.slow, "POST", "/v1/backup/target", struct {
		Input BackupTargetInput `json:"input"`
		Actor string            `json:"actor"`
	}{in, actor}, &out, maxResponseBytes)
	return out, err
}

// ShowBackupPassword reads the repository password again. The broker gives
// it only while a target is set and the admin has not confirmed saving it;
// after that it answers ErrConflict.
func (c *client) ShowBackupPassword(ctx context.Context, in BackupPasswordInput, actor string) (BackupPassword, error) {
	if !validText(in.Reason, 500) || !validText(actor, 120) {
		return BackupPassword{}, ErrInvalid
	}
	var out BackupPassword
	err := c.send(ctx, c.http, "POST", "/v1/backup/password", struct {
		Input BackupPasswordInput `json:"input"`
		Actor string              `json:"actor"`
	}{in, actor}, &out, maxResponseBytes)
	return out, err
}

// ConfirmBackupPassword records that the admin saved the repository
// password; no later answer carries it.
func (c *client) ConfirmBackupPassword(ctx context.Context, in BackupPasswordInput, actor string) (BackupStatus, error) {
	if !validText(in.Reason, 500) || !validText(actor, 120) {
		return BackupStatus{}, ErrInvalid
	}
	var out BackupStatus
	err := c.send(ctx, c.http, "POST", "/v1/backup/password-saved", struct {
		Input BackupPasswordInput `json:"input"`
		Actor string              `json:"actor"`
	}{in, actor}, &out, maxResponseBytes)
	return out, err
}

// BackupAccount backs up the account's home and the named databases.
func (c *client) BackupAccount(ctx context.Context, id string, in BackupInput, actor string) (Snapshot, error) {
	if !idPattern.MatchString(id) || !validBackupInput(in, actor) {
		return Snapshot{}, ErrInvalid
	}
	if in.Databases == nil {
		in.Databases = []string{}
	}
	var out Snapshot
	err := c.send(ctx, c.long, "POST", "/v1/accounts/"+id+"/backup", struct {
		Input BackupInput `json:"input"`
		Actor string      `json:"actor"`
	}{in, actor}, &out, maxResponseBytes)
	return out, err
}

// ListBackups lists the account's snapshots, newest first.
func (c *client) ListBackups(ctx context.Context, id string) ([]Snapshot, error) {
	if !idPattern.MatchString(id) {
		return nil, ErrInvalid
	}
	var out struct {
		Items []Snapshot `json:"items"`
	}
	err := c.send(ctx, c.slow, "GET", "/v1/accounts/"+id+"/backups", nil, &out, maxResponseBytes)
	if err != nil {
		return nil, err
	}
	if out.Items == nil {
		out.Items = []Snapshot{}
	}
	return out.Items, nil
}

// RestoreAccount restores the account's files, databases or both from one
// of its snapshots.
func (c *client) RestoreAccount(ctx context.Context, id string, in RestoreInput, actor string) (RestoreResult, error) {
	if !idPattern.MatchString(id) || !validRestoreInput(in, actor) {
		return RestoreResult{}, ErrInvalid
	}
	if in.Databases == nil {
		in.Databases = []string{}
	}
	var out RestoreResult
	err := c.send(ctx, c.long, "POST", "/v1/accounts/"+id+"/restore", struct {
		Input RestoreInput `json:"input"`
		Actor string       `json:"actor"`
	}{in, actor}, &out, maxResponseBytes)
	return out, err
}

// DrillAccount runs a restore drill of the account's latest snapshot.
func (c *client) DrillAccount(ctx context.Context, id string, in DrillInput, actor string) (DrillResult, error) {
	if !idPattern.MatchString(id) || !validText(in.Reason, 500) || !validText(actor, 120) {
		return DrillResult{}, ErrInvalid
	}
	var out DrillResult
	err := c.send(ctx, c.long, "POST", "/v1/accounts/"+id+"/drill", struct {
		Input DrillInput `json:"input"`
		Actor string     `json:"actor"`
	}{in, actor}, &out, maxResponseBytes)
	return out, err
}

// PruneBackups applies the retention rule (7 daily, 4 weekly) to every
// site's snapshots.
func (c *client) PruneBackups(ctx context.Context, in PruneInput, actor string) (PruneResult, error) {
	if !validText(in.Reason, 500) || !validText(actor, 120) {
		return PruneResult{}, ErrInvalid
	}
	var out PruneResult
	err := c.send(ctx, c.long, "POST", "/v1/backup/prune", struct {
		Input PruneInput `json:"input"`
		Actor string     `json:"actor"`
	}{in, actor}, &out, maxResponseBytes)
	return out, err
}

func (c *client) request(ctx context.Context, method, path string, input, output any) error {
	return c.requestBounded(ctx, method, path, input, output, maxResponseBytes)
}

func (c *client) requestBounded(ctx context.Context, method, path string, input, output any, limit int64) error {
	return c.send(ctx, c.http, method, path, input, output, limit)
}

func (c *client) send(ctx context.Context, h *http.Client, method, path string, input, output any, limit int64) error {
	return c.exchange(ctx, h, method, path, input, MaxRequestBytes, output, limit)
}

// exchange is send with its own bound on the request body.
func (c *client) exchange(ctx context.Context, h *http.Client, method, path string, input any, inputLimit int, output any, limit int64) error {
	if ctx == nil {
		return ErrInvalid
	}
	if !c.configured {
		return ErrUnavailable
	}
	var body io.Reader
	if input != nil {
		b, err := json.Marshal(input)
		if err != nil || len(b) > inputLimit {
			return ErrInvalid
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, body)
	if err != nil {
		return ErrInvalid
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := h.Do(req)
	if err != nil {
		return ErrUnavailable
	}
	defer response.Body.Close()
	b, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(b)) > limit {
		return ErrUnavailable
	}
	if response.StatusCode != 200 {
		var failure struct {
			Error     string `json:"error"`
			Step      string `json:"step"`
			Detail    string `json:"detail"`
			Installed bool   `json:"wordpress_installed"`
		}
		if json.Unmarshal(b, &failure) != nil {
			return ErrUnavailable
		}
		switch failure.Error {
		case "invalid":
			return ErrInvalid
		case "conflict":
			return ErrConflict
		case "delete_busy":
			return ErrDeleteBusy
		case "domain_taken":
			return ErrDomainTaken
		case "delete_stopped":
			return ErrDeleteStopped
		case "not_found":
			return ErrNotFound
		case "recovery":
			return ErrRecovery
		case "web_rejected":
			return ErrWebRejected
		case "certificate_rejected":
			return ErrCertificateRejected
		case "install_failed":
			return &InstallError{Step: failure.Step, Detail: installDetail([]byte(failure.Detail)), Installed: failure.Installed}
		case "backup_failed":
			return &BackupError{Step: backupDetail([]byte(failure.Step)), Detail: backupDetail([]byte(failure.Detail))}
		default:
			return ErrUnavailable
		}
	}
	if json.Unmarshal(b, output) != nil {
		return ErrUnavailable
	}
	return nil
}
