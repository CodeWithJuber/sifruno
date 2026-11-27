package api

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"sifruno/internal/cpsource"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/whmsource"
	"sifruno/internal/wizard"
)

// "Move a website here": migration v1 from a cPanel server over root SSH
// (hostaccounts README, Migration). The routes sit under
// /api/v1/websites/migrations, so the wizard's admission applies (an admin
// session, and for a change also Origin and CSRF), and an API token may not
// use them (tokenRefused): a migration holds a key to another server's root.
// The default way in is the old server's WHM login (D-0005, POST
// .../migrations/whm): the panel lists the accounts and adds the broker's
// public key for root through WHM's API, holding the login in memory for
// that connection only (whmsource.Sessions); it is never stored, logged
// or returned. Copying a command to the old server is the other way in.

const (
	migrationsUnavailable = "Moving websites is not set up on this server."
	migrationReason       = "Move a website here"
	// migrationWait is the response deadline of a route that reads the old
	// server: its account list or the removal of the key.
	migrationWait = 4 * time.Minute
)

var (
	migrationStalePath  = regexp.MustCompile(`^/api/v1/websites/migrations/stale-keys/[a-f0-9]{32}/cleared$`)
	migrationSourcePath = regexp.MustCompile(`^/api/v1/websites/migrations/sources/[a-f0-9]{32}/(host-key|cancel)$`)
	migrationJobPath    = regexp.MustCompile(`^/api/v1/websites/migrations/[a-f0-9]{32}/(verify|accept|ready)$`)
	migrationReadPath   = regexp.MustCompile(`^/api/v1/websites/migrations/sources/[a-f0-9]{32}/accounts$`)
)

// migrationRoute names a migration POST as wizardFields keys it, or "".
func migrationRoute(p string) string {
	switch p {
	case "/api/v1/websites/migrations/sources":
		return "migration-source"
	case "/api/v1/websites/migrations/whm":
		return "migration-whm"
	case "/api/v1/websites/migrations":
		return "migration"
	case migrationArchivePath:
		return "migration-archive"
	}
	if migrationStalePath.MatchString(p) {
		return "migration-stale-cleared"
	}
	if m := migrationSourcePath.FindStringSubmatch(p); m != nil {
		return "migration-" + m[1]
	}
	if m := migrationJobPath.FindStringSubmatch(p); m != nil {
		return "migration-" + m[1]
	}
	return ""
}

// isMigrationSlow is a route that talks to the old server.
func isMigrationSlow(r *http.Request) bool {
	route := migrationRoute(r.URL.Path)
	return migrationReadPath.MatchString(r.URL.Path) || route == "migration-source" || route == "migration-whm" || route == "migration-cancel"
}

// MigrationSource is the old server as the page shows it: the key line the
// admin adds there and the host keys whose fingerprint they confirm.
type MigrationSource struct {
	ID             string                          `json:"id"`
	Host           string                          `json:"host"`
	Port           int                             `json:"port"`
	KeyLine        string                          `json:"key_line" doc:"The line root's authorized_keys on the old server gets; it ends with the migration's name."`
	InstallCommand string                          `json:"install_command" doc:"Run as root on the old server to add the key line."`
	HostKeys       []hostaccounts.MigrationHostKey `json:"host_keys"`
	Pinned         string                          `json:"pinned_fingerprint" doc:"The confirmed fingerprint; empty until the admin confirms one."`
	Via            string                          `json:"via" doc:"whm when connected with the old server's WHM login, archive for an uploaded cPanel backup file, empty for the SSH path."`
	Archive        *hostaccounts.MigrationArchive  `json:"archive,omitempty" doc:"For an uploaded backup file: the account, domain and databases it holds, and what will not move."`
	ExpiresAt      time.Time                       `json:"expires_at"`
}

func migrationSource(m hostaccounts.Migration) MigrationSource {
	return MigrationSource{ID: m.ID, Host: m.Host, Port: m.Port, KeyLine: m.PublicKey, InstallCommand: m.InstallCommand, HostKeys: m.HostKeys, Pinned: m.Pinned, Via: m.Via, Archive: m.Archive, ExpiresAt: m.ExpiresAt}
}

// migrationWHMInput is the WHM login form. The token and the password are
// used in memory for this connection only, and never echoed.
type migrationWHMInput struct {
	Body struct {
		Address        string `json:"address" maxLength:"2048" doc:"WHM's address on the old server, such as https://server1.example.com:2087 (https; port 2087 unless given)."`
		Token          string `json:"token" maxLength:"128" doc:"A WHM API token for root. Kept in memory for this connection only; never stored, logged or returned."`
		Password       string `json:"password" maxLength:"1024" doc:"Root's password, instead of a token. Kept in memory for this connection only; never stored, logged or returned."`
		SSHPort        int    `json:"ssh_port" doc:"The old server's SSH port for the copy; 22 when left out."`
		TLSFingerprint string `json:"tls_fingerprint" maxLength:"95" doc:"The SHA-256 fingerprint of WHM's certificate the admin confirmed, when this server does not trust it."`
	}
}
type migrationWHMOutput struct {
	Body struct {
		Source      MigrationSource       `json:"source"`
		Accounts    []MigrationAccount    `json:"accounts"`
		Certificate whmsource.Certificate `json:"certificate"`
	}
}

func migrationAccounts(items []cpsource.Account) []MigrationAccount {
	out := make([]MigrationAccount, 0, len(items))
	for _, a := range items {
		out = append(out, MigrationAccount(a))
	}
	return out
}

type migrationSourceBody struct {
	Host string `json:"host" maxLength:"253" doc:"The old server's host name or IPv4 address."`
	Port int    `json:"port" minimum:"1" maximum:"65535" doc:"Its SSH port, usually 22."`
}
type migrationSourceInput struct{ Body migrationSourceBody }
type migrationSourceIDInput struct {
	ID string `path:"id"`
}
type migrationHostKeyInput struct {
	ID   string `path:"id"`
	Body struct {
		Fingerprint string `json:"fingerprint" maxLength:"64" doc:"The SHA256 fingerprint the old server shows for its key."`
	}
}
type migrationEmptyInput struct {
	ID   string `path:"id"`
	Body struct{}
}
type migrationSourceOutput struct {
	Body struct {
		Source MigrationSource `json:"source"`
	}
}

// MigrationAccount is one account on the old server; Problem says why it
// cannot move, or is empty.
type MigrationAccount struct {
	User         string `json:"user"`
	Domain       string `json:"domain"`
	DiskUsedMiB  int64  `json:"disk_used_mib"`
	DiskLimitMiB int64  `json:"disk_limit_mib" doc:"0 means unlimited."`
	Suspended    bool   `json:"suspended"`
	Problem      string `json:"problem,omitempty"`
}

type migrationAccountsOutput struct {
	Body struct {
		Accounts []MigrationAccount `json:"accounts"`
	}
}
type migrationCancelOutput struct {
	Body hostaccounts.MigrationFinishResult
}

// StaleKey is a migration key line that may still be in root's
// authorized_keys on an old server: the broker could not prove it removed.
type StaleKey struct {
	ID     string    `json:"id"`
	Host   string    `json:"host"`
	Port   int       `json:"port"`
	Line   string    `json:"line" doc:"The line ends with this text."`
	Detail string    `json:"detail"`
	Since  time.Time `json:"since"`
}
type staleKeysOutput struct {
	Body struct {
		Keys []StaleKey `json:"keys"`
	}
}
type staleClearedOutput struct {
	Body struct {
		Cleared string `json:"cleared"`
	}
}

type migrationStartInput struct {
	Body struct {
		Source   string `json:"source" pattern:"^[a-f0-9]{32}$" doc:"The old server's migration ID."`
		Username string `json:"username" maxLength:"32" doc:"The account to move; it keeps this name here."`
	}
}
type migrationAcceptInput struct {
	ID   string `path:"id"`
	Body struct {
		Reason string `json:"reason" maxLength:"500" doc:"Why the red lines are accepted; the activity log keeps it."`
	}
}

// siteKind is what a website is: a moved one is WordPress or a PHP site by
// what its files hold.
func siteKind(j wizard.Job) string {
	if j.Kind != wizard.KindMigration {
		return j.Kind
	}
	if j.Migration != nil && j.Migration.WordPress {
		return wizard.KindWordPress
	}
	return wizard.KindPHP
}

// migrationProblem is a migration route's problem answer: detail says why,
// next is the next step for that case, and technical what the old server
// printed, which the page shows under Technical details only (D-0006).
type migrationProblem struct {
	huma.ErrorModel
	Next      string `json:"next"`
	Technical string `json:"technical,omitempty"`
	// Certificate is WHM's certificate this server does not trust, for the
	// admin to compare and confirm.
	Certificate *whmsource.Certificate `json:"certificate,omitempty"`
}

func newMigrationProblem(status int, why, next, technical string) *migrationProblem {
	return &migrationProblem{ErrorModel: huma.ErrorModel{Status: status, Title: http.StatusText(status), Detail: why}, Next: next, Technical: technical}
}

// migrationAgain is how the person retries on the Move a website here page.
const migrationAgain = "press Try again"

// migrationBrokerError explains the broker's answers in plain words.
func migrationBrokerError(err error) error {
	var failed *hostaccounts.MigrationError
	switch {
	case errors.As(err, &failed):
		e := wizard.ExplainMigration(failed, migrationAgain)
		return newMigrationProblem(http.StatusUnprocessableEntity, e.Why, e.Next, e.Technical)
	case errors.Is(err, hostaccounts.ErrNotFound):
		return newMigrationProblem(http.StatusNotFound, "That connection to the old server has ended (it lasts 24 hours), so Sifruno no longer holds its key.", "Connect to the old server again.", "")
	case errors.Is(err, hostaccounts.ErrInvalid):
		return newMigrationProblem(http.StatusUnprocessableEntity, "The old server's address must be a host name or IPv4 address and its SSH port 1 to 65535.", "Correct the address or the port, then press Connect again.", "")
	case errors.Is(err, hostaccounts.ErrConflict):
		return newMigrationProblem(http.StatusConflict, "Too many connections to old servers are open (16 at most), or this one changed meanwhile.", "Finish a move or press Stop and remove the key on another one, then press Try again.", "")
	}
	return newMigrationProblem(http.StatusServiceUnavailable, "The account service, which holds the migration key, is not answering.", "Check that the sifruno-broker service is running on this server, then press Try again.", "")
}

func registerMigrations(a huma.API, o Options) {
	op := func(id, method, path string, status int) huma.Operation {
		return huma.Operation{OperationID: id, Method: method, Path: path, DefaultStatus: status, MaxBodyBytes: 4096, BodyReadTimeout: 5 * time.Second, SkipValidateBody: true, SkipValidateParams: true}
	}
	broker := func() (hostaccounts.MigrationService, error) {
		if o.Migrations == nil || o.Wizard == nil {
			return nil, huma.Error503ServiceUnavailable(migrationsUnavailable)
		}
		return o.Migrations, nil
	}
	huma.Register(a, op("open-migration-source", http.MethodPost, "/api/v1/websites/migrations/sources", http.StatusOK), func(ctx context.Context, in *migrationSourceInput) (*migrationSourceOutput, error) {
		b, err := broker()
		if err != nil {
			return nil, err
		}
		m, err := b.OpenMigration(ctx, hostaccounts.MigrationOpenInput{Host: in.Body.Host, Port: in.Body.Port, Reason: migrationReason}, siteActor(ctx))
		if err != nil {
			return nil, migrationBrokerError(err)
		}
		out := &migrationSourceOutput{}
		out.Body.Source = migrationSource(m)
		return out, nil
	})
	huma.Register(a, op("connect-migration-whm", http.MethodPost, "/api/v1/websites/migrations/whm", http.StatusOK), func(ctx context.Context, in *migrationWHMInput) (*migrationWHMOutput, error) {
		// The handler drops its references to the login when it returns;
		// the client keeps its own in memory until the move ends.
		defer func() { in.Body.Token, in.Body.Password = "", "" }()
		b, err := broker()
		if err != nil {
			return nil, err
		}
		return connectWHM(ctx, b, o.MigrationLogins, in, siteActor(ctx))
	})
	huma.Register(a, op("get-migration-source", http.MethodGet, "/api/v1/websites/migrations/sources/{id}", http.StatusOK), func(ctx context.Context, in *migrationSourceIDInput) (*migrationSourceOutput, error) {
		b, err := broker()
		if err != nil {
			return nil, err
		}
		m, err := b.GetMigration(ctx, in.ID)
		if err != nil {
			return nil, migrationBrokerError(err)
		}
		out := &migrationSourceOutput{}
		out.Body.Source = migrationSource(m)
		return out, nil
	})
	huma.Register(a, op("confirm-migration-host-key", http.MethodPost, "/api/v1/websites/migrations/sources/{id}/host-key", http.StatusOK), func(ctx context.Context, in *migrationHostKeyInput) (*migrationSourceOutput, error) {
		b, err := broker()
		if err != nil {
			return nil, err
		}
		m, err := b.PinMigrationHostKey(ctx, in.ID, hostaccounts.MigrationPinInput{Fingerprint: in.Body.Fingerprint, Reason: migrationReason}, siteActor(ctx))
		if err != nil {
			var failed *hostaccounts.MigrationError
			if errors.As(err, &failed) && failed.Step == "host_key" {
				return nil, newMigrationProblem(http.StatusUnprocessableEntity, "That fingerprint is not one the old server showed, so it was not confirmed.", "Compare it again with ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub on the old server; if it does not match any, stop: something else answered at that address.", "")
			}
			return nil, migrationBrokerError(err)
		}
		out := &migrationSourceOutput{}
		out.Body.Source = migrationSource(m)
		return out, nil
	})
	huma.Register(a, op("list-migration-accounts", http.MethodGet, "/api/v1/websites/migrations/sources/{id}/accounts", http.StatusOK), func(ctx context.Context, in *migrationSourceIDInput) (*migrationAccountsOutput, error) {
		b, err := broker()
		if err != nil {
			return nil, err
		}
		var items []cpsource.Account
		if o.MigrationLogins.Has(in.ID) {
			// A WHM migration's accounts come through WHM's API.
			items, err = o.MigrationLogins.Accounts(ctx, in.ID)
		} else if m, gerr := b.GetMigration(ctx, in.ID); gerr == nil && m.Via == hostaccounts.ViaWHM {
			items, err = o.MigrationLogins.Accounts(ctx, in.ID)
		} else {
			items, err = b.MigrationAccounts(ctx, in.ID)
		}
		if err != nil {
			return nil, migrationBrokerError(err)
		}
		out := &migrationAccountsOutput{}
		out.Body.Accounts = migrationAccounts(items)
		return out, nil
	})
	huma.Register(a, op("cancel-migration-source", http.MethodPost, "/api/v1/websites/migrations/sources/{id}/cancel", http.StatusOK), func(ctx context.Context, in *migrationEmptyInput) (*migrationCancelOutput, error) {
		b, err := broker()
		if err != nil {
			return nil, err
		}
		res, err := o.MigrationLogins.Finish(ctx, in.ID, b, hostaccounts.MigrationFinishInput{Reason: migrationReason}, siteActor(ctx))
		if err != nil {
			return nil, migrationBrokerError(err)
		}
		return &migrationCancelOutput{Body: res}, nil
	})
	huma.Register(a, op("list-stale-migration-keys", http.MethodGet, "/api/v1/websites/migrations/stale-keys", http.StatusOK), func(ctx context.Context, _ *struct{}) (*staleKeysOutput, error) {
		b, err := broker()
		if err != nil {
			return nil, err
		}
		items, err := b.StaleMigrationKeys(ctx)
		if err != nil {
			return nil, migrationBrokerError(err)
		}
		out := &staleKeysOutput{}
		out.Body.Keys = make([]StaleKey, 0, len(items))
		for _, k := range items {
			out.Body.Keys = append(out.Body.Keys, StaleKey{ID: k.ID, Host: k.Host, Port: k.Port, Line: k.Comment, Detail: k.Detail, Since: k.At})
		}
		return out, nil
	})
	huma.Register(a, op("clear-stale-migration-key", http.MethodPost, "/api/v1/websites/migrations/stale-keys/{id}/cleared", http.StatusOK), func(ctx context.Context, in *migrationEmptyInput) (*staleClearedOutput, error) {
		b, err := broker()
		if err != nil {
			return nil, err
		}
		if err = b.ClearStaleMigrationKey(ctx, in.ID, hostaccounts.MigrationFinishInput{Reason: "The admin removed the key line by hand"}, siteActor(ctx)); err != nil {
			if errors.Is(err, hostaccounts.ErrNotFound) {
				return nil, huma.Error404NotFound("That key line is not listed any more.")
			}
			return nil, migrationBrokerError(err)
		}
		out := &staleClearedOutput{}
		out.Body.Cleared = in.ID
		return out, nil
	})
	huma.Register(a, op("start-migration", http.MethodPost, "/api/v1/websites/migrations", http.StatusAccepted), func(ctx context.Context, in *migrationStartInput) (*websiteJobOutput, error) {
		if _, err := broker(); err != nil {
			return nil, err
		}
		job, err := o.Wizard.StartMigration(ctx, wizard.MigrationInput{Source: in.Body.Source, Username: in.Body.Username}, siteActor(ctx))
		if err != nil {
			return nil, wizardError(err)
		}
		return &websiteJobOutput{Body: websiteJobBody{Job: job}}, nil
	})
	change := func(id, action string, run func(context.Context, string, string, string) (wizard.Job, error)) {
		huma.Register(a, op(id, http.MethodPost, "/api/v1/websites/migrations/{id}/"+action, http.StatusOK), func(ctx context.Context, in *migrationAcceptInput) (*websiteJobOutput, error) {
			if _, err := broker(); err != nil {
				return nil, err
			}
			job, err := run(ctx, in.ID, in.Body.Reason, siteActor(ctx))
			if err != nil {
				if errors.Is(err, wizard.ErrNotFound) {
					return nil, huma.Error404NotFound(err.Error())
				}
				return nil, wizardError(err)
			}
			return &websiteJobOutput{Body: websiteJobBody{Job: job}}, nil
		})
	}
	change("verify-migration", "verify", func(ctx context.Context, id, _, actor string) (wizard.Job, error) {
		return o.Wizard.VerifyMigration(ctx, id, actor)
	})
	change("accept-migration", "accept", func(ctx context.Context, id, reason, actor string) (wizard.Job, error) {
		return o.Wizard.AcceptMigration(ctx, id, reason, actor)
	})
	change("ready-migration", "ready", func(ctx context.Context, id, _, actor string) (wizard.Job, error) {
		return o.Wizard.ReadyMigration(ctx, id, actor)
	})
}

// connectWHM is D-0005's connection (steps 1 and 2, and the host key's
// reading for step 3): WHM's certificate checked, the accounts listed with
// the login, the broker's migration opened (its key made, the old server's
// SSH host keys read), and its public key added for root through WHM's
// API. A certificate this server does not trust answers 409 with its
// fingerprint before any login is sent; the admin confirms it and sends it
// back as tls_fingerprint, and only that certificate is then accepted.
// No documented WHM API 1 function returns the SSH host key, so the page
// shows the one the broker read and the admin confirms it with one button.
func connectWHM(ctx context.Context, b hostaccounts.MigrationService, logins *whmsource.Sessions, in *migrationWHMInput, actor string) (*migrationWHMOutput, error) {
	if logins == nil {
		return nil, huma.Error503ServiceUnavailable(migrationsUnavailable)
	}
	again := "then press Connect again."
	address, err := whmsource.ParseAddress(in.Body.Address)
	if err != nil {
		return nil, newMigrationProblem(http.StatusUnprocessableEntity, "WHM's address must be https with the old server's host name or IPv4 address, such as https://server1.example.com:2087 (port 2087 unless you give another).", "Correct the address, "+again, "")
	}
	login := whmsource.Login{Token: strings.TrimSpace(in.Body.Token), Password: in.Body.Password}
	if !login.Valid() {
		return nil, newMigrationProblem(http.StatusUnprocessableEntity, "Give either a WHM API token for root (letters and digits) or root's password, not both and not neither.", "Enter one of them, "+again, "")
	}
	port := in.Body.SSHPort
	if port == 0 {
		port = 22
	}
	pinned := in.Body.TLSFingerprint
	if port < 1 || port > 65535 || (pinned != "" && !whmsource.ValidFingerprint(pinned)) {
		return nil, newMigrationProblem(http.StatusUnprocessableEntity, "The SSH port must be 1 to 65535, and a confirmed certificate fingerprint 32 pairs of hex digits.", "Correct it, "+again, "")
	}
	cert, err := whmsource.Probe(ctx, address)
	if err != nil {
		return nil, migrationBrokerError(err)
	}
	switch {
	case cert.Trusted:
		pinned = ""
	case pinned == "":
		p := newMigrationProblem(http.StatusConflict, "WHM's certificate at "+address.String()+" is not signed by an authority this server trusts. cPanel's own self-signed certificate looks like this; so would another machine pretending to be the old server.", "Compare this fingerprint with WHM's certificate on the old server (in WHM: Service Configuration, Manage Service SSL Certificates). If it is the same, press Trust this certificate. Your login was not sent.", "certificate "+cert.Subject+", issued by "+cert.Issuer)
		p.Certificate = &cert
		return nil, p
	case pinned != cert.Fingerprint:
		return nil, migrationBrokerError(&hostaccounts.MigrationError{Step: "whm_tls", Detail: "WHM at " + address.String() + " now presents another certificate than the one you confirmed. Your login was not sent."})
	}
	client, err := whmsource.New(address, login, pinned)
	if err != nil {
		return nil, newMigrationProblem(http.StatusUnprocessableEntity, "The WHM address or login could not be used.", "Check both, "+again, "")
	}
	items, err := client.Accounts(ctx)
	if err != nil {
		return nil, migrationBrokerError(err)
	}
	m, err := b.OpenMigration(ctx, hostaccounts.MigrationOpenInput{Host: address.Host, Port: port, Via: hostaccounts.ViaWHM, Reason: migrationReason}, actor)
	if err != nil {
		return nil, migrationBrokerError(err)
	}
	logins.Put(m.ID, client, m.PublicKey, m.ExpiresAt)
	if err = client.AuthorizeKey(ctx, m.PublicKey, m.ID); err != nil {
		// End the migration at once: its key goes from this server, and
		// from the old one as far as WHM can remove it.
		_, _ = logins.Finish(context.WithoutCancel(ctx), m.ID, b, hostaccounts.MigrationFinishInput{Reason: migrationReason}, actor)
		return nil, migrationBrokerError(err)
	}
	out := &migrationWHMOutput{}
	out.Body.Source = migrationSource(m)
	out.Body.Accounts = migrationAccounts(items)
	out.Body.Certificate = cert
	return out, nil
}
