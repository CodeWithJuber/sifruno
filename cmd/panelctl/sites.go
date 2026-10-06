package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"sifruno/internal/securestate"
	"sifruno/internal/sites"
)

const siteResponseLimit = sites.MaxFileBytes*6 + 8192

type siteClient struct {
	client *http.Client
	base   string
	csrf   string
}

// Explicit numeric loopback URLs prevent sending a local access key to a remote
// address through DNS, an inherited HTTP proxy, or a redirect.
func newSiteClient(raw string) (*siteClient, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return nil, errors.New("panel URL must be a plain explicit loopback HTTP(S) origin")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() || u.Port() == "" {
		return nil, errors.New("panel URL requires a numeric loopback IP and explicit port")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 5 * time.Second, DisableKeepAlives: true}
	client := &http.Client{Jar: jar, Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("panel redirects are refused") }}
	return &siteClient{client: client, base: u.Scheme + "://" + u.Host}, nil
}

func readOperatorKey(state string) (string, error) {
	keyPath, err := filepath.Abs(filepath.Join(state, "operator", "access.key"))
	if err != nil || securestate.CheckPath(keyPath) != nil {
		return "", errors.New("private operator access key unavailable")
	}
	root, err := os.OpenRoot(filepath.Dir(keyPath))
	if err != nil {
		return "", errors.New("start the panel with this state directory before running site commands")
	}
	defer root.Close()
	info, err := root.Lstat("access.key")
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 256 {
		return "", errors.New("invalid private operator access key file")
	}
	f, err := root.Open("access.key")
	if err != nil {
		return "", errors.New("private operator access key unavailable")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
		return "", errors.New("private operator access key changed during read")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 257))
	if err != nil || len(raw) > 256 {
		return "", errors.New("private operator access key unavailable")
	}
	key := strings.TrimSpace(string(raw))
	if len(key) != 43 {
		return "", errors.New("invalid private operator access key")
	}
	for _, c := range key {
		if c < 33 || c > 126 {
			return "", errors.New("invalid private operator access key")
		}
	}
	return key, nil
}

func (c *siteClient) request(method, path string, body any) (json.RawMessage, error) {
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequest(method, c.base+path, bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("invalid panel request")
	}
	req.Header.Set("Accept", "application/json")
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", c.base)
	}
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		if strings.HasPrefix(path, "/api/v1/accounts") {
			return nil, errors.New("account request result is unknown; refresh accounts and reconcile any interrupted creation before retrying")
		}
		return nil, errors.New("local panel request failed; check the running panel and loopback URL")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, siteResponseLimit+1))
	if err != nil || len(raw) > siteResponseLimit {
		return nil, errors.New("panel response exceeded the bounded limit")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message := "panel operation rejected"
		switch resp.StatusCode {
		case 401:
			message = "operator authentication required"
		case 403:
			message = "operator origin or CSRF verification failed"
		case 404:
			message = "website or resource not found"
		case 409:
			message = "website changed; reload its revision and file hash before retrying"
		case 422:
			message = "invalid website operation"
		case 429:
			message = "operator login rate limit reached"
		case 503:
			message = "website store unavailable"
		}
		if strings.HasPrefix(path, "/api/v1/accounts") {
			switch resp.StatusCode {
			case 404:
				message = "managed account not found"
			case 409:
				message = "account identity, domain or revision changed; refresh and review before retrying"
			case 422:
				message = "invalid native account operation"
			case 503:
				message = "account broker or recovery unavailable; refresh the account list before retrying creation"
			}
		}
		return nil, fmt.Errorf("%s (HTTP %d)", message, resp.StatusCode)
	}
	if !json.Valid(raw) {
		return nil, errors.New("panel returned invalid JSON")
	}
	return json.RawMessage(raw), nil
}

func (c *siteClient) login(key string) error {
	raw, err := c.request(http.MethodPost, "/api/v1/session/login", map[string]string{"access_key": key})
	if err != nil {
		return err
	}
	var session struct {
		Authenticated bool   `json:"authenticated"`
		CSRF          string `json:"csrf_token"`
	}
	if json.Unmarshal(raw, &session) != nil || !session.Authenticated || session.CSRF == "" {
		return errors.New("panel operator session unavailable")
	}
	c.csrf = session.CSRF
	return nil
}

func runSites(args []string, state, base string, out, errs io.Writer) error {
	if len(args) == 0 {
		return errors.New("sites requires a subcommand; run panelctl help")
	}
	f := flag.NewFlagSet("sites "+args[0], flag.ContinueOnError)
	f.SetOutput(errs)
	transfer := args[0] == "export" || args[0] == "import"
	if transfer {
		f.SetOutput(io.Discard)
	}
	id := f.String("id", "", "Website ID")
	name := f.String("name", "", "Website name")
	domain := f.String("domain", "", "Website domain")
	path := f.String("path", "", "Relative managed file")
	from := f.String("from", "", "Local UTF-8 file to save or native ZIP to import")
	revision := f.Uint64("revision", 0, "Expected current website revision")
	sha := f.String("sha256", "", "Expected current file hash, empty for a new file")
	wantedState := f.String("state", "", "active or suspended")
	backup := f.String("backup", "", "Native backup ID to restore or export")
	destination := f.String("out", "", "New native ZIP export file (never overwritten)")
	scheduleRevision := f.Uint64("schedule-revision", 0, "Expected current backup schedule revision; zero only when absent")
	interval := f.String("interval", "", "hourly, daily or weekly")
	enabled := f.String("enabled", "", "Explicit true or false")
	if err := f.Parse(args[1:]); err != nil {
		if transfer {
			return errors.New("invalid site transfer flags; run panelctl help")
		}
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected site command arguments")
	}
	method, endpoint := http.MethodGet, "/api/v1/sites"
	var body any
	sub := args[0]
	if sub != "list" && sub != "create" && sub != "import" {
		if *id == "" || strings.ContainsAny(*id, "/\\?#%") {
			return errors.New("sites command requires a valid --id")
		}
		endpoint += "/" + url.PathEscape(*id)
	}
	switch sub {
	case "restore-preview":
		if !transferID(*id) || !transferID(*backup) || *revision == 0 || *revision > 9007199254740991 {
			return errors.New("restore-preview requires valid --id, --backup and a positive safe --revision")
		}
		method, endpoint = http.MethodPost, endpoint+"/restore-preview"
		body = sites.RestoreInput{BackupID: *backup, ExpectedRevision: *revision}
	case "backup-schedule":
		if !transferID(*id) {
			return errors.New("backup-schedule requires a valid --id")
		}
		endpoint += "/backup-schedule"
	case "backup-schedule-set":
		if !transferID(*id) || *revision == 0 || *revision > 9007199254740991 || *scheduleRevision > 9007199254740991 ||
			(*interval != "hourly" && *interval != "daily" && *interval != "weekly") || (*enabled != "true" && *enabled != "false") {
			return errors.New("backup-schedule-set requires --id, --revision, --schedule-revision, --interval and explicit --enabled true|false")
		}
		seenRevision := false
		f.Visit(func(flag *flag.Flag) {
			if flag.Name == "schedule-revision" {
				seenRevision = true
			}
		})
		if !seenRevision {
			return errors.New("backup-schedule-set requires explicit --schedule-revision (zero only when absent)")
		}
		value := *enabled == "true"
		method, endpoint = http.MethodPut, endpoint+"/backup-schedule"
		body = sites.BackupScheduleInput{ExpectedRevision: *revision, ExpectedScheduleRevision: *scheduleRevision, Interval: *interval, Enabled: &value}
	case "export":
		if !transferID(*id) || !transferID(*backup) || *destination == "" {
			return errors.New("export requires --id, --backup and --out")
		}
		endpoint += "/backups/" + *backup + "/download"
	case "import":
		if *from == "" || *name == "" || len(*name) > 80 || !utf8.ValidString(*name) || *domain == "" || len(*domain) > 253 || !utf8.ValidString(*domain) {
			return errors.New("import requires --name, --domain and --from within the native limits")
		}
		endpoint += "/import"
	case "list", "show":
	case "create":
		method = http.MethodPost
		body = sites.CreateInput{Name: *name, Domain: *domain}
	case "files":
		endpoint += "/files"
	case "read":
		if *path == "" {
			return errors.New("read requires --path")
		}
		endpoint += "/file?path=" + url.QueryEscape(*path)
	case "write":
		if *path == "" || *from == "" || *revision == 0 {
			return errors.New("write requires --path, --from and --revision")
		}
		file, err := os.Open(*from)
		if err != nil {
			return errors.New("input file unavailable")
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 2<<20 {
			file.Close()
			return errors.New("input must be a regular file no larger than 2 MiB")
		}
		content, err := io.ReadAll(io.LimitReader(file, (2<<20)+1))
		file.Close()
		if err != nil || len(content) > 2<<20 || !utf8.Valid(content) {
			return errors.New("input file exceeded the bounded limit")
		}
		method = http.MethodPut
		endpoint += "/file"
		body = sites.WriteInput{Path: *path, Content: string(content), ExpectedSHA256: *sha, ExpectedRevision: *revision}
	case "state":
		if *revision == 0 || (*wantedState != "active" && *wantedState != "suspended") {
			return errors.New("state requires --state active|suspended and --revision")
		}
		method = http.MethodPost
		endpoint += "/state"
		body = sites.StateInput{State: *wantedState, ExpectedRevision: *revision}
	case "backups":
		endpoint += "/backups"
	case "backup":
		if *revision == 0 {
			return errors.New("backup requires --revision")
		}
		method = http.MethodPost
		endpoint += "/backups"
		body = map[string]uint64{"expected_revision": *revision}
	case "restore":
		if *backup == "" || *revision == 0 {
			return errors.New("restore requires --backup and --revision")
		}
		method = http.MethodPost
		endpoint += "/restore"
		body = sites.RestoreInput{BackupID: *backup, ExpectedRevision: *revision}
	default:
		return errors.New("unknown sites subcommand; run panelctl help")
	}
	c, err := newSiteClient(base)
	if err != nil {
		return err
	}
	key, err := readOperatorKey(state)
	if err != nil {
		return err
	}
	if err = c.login(key); err != nil {
		return err
	}
	key = ""
	defer func() { _, _ = c.request(http.MethodPost, "/api/v1/session/logout", map[string]any{}) }()
	if sub == "export" {
		return c.exportSite(endpoint, *destination, out)
	}
	if sub == "import" {
		return c.importSite(endpoint, *name, *domain, *from, out)
	}
	raw, err := c.request(method, endpoint, body)
	if err != nil {
		return err
	}
	e := json.NewEncoder(out)
	e.SetIndent("", "  ")
	return e.Encode(raw)
}
