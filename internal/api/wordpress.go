package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/danielgtaylor/huma/v2"
	"sifruno/internal/operator"
	"sifruno/internal/wizard"
)

// WordPressCreateBody is the wizard's request. The middleware has already
// checked that it holds exactly these keys, each once, each a string.
type WordPressCreateBody struct {
	Domain        string `json:"domain" maxLength:"253" doc:"Lowercase domain name, such as example.com."`
	Title         string `json:"title" maxLength:"200" doc:"Site title, 1 to 200 bytes."`
	AdminUser     string `json:"admin_user" pattern:"^[A-Za-z0-9_.@][A-Za-z0-9_.@-]{0,59}$" doc:"WordPress admin username."`
	AdminEmail    string `json:"admin_email" maxLength:"100" doc:"WordPress admin email, a plain address."`
	AdminPassword string `json:"admin_password" minLength:"12" maxLength:"128" format:"password" writeOnly:"true" doc:"WordPress admin password. Held only in memory, never stored or returned; the job drops its reference when it ends, after the install step or after undoing a failed job."`
	PHPVersion    string `json:"php_version" enum:"8.1,8.2,8.3,8.4" doc:"PHP version for the site."`
}

type wordpressCreateInput struct{ Body WordPressCreateBody }

// PHPSiteCreateBody is the wizard's request for a PHP site: an empty site
// with its own PHP version, a placeholder page and, if asked, a database.
// The middleware has already checked that it holds only these keys, each
// once, each a string.
type PHPSiteCreateBody struct {
	Domain           string `json:"domain" maxLength:"253" doc:"Lowercase domain name, such as example.com."`
	PHPVersion       string `json:"php_version" enum:"8.1,8.2,8.3,8.4" doc:"PHP version for the site."`
	Database         string `json:"database" enum:"none,create" doc:"create also makes a database and its user, both named <username>_wp, with every privilege on that database."`
	DatabasePassword string `json:"database_password" maxLength:"128" format:"password" writeOnly:"true" doc:"The database user's password when database is create: 12 to 128 bytes, no control characters, no space at the start or end. Empty or left out otherwise. Held only in memory, never stored or returned."`
}

type phpSiteCreateInput struct{ Body PHPSiteCreateBody }
type websiteJobInput struct {
	ID string `path:"id"`
}
type websiteJobBody struct {
	Job wizard.Job `json:"job"`
}
type websiteJobOutput struct{ Body websiteJobBody }
type websiteJobListBody struct {
	Jobs []wizard.Job `json:"jobs"`
}
type websiteJobListOutput struct{ Body websiteJobListBody }

const wizardUnavailable = "Website creation is not set up on this server"

// wizardFields are each POST's keys under /api/v1/websites, exactly as the
// contract spells them and in its order: the wizard's request, and the site
// page's changes by action. A key is text unless it is whole or a flag.
type wizardField struct {
	name  string
	whole bool // a whole number, as a revision is
	flag  bool // true or false, as a switch is
}

var wizardFields = map[string][]wizardField{
	"wordpress": {{name: "domain"}, {name: "title"}, {name: "admin_user"}, {name: "admin_email"}, {name: "admin_password"}, {name: "php_version"}},
	"php-site":  {{name: "domain"}, {name: "php_version"}, {name: "database"}, {name: "database_password"}},
	"php":       {{name: "php_version"}, {name: "expected_revision", whole: true}},
	"state":     {{name: "state"}, {name: "expected_revision", whole: true}},
	"folder":    {{name: "expected_revision", whole: true}},
	"delete":    {{name: "confirm_domain"}, {name: "expected_revision", whole: true}},
	// The site page's domains and redirects.
	"domain-add":      {{name: "domain"}, {name: "expected_revision", whole: true}},
	"domain-remove":   {{name: "domain"}, {name: "expected_revision", whole: true}},
	"redirect-add":    {{name: "from"}, {name: "to"}, {name: "status", whole: true}, {name: "expected_revision", whole: true}},
	"redirect-remove": {{name: "from"}, {name: "expected_revision", whole: true}},
	"always-https":    {{name: "always_https", flag: true}, {name: "expected_revision", whole: true}},
	// Move a website here (migrations.go).
	"migration-source":        {{name: "host"}, {name: "port", whole: true}},
	"migration-whm":           {{name: "address"}, {name: "token"}, {name: "password"}, {name: "ssh_port", whole: true}, {name: "tls_fingerprint"}},
	"migration-host-key":      {{name: "fingerprint"}},
	"migration-cancel":        {},
	"migration-stale-cleared": {},
	"migration-archive":       {}, // the backup file's bytes, read as a stream

	"migration":        {{name: "source"}, {name: "username"}},
	"migration-verify": {},
	"migration-accept": {{name: "reason"}},
	"migration-ready":  {},
}

var wholeNumber = regexp.MustCompile(`^(0|[1-9][0-9]{0,19})$`)

// wizardRoute names the POST a request is, as wizardFields keys it, or "".
func wizardRoute(r *http.Request) string {
	if r.Method != http.MethodPost {
		return ""
	}
	switch r.URL.Path {
	case "/api/v1/websites/wordpress":
		return "wordpress"
	case "/api/v1/websites/php":
		return "php-site"
	}
	if route := migrationRoute(r.URL.Path); route != "" {
		return route
	}
	return websiteAction(r.URL.Path)
}

func wizardError(err error) error {
	var refusal *wizard.Refusal
	if !errors.As(err, &refusal) {
		return huma.Error503ServiceUnavailable("The panel could not start the job. Try again.")
	}
	switch {
	case errors.Is(err, wizard.ErrInvalid):
		return huma.Error422UnprocessableEntity(refusal.Detail)
	case errors.Is(err, wizard.ErrConflict):
		return huma.Error409Conflict(refusal.Detail)
	default:
		return huma.Error503ServiceUnavailable(refusal.Detail)
	}
}

func registerWizard(a huma.API, o Options) {
	runner := o.Wizard
	op := func(id, method, path string, status int) huma.Operation {
		return huma.Operation{OperationID: id, Method: method, Path: path, DefaultStatus: status, MaxBodyBytes: 4096, BodyReadTimeout: 5 * time.Second, SkipValidateBody: true, SkipValidateParams: true}
	}
	huma.Register(a, op("create-wordpress-website", http.MethodPost, "/api/v1/websites/wordpress", http.StatusAccepted), func(ctx context.Context, in *wordpressCreateInput) (*websiteJobOutput, error) {
		// The handler drops its references to the password when it returns,
		// and the job drops its own when it ends, after the install step or
		// after undoing a failed job. Go strings cannot be zeroed, so this
		// lets the memory be reused; it does not erase it.
		defer func() { in.Body.AdminPassword = "" }()
		if runner == nil {
			return nil, huma.Error503ServiceUnavailable(wizardUnavailable)
		}
		b := in.Body
		if panelHost(o.PanelHosts, b.Domain) {
			return nil, huma.Error422UnprocessableEntity(panelHostTaken)
		}
		job, err := runner.Start(ctx, wizard.Input{Domain: b.Domain, Title: b.Title, AdminUser: b.AdminUser, AdminEmail: b.AdminEmail, AdminPassword: b.AdminPassword, PHPVersion: b.PHPVersion}, siteActor(ctx))
		b.AdminPassword = ""
		if err != nil {
			return nil, wizardError(err)
		}
		return &websiteJobOutput{Body: websiteJobBody{Job: job}}, nil
	})
	huma.Register(a, op("create-php-website", http.MethodPost, "/api/v1/websites/php", http.StatusAccepted), func(ctx context.Context, in *phpSiteCreateInput) (*websiteJobOutput, error) {
		// As for WordPress: the handler drops its references to the
		// database password when it returns, the job after the database step
		// or after undoing a failed job.
		defer func() { in.Body.DatabasePassword = "" }()
		if runner == nil {
			return nil, huma.Error503ServiceUnavailable(wizardUnavailable)
		}
		b := in.Body
		if panelHost(o.PanelHosts, b.Domain) {
			return nil, huma.Error422UnprocessableEntity(panelHostTaken)
		}
		database := false
		switch b.Database {
		case "create":
			database = true
		case "none":
		default:
			return nil, huma.Error422UnprocessableEntity("database must be none or create.")
		}
		job, err := runner.Start(ctx, wizard.Input{Kind: wizard.KindPHP, Domain: b.Domain, PHPVersion: b.PHPVersion, Database: database, DBPassword: b.DatabasePassword}, siteActor(ctx))
		b.DatabasePassword = ""
		if err != nil {
			return nil, wizardError(err)
		}
		return &websiteJobOutput{Body: websiteJobBody{Job: job}}, nil
	})
	huma.Register(a, op("get-website-job", http.MethodGet, "/api/v1/websites/jobs/{id}", http.StatusOK), func(ctx context.Context, in *websiteJobInput) (*websiteJobOutput, error) {
		if runner == nil {
			return nil, huma.Error503ServiceUnavailable(wizardUnavailable)
		}
		if !wizard.ValidID(in.ID) {
			return nil, huma.Error404NotFound("That website job was not found. The panel keeps the newest 50 jobs.")
		}
		job, ok := runner.Get(in.ID)
		if !ok {
			return nil, huma.Error404NotFound("That website job was not found. The panel keeps the newest 50 jobs.")
		}
		return &websiteJobOutput{Body: websiteJobBody{Job: job}}, nil
	})
	huma.Register(a, op("list-website-jobs", http.MethodGet, "/api/v1/websites/jobs", http.StatusOK), func(ctx context.Context, _ *struct{}) (*websiteJobListOutput, error) {
		if runner == nil {
			return nil, huma.Error503ServiceUnavailable(wizardUnavailable)
		}
		return &websiteJobListOutput{Body: websiteJobListBody{Jobs: runner.List()}}, nil
	})
}

func isWizardPath(p string) bool {
	return p == "/api/v1/websites" || strings.HasPrefix(p, "/api/v1/websites/")
}

func allowedWizardMutation(r *http.Request) bool { return wizardRoute(r) != "" }

// prepareWizardJSON checks a body under /api/v1/websites (the wizard's
// request, or one of the site page's changes) before Huma decodes it.
func prepareWizardJSON(w http.ResponseWriter, r *http.Request) bool {
	return prepareStrictJSON(w, r, wizardFields[wizardRoute(r)])
}

// prepareStrictJSON bounds and checks a POST body before Huma decodes it:
// JSON content type, at most 4 KiB, one object holding only the request's
// own fields, each once, each a string or, for a revision, a whole number,
// or for a switch, true or false.
// Go's decoder would accept a key in another case, so keys are compared
// exactly. Nothing from the body is echoed back.
func prepareStrictJSON(w http.ResponseWriter, r *http.Request, fields []wizardField) bool {
	return prepareStrictJSONWithin(w, r, fields, 4096)
}

// prepareStrictJSONWithin is prepareStrictJSON with its own size bound,
// for a body that carries a file's text.
func prepareStrictJSONWithin(w http.ResponseWriter, r *http.Request, fields []wizardField, limit int64) bool {
	names := make([]string, len(fields))
	whole, flag := map[string]bool{}, map[string]bool{}
	for i, f := range fields {
		names[i] = f.name
		whole[f.name], flag[f.name] = f.whole, f.flag
	}
	ct, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || ct != "application/json" || (params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8")) {
		operator.WriteError(w, 415, "invalid_request", "Send the request as JSON.")
		return false
	}
	// A file's text takes longer to arrive than a form's few fields.
	wait, size := 5*time.Second, strconv.FormatInt(limit>>10, 10)+" KiB"
	if limit > 64<<10 {
		wait, size = 30*time.Second, strconv.FormatInt(limit>>20, 10)+" MiB"
	}
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(wait))
	defer http.NewResponseController(w).SetReadDeadline(time.Time{})
	raw, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		operator.WriteError(w, 400, "invalid_request", "The request could not be read.")
		return false
	}
	if int64(len(raw)) > limit {
		operator.WriteError(w, 413, "invalid_request", "The request is larger than "+size+".")
		return false
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' || !utf8.Valid(raw) || !json.Valid(raw) {
		operator.WriteError(w, 400, "invalid_request", "The request must be one JSON object.")
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if _, err = d.Token(); err != nil {
		operator.WriteError(w, 400, "invalid_request", "The request must be one JSON object.")
		return false
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			operator.WriteError(w, 400, "invalid_request", "The request must be one JSON object.")
			return false
		}
		if !slices.Contains(names, key) {
			only := strings.Join(names, "")
			if n := len(names); n > 1 {
				only = strings.Join(names[:n-1], ", ") + " and " + names[n-1]
			}
			operator.WriteError(w, 422, "invalid_request", "The request has a field this form does not use. Send only "+only+".")
			return false
		}
		if seen[key] {
			operator.WriteError(w, 422, "invalid_request", "The request has the field "+key+" more than once.")
			return false
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			operator.WriteError(w, 400, "invalid_request", "The request must be one JSON object.")
			return false
		}
		v := bytes.TrimSpace(value)
		if flag[key] {
			if string(v) != "true" && string(v) != "false" {
				operator.WriteError(w, 422, "invalid_request", key+" must be true or false.")
				return false
			}
			continue
		}
		if whole[key] && !wholeNumber.Match(v) {
			operator.WriteError(w, 422, "invalid_request", key+" must be a whole number.")
			return false
		}
		if !whole[key] && (len(v) == 0 || v[0] != '"') {
			operator.WriteError(w, 422, "invalid_request", key+" must be text.")
			return false
		}
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	r.ContentLength = int64(len(raw))
	return true
}
