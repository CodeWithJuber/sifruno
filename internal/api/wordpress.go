package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
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
	AdminPassword string `json:"admin_password" minLength:"12" maxLength:"128" format:"password" writeOnly:"true" doc:"WordPress admin password. Kept in memory until the install ends; never stored or returned."`
	PHPVersion    string `json:"php_version" enum:"8.1,8.2,8.3,8.4" doc:"PHP version for the site."`
}

type wordpressCreateInput struct{ Body WordPressCreateBody }
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

// wordpressKeys are the request's keys, exactly as the contract spells them.
var wordpressKeys = map[string]bool{"domain": true, "title": true, "admin_user": true, "admin_email": true, "admin_password": true, "php_version": true}

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
		// The handler's copy of the password goes when it returns; the job
		// keeps its own until the install ends.
		defer func() { in.Body.AdminPassword = "" }()
		if runner == nil {
			return nil, huma.Error503ServiceUnavailable(wizardUnavailable)
		}
		b := in.Body
		job, err := runner.Start(ctx, wizard.Input{Domain: b.Domain, Title: b.Title, AdminUser: b.AdminUser, AdminEmail: b.AdminEmail, AdminPassword: b.AdminPassword, PHPVersion: b.PHPVersion}, siteActor(ctx))
		b.AdminPassword = ""
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

func allowedWizardMutation(r *http.Request) bool {
	return r.Method == http.MethodPost && r.URL.Path == "/api/v1/websites/wordpress"
}

// prepareWizardJSON bounds and checks the wizard's body before Huma decodes
// it: JSON content type, at most 4 KiB, one object holding only the
// contract's keys, each once, each a string. Go's decoder would accept a
// key in another case, so keys are compared exactly. Nothing from the body
// is echoed back.
func prepareWizardJSON(w http.ResponseWriter, r *http.Request) bool {
	ct, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || ct != "application/json" || (params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8")) {
		operator.WriteError(w, 415, "invalid_request", "Send the request as JSON.")
		return false
	}
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(5 * time.Second))
	defer http.NewResponseController(w).SetReadDeadline(time.Time{})
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4097))
	if err != nil {
		operator.WriteError(w, 400, "invalid_request", "The request could not be read.")
		return false
	}
	if len(raw) > 4096 {
		operator.WriteError(w, 413, "invalid_request", "The request is larger than 4 KiB.")
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
		if !wordpressKeys[key] {
			operator.WriteError(w, 422, "invalid_request", "The request has a field this form does not use. Send only domain, title, admin_user, admin_email, admin_password and php_version.")
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
		if v := bytes.TrimSpace(value); len(v) == 0 || v[0] != '"' {
			operator.WriteError(w, 422, "invalid_request", key+" must be text.")
			return false
		}
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	r.ContentLength = int64(len(raw))
	return true
}
