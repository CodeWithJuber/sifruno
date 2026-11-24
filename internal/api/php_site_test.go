package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"sifruno/internal/hostaccounts"
	"sifruno/internal/wizard"
)

const phpDBPassword = "chosen db pass 0123"

func (s *wizardBrokerSpy) InstallPlaceholder(context.Context, string, hostaccounts.PlaceholderInput, string) (hostaccounts.PlaceholderResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return hostaccounts.PlaceholderResult{Written: true}, nil
}

func (b *sitesBroker) InstallPlaceholder(context.Context, string, hostaccounts.PlaceholderInput, string) (hostaccounts.PlaceholderResult, error) {
	return hostaccounts.PlaceholderResult{Written: true}, nil
}

func phpBody(change func(map[string]any)) string {
	body := map[string]any{"domain": "example.com", "php_version": "8.2", "database": "create", "database_password": phpDBPassword}
	if change != nil {
		change(body)
	}
	raw, _ := json.Marshal(body)
	return string(raw)
}

func TestPHPSiteWizardAdmission(t *testing.T) {
	f, runner, spy := wizardFixture(t)
	const path = "/api/v1/websites/php"
	if w := websiteRequest(f.handler, "POST", path, phpBody(nil), nil, ""); w.Code != 401 {
		t.Fatalf("unauthenticated status %d", w.Code)
	}
	cookie, csrf := websiteSignIn(t, f)
	if w := websiteRequest(f.handler, "POST", path, phpBody(nil), cookie, ""); w.Code != 403 {
		t.Fatalf("missing CSRF status %d", w.Code)
	}
	if w := websiteRequest(f.handler, "PUT", path, phpBody(nil), cookie, csrf); w.Code != 405 {
		t.Fatalf("PUT status %d", w.Code)
	}
	for _, tc := range []struct {
		name, body string
		status     int
		detail     string
	}{
		{"a WordPress key", phpBody(func(b map[string]any) { b["title"] = "My site" }), 422, "Send only domain, php_version, database and database_password"},
		{"unknown key", phpBody(func(b map[string]any) { b["sensitive-key"] = "x" }), 422, "Send only domain"},
		{"duplicate key", strings.Replace(phpBody(nil), `{`, `{"domain":"other.example",`, 1), 422, "domain more than once"},
		{"boolean", phpBody(func(b map[string]any) { b["database"] = true }), 422, "database must be text"},
		{"no database choice", phpBody(func(b map[string]any) { delete(b, "database"); delete(b, "database_password") }), 422, "database must be none or create."},
		{"another database choice", phpBody(func(b map[string]any) { b["database"] = "yes" }), 422, "database must be none or create."},
		{"domain", phpBody(func(b map[string]any) { b["domain"] = "Example.com" }), 422, "domain "},
		{"php_version", phpBody(func(b map[string]any) { b["php_version"] = "7.4" }), 422, "php_version "},
		{"short password", phpBody(func(b map[string]any) { b["database_password"] = "short" }), 422, "database_password "},
		{"no password", phpBody(func(b map[string]any) { delete(b, "database_password") }), 422, "database_password "},
		{"password without a database", phpBody(func(b map[string]any) { b["database"] = "none" }), 422, "database_password "},
	} {
		w := websiteRequest(f.handler, "POST", path, tc.body, cookie, csrf)
		if w.Code != tc.status || !strings.HasPrefix(problemDetail(t, w), tc.detail) && !strings.Contains(problemDetail(t, w), tc.detail) {
			t.Fatalf("%s: status %d: %s", tc.name, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "sensitive-key") || strings.Contains(w.Body.String(), phpDBPassword) {
			t.Fatalf("%s: request echoed", tc.name)
		}
	}
	if spy.calls != 0 || len(runner.List()) != 0 {
		t.Fatal("a refused request reached the broker or the job store")
	}
}

func TestPHPSiteWizardJobShapes(t *testing.T) {
	f, runner, _ := wizardFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	start := func(body string) wizard.Job {
		t.Helper()
		w := websiteRequest(f.handler, "POST", "/api/v1/websites/php", body, cookie, csrf)
		if w.Code != 202 || strings.Contains(w.Body.String(), phpDBPassword) {
			t.Fatalf("start status %d: %s", w.Code, w.Body.String())
		}
		var started struct{ Job wizard.Job }
		if err := json.Unmarshal(w.Body.Bytes(), &started); err != nil || started.Job.Kind != "php" || started.Job.State != "running" {
			t.Fatalf("started %s", w.Body.String())
		}
		runner.Wait()
		return started.Job
	}
	read := func(id string) (wizard.Job, map[string]json.RawMessage) {
		t.Helper()
		w := websiteRequest(f.handler, "GET", "/api/v1/websites/jobs/"+id, nil, cookie, "")
		var body struct {
			Job json.RawMessage `json:"job"`
		}
		var job wizard.Job
		var result map[string]json.RawMessage
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &body) != nil || json.Unmarshal(body.Job, &job) != nil || strings.Contains(w.Body.String(), phpDBPassword) {
			t.Fatalf("GET job %d: %s", w.Code, w.Body.String())
		}
		var raw struct {
			Result map[string]json.RawMessage `json:"result"`
		}
		if err := json.Unmarshal(body.Job, &raw); err == nil {
			result = raw.Result
		}
		return job, result
	}

	job := start(phpBody(func(b map[string]any) { b["database"] = "none"; delete(b, "database_password") }))
	done, result := read(job.ID)
	names := []string{}
	for _, s := range done.Steps {
		names = append(names, s.Name+"="+s.State)
	}
	if strings.Join(names, " ") != "account=done web=done ssl=skipped database=skipped placeholder=done" {
		t.Fatalf("steps %q", names)
	}
	if done.State != "succeeded" || done.Kind != "php" || done.PHPVersion != "8.2" || done.Result == nil || done.Result.URL != "http://example.com/" || done.Result.AdminURL != "" || done.Result.WordPressVersion != "" {
		t.Fatalf("finished job %+v %+v", done, done.Result)
	}
	if _, ok := result["database"]; ok || len(result) != 4 {
		t.Fatalf("result keys without a database: %v", result)
	}

	// With a database: its name is in the result, its password nowhere.
	job = start(phpBody(func(b map[string]any) { b["domain"] = "second.example" }))
	done, result = read(job.ID)
	if done.State != "succeeded" || done.Result.Database != "second_wp" || len(result) != 5 {
		t.Fatalf("finished job %+v %+v", done, done.Result)
	}
}

func TestWebsitesShowTheSiteType(t *testing.T) {
	f, runner, _ := sitesFixture(t)
	wp := makeSite(t, runner, "blog.example", "8.3")
	job, err := runner.Start(context.Background(), wizard.Input{Kind: wizard.KindPHP, Domain: "app.example", PHPVersion: "8.2"}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	runner.Wait()
	php, _ := runner.Get(job.ID)
	cookie, _ := websiteSignIn(t, f)
	w := websiteRequest(f.handler, "GET", "/api/v1/websites/sites", nil, cookie, "")
	sites := decodeSites(t, w.Body.Bytes())
	if len(sites) != 2 || sites[0].AccountID != php.Result.AccountID || sites[0].Kind != "php" || sites[0].AdminURL != "" || sites[0].WordPressVersion != "" || sites[0].PHPVersion != "8.2" {
		t.Fatalf("PHP site %+v", sites)
	}
	if sites[1].AccountID != wp.Result.AccountID || sites[1].Kind != "wordpress" || sites[1].AdminURL == "" {
		t.Fatalf("WordPress site %+v", sites[1])
	}
	w = websiteRequest(f.handler, "GET", "/api/v1/websites/sites/"+php.Result.AccountID, nil, cookie, "")
	var one map[string]json.RawMessage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &one) != nil || string(one["kind"]) != `"php"` {
		t.Fatalf("one site %d: %s", w.Code, w.Body.String())
	}
	checkWebsiteShape(t, one, "php_versions")
}
