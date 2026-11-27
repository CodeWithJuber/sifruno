package api

import (
	"testing"
)

// A website named like the panel would take the panel's own address on
// port 80, where the panel's certificate is validated: the wizard's two
// kinds and the account create refuse it, and its www. form, before the
// broker or the job store is asked.
func TestWebsiteCreateRefusesThePanelHost(t *testing.T) {
	if panelHostTaken != "This name is the panel's own address. Use a different domain for the website." {
		t.Fatalf("message %q", panelHostTaken)
	}
	f, runner, spy := wizardFixture(t)
	f.handler = New(Options{Operator: f.manager, Wizard: runner, PanelHosts: []string{"panel.example.org", "203.0.113.9"}, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
	cookie, csrf := websiteSignIn(t, f)
	for _, domain := range []string{"panel.example.org", "www.panel.example.org"} {
		for path, body := range map[string]string{
			"/api/v1/websites/wordpress": wizardBody(func(b map[string]any) { b["domain"] = domain }),
			"/api/v1/websites/php":       phpBody(func(b map[string]any) { b["domain"] = domain }),
		} {
			w := websiteRequest(f.handler, "POST", path, body, cookie, csrf)
			if w.Code != 422 || problemDetail(t, w) != panelHostTaken {
				t.Errorf("%s %s: %d %s", path, domain, w.Code, w.Body.String())
			}
		}
	}
	if spy.calls != 0 || len(runner.List()) != 0 {
		t.Fatal("a refused request reached the broker or the job store")
	}
	// Another name still starts a job.
	if w := websiteRequest(f.handler, "POST", "/api/v1/websites/php", phpBody(func(b map[string]any) { b["domain"] = "shop.panel.example.org" }), cookie, csrf); w.Code != 202 {
		t.Fatalf("another name: %d %s", w.Code, w.Body.String())
	}
}

func TestAccountCreateRefusesThePanelHost(t *testing.T) {
	f := websiteFixture(t)
	s := &accountSpy{}
	f.handler = New(Options{Operator: f.manager, Accounts: s, PanelHosts: []string{"panel.example.org"}, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
	cookie, csrf := websiteSignIn(t, f)
	for _, domain := range []string{"panel.example.org", "www.panel.example.org", "Panel.Example.org"} {
		w := websiteRequest(f.handler, "POST", "/api/v1/accounts", `{"username":"nativeuser","domain":"`+domain+`","reason":"operator fixture"}`, cookie, csrf)
		if w.Code != 422 || problemDetail(t, w) != panelHostTaken {
			t.Errorf("%s: %d %s", domain, w.Code, w.Body.String())
		}
	}
	if s.calls != 0 {
		t.Fatal("a refused create reached the broker")
	}
	if w := websiteRequest(f.handler, "POST", "/api/v1/accounts", `{"username":"nativeuser","domain":"native.example.test","reason":"operator fixture"}`, cookie, csrf); w.Code != 200 || s.calls != 1 {
		t.Fatalf("another name: %d %s", w.Code, w.Body.String())
	}
}
