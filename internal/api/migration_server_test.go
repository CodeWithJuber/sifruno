package api

import (
	"encoding/json"
	"strings"
	"testing"

	"sifruno/internal/hostaccounts"
)

func TestMoveFromAnotherLinuxServerRoutes(t *testing.T) {
	f, runner, spy := migrationFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	base := "/api/v1/websites/migrations"
	if w := websiteRequest(f.handler, "POST", base+"/sources", map[string]any{"host": "old.example.test", "port": 22, "via": "plesk"}, cookie, csrf); w.Code != 422 {
		t.Fatalf("an unknown way: %d %s", w.Code, w.Body.String())
	}
	w := websiteRequest(f.handler, "POST", base+"/sources", map[string]any{"host": "old.example.test", "port": 22, "via": "server"}, cookie, csrf)
	var opened struct {
		Source MigrationSource `json:"source"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &opened) != nil || opened.Source.Via != hostaccounts.ViaServer || spy.via != hostaccounts.ViaServer {
		t.Fatalf("open: %d %s", w.Code, w.Body.String())
	}
	key := base + "/sources/" + testSourceID + "/install-key"
	// No password reaches a server whose fingerprint nobody confirmed.
	if w := websiteRequest(f.handler, "POST", key, map[string]any{"password": "root's password"}, cookie, csrf); w.Code != 409 || !strings.Contains(w.Body.String(), "only to the server you confirmed") {
		t.Fatalf("before the fingerprint: %d %s", w.Code, w.Body.String())
	}
	if w := websiteRequest(f.handler, "GET", base+"/sources/"+testSourceID+"/sites", nil, cookie, ""); w.Code != 422 {
		t.Fatalf("sites before the fingerprint: %d %s", w.Code, w.Body.String())
	}
	if w := websiteRequest(f.handler, "POST", base+"/sources/"+testSourceID+"/host-key", map[string]any{"fingerprint": "SHA256:abc"}, cookie, csrf); w.Code != 200 {
		t.Fatalf("pin: %d %s", w.Code, w.Body.String())
	}
	for _, body := range []map[string]any{{}, {"password": "a", "private_key": "b"}, {"password": "two\nlines"}, {"passphrase": "p"}} {
		if w := websiteRequest(f.handler, "POST", key, body, cookie, csrf); w.Code != 422 || strings.Contains(w.Body.String(), "two") {
			t.Fatalf("%v: %d %s", body, w.Code, w.Body.String())
		}
	}
	if w := websiteRequest(f.handler, "POST", key, map[string]any{"password": "x", "user": "admin"}, cookie, csrf); w.Code != 422 {
		t.Fatalf("an unknown field: %d %s", w.Code, w.Body.String())
	}
	// A password or passphrase over its limit is refused without the
	// answer repeating it.
	long := strings.Repeat("overlong-secret-", 125)
	for _, body := range []map[string]any{{"password": long}, {"private_key": "k", "passphrase": long}} {
		if w := websiteRequest(f.handler, "POST", key, body, cookie, csrf); w.Code != 422 || strings.Contains(w.Body.String(), "overlong-secret") {
			t.Fatalf("an over-long secret: %d %s", w.Code, w.Body.String())
		}
	}
	w = websiteRequest(f.handler, "GET", base+"/sources/"+testSourceID+"/sites", nil, cookie, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"domain":"blog.example.test"`) || !strings.Contains(w.Body.String(), `"account":"blog"`) {
		t.Fatalf("sites: %d %s", w.Code, w.Body.String())
	}
	w = websiteRequest(f.handler, "POST", base, map[string]any{"source": testSourceID, "username": "blog", "site": "blog.example.test"}, cookie, csrf)
	if w.Code != 202 {
		t.Fatalf("start: %d %s", w.Code, w.Body.String())
	}
	runner.Wait()
}
