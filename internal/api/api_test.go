package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"

	"sifruno/config"
	"sifruno/internal/budget"
	"sifruno/internal/compat"
	"sifruno/internal/trail"
)

func testHandler(t *testing.T) http.Handler {
	t.Helper()
	b, entries, e := config.Load()
	if e != nil {
		t.Fatal(e)
	}
	dir := realTempDir(t)
	tr, e := trail.Open(filepath.Join(dir, "trail"))
	if e != nil {
		t.Fatal(e)
	}
	bs, e := budget.Open(filepath.Join(dir, "budget"), budget.DefaultCap)
	if e != nil {
		t.Fatal(e)
	}
	return New(Options{Report: compat.Evaluate(b, entries), Trail: tr, Budget: bs, AllowedOrigins: []string{"http://127.0.0.1:8080"}, UI: fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html>Sifruno</html>")}, "assets/app.js": &fstest.MapFile{Data: []byte("ok")}}})
}
func request(h http.Handler, method, path, host, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, nil)
	r.Host = host
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestRealStoresAndFailClosedContracts(t *testing.T) {
	h := testHandler(t)
	for _, p := range []string{"/api/v1/status", "/api/v1/trail", "/api/v1/budget", "/api/v1/platform", "/openapi.json"} {
		w := request(h, "GET", p, "127.0.0.1:8080", "")
		if w.Code != 200 {
			t.Fatalf("%s %d %s", p, w.Code, w.Body.String())
		}
		var obj map[string]any
		if e := json.Unmarshal(w.Body.Bytes(), &obj); e != nil {
			t.Fatal(e)
		}
		if p == "/api/v1/status" && (obj["ready"] != false || obj["passed"] != float64(0)) {
			t.Fatal("unverified status escaped gate")
		}
		if p == "/api/v1/budget" && obj["remaining_usd_micros"] != float64(budget.DefaultCap) {
			t.Fatal("real budget mismatch")
		}
	}
	for _, p := range []string{"/json-api/createacct", "/execute/Email/add_pop", "/scripts/pkgacct", "/cpsess1234567890/json-api/createacct", "/cpsess1234567890/execute/Email/add_pop"} {
		w := request(h, "GET", p, "localhost:8080", "")
		if w.Code != 501 || !strings.Contains(w.Body.String(), "compatibility_not_implemented") {
			t.Fatal("fake legacy success", p)
		}
	}
	for _, p := range []string{"/api/v1/missing", "/assets/missing.js", "/.state/key", "/missing.js"} {
		if w := request(h, "GET", p, "localhost:8080", ""); w.Code != 404 {
			t.Fatal("SPA exposed unavailable path", p, w.Code)
		}
	}
	if w := request(h, "GET", "/platforms", "localhost:8080", ""); w.Code != 200 || !strings.Contains(w.Body.String(), "Sifruno") {
		t.Fatal("SPA navigation failed")
	}
}
func TestLoopbackHostOriginAndMutationGuards(t *testing.T) {
	h := testHandler(t)
	for _, pair := range [][2]string{{"evil.example:8080", ""}, {"127.0.0.1:8080", "https://evil.example"}} {
		if w := request(h, "GET", "/api/v1/status", pair[0], pair[1]); w.Code != 403 {
			t.Fatal("cross-origin leaked")
		}
	}
	if w := request(h, "POST", "/api/v1/budget", "localhost:8080", ""); w.Code != 405 {
		t.Fatal("remote mutation allowed", w.Code)
	}
	r := httptest.NewRequest("GET", "http://localhost:8080/api/v1/status", nil)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("cross-site request allowed")
	}
}
func TestBudgetCorruptionReturnsUnavailable(t *testing.T) {
	b, o, _ := config.Load()
	dir := filepath.Join(realTempDir(t), "budget")
	bs, e := budget.Open(dir, budget.DefaultCap)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "ledger.json"), []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	h := New(Options{Report: compat.Evaluate(b, o), Budget: bs})
	if w := request(h, "GET", "/api/v1/budget", "localhost:8080", ""); w.Code != 503 || strings.Contains(w.Body.String(), dir) {
		t.Fatal("corrupt store did not fail safely", w.Code)
	}
}

func realTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		return dir
	}
	dir, e := filepath.EvalSymlinks(dir)
	if e != nil {
		t.Fatal(e)
	}
	return dir
}
