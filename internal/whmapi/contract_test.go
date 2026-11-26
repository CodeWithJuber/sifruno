package whmapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The backend data below is synthetic: made-up values in the field layout
// this package serves. Expected bodies are the package's own compatibility
// wording (envelope.go, handlers.go). Volatile segments such as XID tokens
// are asserted by prefix and containment, not byte equality.

type testBackend struct{}

func (testBackend) Version() string { return "99.0.0.1" }
func (testBackend) ListPackages() []Package {
	return []Package{{
		"name": "starter", "BWLIMIT": "10240", "QUOTA": "2048",
		"MAXADDON": "2", "MAXPARK": "1", "MAXSUB": "5",
		"MAXPOP": "20", "MAXFTP": "3", "MAXSQL": "4",
		"MAXLST": "0", "CPMOD": "example-theme", "FEATURELIST": "starter-features",
		"PACKAGE_TYPE": "standard", "HASSHELL": "n", "CGI": "n", "IP": "n",
		"LANG": "en", "DIGESTAUTH": "n",
	}}
}
func (testBackend) ListAccounts() []Account {
	return []Account{{
		User: "example", UID: "2001", Domain: "example.com",
		IP: "203.0.113.10", IPv6: []string{}, Owner: "root", Plan: "starter",
		Theme: "example-theme", Shell: "/usr/sbin/nologin",
		Partition: "home", DiskUsed: "12M", DiskLimit: "2048M",
		InodesUsed: 150, InodesLimit: "50000", Email: "owner@example.com",
		StartDate: "25 Jan 02 09:30", UnixStartdate: 1735810200,
		Suspended: 0, SuspendReason: "not suspended", SuspendTime: 0,
		IsLocked: 0, Temporary: 0, IsTemporaryDomain: 0,
		Backup: 1, LegacyBackup: 0, HasBackup: 0, MailboxFormat: "maildir",
		MaxPop: "20", MaxFTP: "3", MaxSQL: "4",
		MaxLst: "0", MaxSub: "5", MaxParked: "1",
		MaxAddons: "2", MaxEmailacctQuota: "1024",
		MaxEmailPerHour: "100", MaxDeferFailPct: "50",
		MinDeferFailTrig: "3", OutgoingMailHold: 0, OutgoingMailSusp: 0,
		ChildNodes: []string{}, StandaloneFeature: "", StandaloneFeatName: "",
	}}
}

func issueToken(t *testing.T) (*TokenStore, string) {
	t.Helper()
	ts := NewMemoryTokenStore()
	token, _, err := ts.Create("root", "bootstrap")
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	return ts, token
}

func newServer(t *testing.T) (*Server, string) {
	t.Helper()
	ts, token := issueToken(t)
	return New(testBackend{}, ts), token
}

func get(t *testing.T, s *Server, path, authHeader string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if authHeader != "" {
		r.Header.Set("Authorization", authHeader)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestVersionEnvelope(t *testing.T) {
	s, token := newServer(t)
	w := get(t, s, "/json-api/version?api.version=1", "whm root:"+token)
	if w.Code != 200 {
		t.Fatalf("status = %d", w.Code)
	}
	// Compare decoded maps: clients must not depend on key order.
	want := `{"data":{"version":"99.0.0.1"},"metadata":{"version":1,"result":1,"command":"version","reason":"OK"}}`
	var gotMap, wantMap map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &gotMap); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := json.Unmarshal([]byte(want), &wantMap); err != nil {
		t.Fatalf("fixture decode: %v", err)
	}
	if jsonString(gotMap) != jsonString(wantMap) {
		t.Fatalf("body mismatch:\n got %s\nwant %s", w.Body.String(), want)
	}
	if ct := w.Header().Get("Content-Type"); ct != `application/json; charset="utf-8"` {
		t.Fatalf("Content-Type = %q", ct)
	}
	for _, h := range []string{"X-Frame-Options", "X-Content-Type-Options", "Pragma"} {
		if w.Header().Get(h) == "" {
			t.Fatalf("missing header %s", h)
		}
	}
}

func TestUnknownAppExactError(t *testing.T) {
	s, token := newServer(t)
	w := get(t, s, "/json-api/nonexistent_fn?api.version=1", "whm root:"+token)
	if w.Code != 200 {
		t.Fatalf("status = %d", w.Code)
	}
	// Curly quotes, and metadata.version as a string in this error.
	want := `{"metadata":{"reason":"Unknown app (“nonexistent_fn”) requested for this version (1) of the API.","command":"nonexistent_fn","version":"1","result":0}}`
	var gotMap, wantMap map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &gotMap); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := json.Unmarshal([]byte(want), &wantMap); err != nil {
		t.Fatalf("fixture decode: %v", err)
	}
	if jsonString(gotMap) != jsonString(wantMap) {
		t.Fatalf("unknown-app mismatch:\n got %s\nwant %s", w.Body.String(), want)
	}
}

func TestUnauthenticatedLegacyEnvelope(t *testing.T) {
	s, _ := newServer(t)
	w := get(t, s, "/json-api/version?api.version=1", "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d", w.Code)
	}
	want := `{"cpanelresult":{"apiversion":"2","error":"Access denied","data":{"reason":"Access denied","result":"0"},"type":"text"}}`
	var gotMap, wantMap map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &gotMap); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := json.Unmarshal([]byte(want), &wantMap); err != nil {
		t.Fatalf("fixture decode: %v", err)
	}
	if jsonString(gotMap) != jsonString(wantMap) {
		t.Fatalf("403 body mismatch:\n got %s\nwant %s", w.Body.String(), want)
	}
}

func TestAuthSchemes(t *testing.T) {
	s, token := newServer(t)
	if w := get(t, s, "/json-api/version?api.version=1", "whm root:wrong"); w.Code != 403 {
		t.Fatalf("bad token: status = %d", w.Code)
	}
	if w := get(t, s, "/json-api/version?api.version=1", "WHM root:"+token); w.Code != 200 {
		t.Fatalf("case-insensitive scheme: status = %d", w.Code)
	}
	r := httptest.NewRequest(http.MethodGet, "/json-api/version?api.version=1", nil)
	r.SetBasicAuth("root", token)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("basic auth: status = %d", w.Code)
	}
}

func TestListPkgsShape(t *testing.T) {
	s, token := newServer(t)
	w := get(t, s, "/json-api/listpkgs?api.version=1", "whm root:"+token)
	var body struct {
		Data struct {
			Pkg []map[string]string `json:"pkg"`
		} `json:"data"`
		Metadata struct {
			Result int    `json:"result"`
			Reason string `json:"reason"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Metadata.Result != 1 || body.Metadata.Reason != "OK" {
		t.Fatalf("metadata = %+v", body.Metadata)
	}
	if len(body.Data.Pkg) != 1 {
		t.Fatalf("pkg count = %d", len(body.Data.Pkg))
	}
	p := body.Data.Pkg[0]
	for _, k := range []string{"name", "BWLIMIT", "QUOTA", "MAXADDON", "CPMOD", "FEATURELIST", "PACKAGE_TYPE"} {
		if _, ok := p[k]; !ok {
			t.Fatalf("pkg missing key %s", k)
		}
	}
}

func TestListAcctsZeroMatchHasNoDataKey(t *testing.T) {
	s, token := newServer(t)
	w := get(t, s, "/json-api/listaccts?api.version=1&search=nobody&searchtype=user", "whm root:"+token)
	var raw map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, present := raw["data"]; present {
		t.Fatalf("zero-match listaccts must omit data: %s", w.Body.String())
	}
	md := raw["metadata"].(map[string]any)
	if md["result"].(float64) != 1 || md["reason"] != "OK" {
		t.Fatalf("metadata = %v", md)
	}
}

func TestListAcctsSearchMatch(t *testing.T) {
	s, token := newServer(t)
	w := get(t, s, "/json-api/listaccts?api.version=1&search=example&searchtype=user", "whm root:"+token)
	var body struct {
		Data struct {
			Acct []Account `json:"acct"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Data.Acct) != 1 || body.Data.Acct[0].User != "example" {
		t.Fatalf("acct = %+v", body.Data.Acct)
	}
	a := body.Data.Acct[0]
	if a.Theme != "example-theme" || a.MailboxFormat != "maildir" || a.Shell != "/usr/sbin/nologin" || a.UnixStartdate != 1735810200 {
		t.Fatalf("backend fields not passed through: %+v", a)
	}
}

func TestErrorEnvelopeExactStrings(t *testing.T) {
	w := httptest.NewRecorder()
	// A made-up reason in the "(XID …) message" shape; the XID is volatile, so
	// it is asserted by prefix.
	writeError(w, "createacct", "(XID q7k2mz) Example failure for the account “example”.\n")
	var body struct {
		Metadata struct {
			Result  int    `json:"result"`
			Reason  string `json:"reason"`
			Command string `json:"command"`
			Output  struct {
				Raw any `json:"raw"`
			} `json:"output"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Metadata.Result != 0 || body.Metadata.Command != "createacct" {
		t.Fatalf("metadata = %+v", body.Metadata)
	}
	if !strings.HasPrefix(body.Metadata.Reason, "(XID ") ||
		!strings.Contains(body.Metadata.Reason, "Example failure for the account “example”.") {
		t.Fatalf("reason = %q", body.Metadata.Reason)
	}
	if body.Metadata.Output.Raw != nil {
		t.Fatalf("error output.raw must be null, got %v", body.Metadata.Output.Raw)
	}
}

func TestFailClosedWithoutBackendOrAuth(t *testing.T) {
	// Nil authenticator: deny even with a valid-looking header.
	s := New(testBackend{}, nil)
	if w := get(t, s, "/json-api/version?api.version=1", "whm root:x"); w.Code != 403 {
		t.Fatalf("nil auth: status = %d", w.Code)
	}
	// Nil backend: deny after authentication rather than fabricate data.
	ts, token := issueToken(t)
	s = New(nil, ts)
	if w := get(t, s, "/json-api/version?api.version=1", "whm root:"+token); w.Code != 403 {
		t.Fatalf("nil backend: status = %d", w.Code)
	}
}

func jsonString(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return "<marshal error>"
	}
	return string(raw)
}
