package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"sifruno/internal/whmapi"
)

// whmStub serves a minimal WHM API 1 response for wiring tests.
func whmStub(t *testing.T) (http.Handler, string) {
	t.Helper()
	ts := whmapi.NewMemoryTokenStore()
	token, _, err := ts.Create("root", "wiring")
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	return whmapi.New(whmapi.HostAccounts{Build: "11.138.0.11"}, ts), token
}

func TestWHMRoutedWhenConfigured(t *testing.T) {
	stub, token := whmStub(t)
	h := New(Options{WHM: stub, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/json-api/version?api.version=1", nil)
	r.Header.Set("Authorization", "whm root:"+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", w.Code, w.Body.String())
	}
	var body struct {
		Data struct {
			Version string `json:"version"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Data.Version != "11.138.0.11" {
		t.Fatalf("body = %s err = %v", w.Body.String(), err)
	}
}

func TestWHM501WhenNotConfigured(t *testing.T) {
	h := New(Options{AllowedOrigins: []string{"http://127.0.0.1:8080"}})
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/json-api/version?api.version=1", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d body = %s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body["error"] != "compatibility_not_implemented" {
		t.Fatalf("body = %s err = %v", w.Body.String(), err)
	}
}

func TestWHMUnauthenticatedDeniedThroughPanel(t *testing.T) {
	stub, _ := whmStub(t)
	h := New(Options{WHM: stub, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/json-api/version?api.version=1", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d body = %s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["cpanelresult"]; !ok {
		t.Fatalf("expected legacy cpanelresult envelope, got %s", w.Body.String())
	}
}
