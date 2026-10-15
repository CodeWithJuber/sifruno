package whmapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Token endpoint golden strings below are verbatim reference captures
// (2026-10-15, docs/reference/whm-api-contract-batch3.md).

func tokenServer(t *testing.T) (*Server, *TokenStore, string) {
	t.Helper()
	ts := NewMemoryTokenStore()
	token, _, err := ts.Create("root", "bootstrap")
	if err != nil {
		t.Fatalf("bootstrap token: %v", err)
	}
	return New(testBackend{}, ts), ts, token
}

func tokenCall(t *testing.T, s *Server, token, path string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Header.Set("Authorization", "whm root:"+token)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestTokenCreateSuccessShape(t *testing.T) {
	s, ts, token := tokenServer(t)
	w := tokenCall(t, s, token, "/json-api/api_token_create?api.version=1&token_name=whmcs-prod")
	var body struct {
		Data struct {
			Name       string `json:"name"`
			ExpiresAt  any    `json:"expires_at"`
			CreateTime int64  `json:"create_time"`
			Token      string `json:"token"`
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
	if body.Data.Name != "whmcs-prod" || body.Data.ExpiresAt != nil || body.Data.CreateTime == 0 {
		t.Fatalf("data = %+v", body.Data)
	}
	if len(body.Data.Token) != 64 {
		t.Fatalf("token length = %d", len(body.Data.Token))
	}
	// The issued token must authenticate via the WHM header scheme.
	if !ts.Authenticate("root", body.Data.Token) {
		t.Fatal("issued token does not authenticate")
	}
}

func TestTokenCreateMissingNameExactError(t *testing.T) {
	s, _, token := tokenServer(t)
	w := tokenCall(t, s, token, "/json-api/api_token_create?api.version=1")
	body := decodeEnvelope(t, w)
	md := metadataOf(t, body)
	want := "The system failed to create the API token: The parameter “token_name” is required."
	if md["reason"] != want {
		t.Fatalf("reason = %q want %q", md["reason"], want)
	}
	if _, ok := body["data"]; !ok {
		t.Fatal("observed create errors carry an empty data object")
	}
}

func TestTokenCreateInvalidAndConflictExactErrors(t *testing.T) {
	s, _, token := tokenServer(t)
	w := tokenCall(t, s, token, "/json-api/api_token_create?api.version=1&token_name=bad+name+!!")
	md := metadataOf(t, decodeEnvelope(t, w))
	if !strings.Contains(md["reason"].(string), "is not a valid API token name. An API token name must not be longer than 50 characters and may only contain the following characters: a-z A-Z 0-9 _ -") {
		t.Fatalf("invalid-name reason = %q", md["reason"])
	}

	tokenCall(t, s, token, "/json-api/api_token_create?api.version=1&token_name=taken")
	w = tokenCall(t, s, token, "/json-api/api_token_create?api.version=1&token_name=taken")
	md = metadataOf(t, decodeEnvelope(t, w))
	if md["reason"] != "The system failed to create the API token: A conflicting API token with the name “taken” already exists." {
		t.Fatalf("conflict reason = %q", md["reason"])
	}
}

func TestTokenListShapeAndRedaction(t *testing.T) {
	s, _, token := tokenServer(t)
	tokenCall(t, s, token, "/json-api/api_token_create?api.version=1&token_name=whmcs-prod")
	w := tokenCall(t, s, token, "/json-api/api_token_list?api.version=1")
	var body struct {
		Data struct {
			Tokens map[string]struct {
				ACLs       map[string]int `json:"acls"`
				ExpiresAt  any            `json:"expires_at"`
				CreateTime int64          `json:"create_time"`
				Name       string         `json:"name"`
			} `json:"tokens"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	tk, ok := body.Data.Tokens["whmcs-prod"]
	if !ok || tk.Name != "whmcs-prod" || tk.CreateTime == 0 {
		t.Fatalf("tokens = %+v", body.Data.Tokens)
	}
	if tk.ACLs["all"] != 1 {
		t.Fatalf("acls = %v", tk.ACLs)
	}
	if strings.Contains(w.Body.String(), "sha256") {
		t.Fatal("digest material leaked into list response")
	}
}

func TestTokenRevokeIdempotent(t *testing.T) {
	s, ts, token := tokenServer(t)
	tokenCall(t, s, token, "/json-api/api_token_create?api.version=1&token_name=temp")
	for i := 0; i < 2; i++ {
		w := tokenCall(t, s, token, "/json-api/api_token_revoke?api.version=1&token_name=temp")
		md := metadataOf(t, decodeEnvelope(t, w))
		// Observed: repeat revoke still returns result:1.
		if md["result"].(float64) != 1 || md["reason"] != "OK" {
			t.Fatalf("revoke %d metadata = %v", i, md)
		}
	}
	for _, info := range ts.List() {
		if info.Name == "temp" {
			t.Fatal("revoked token still listed")
		}
	}
}

func TestTokenStorePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whmapi-tokens.json")
	s1, err := OpenTokenStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	token, _, err := s1.Create("root", "persisted")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o", fi.Mode().Perm())
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), token) {
		t.Fatal("plaintext token persisted")
	}
	s2, err := OpenTokenStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if !s2.Authenticate("root", token) {
		t.Fatal("reopened store does not authenticate issued token")
	}
	if s2.Authenticate("root", token+"x") || s2.Authenticate("nobody", token) {
		t.Fatal("store accepted wrong credential")
	}
}

func TestTokenEndpointsFailClosedWithoutManager(t *testing.T) {
	// An authenticator that is not a TokenManager denies token management.
	s := New(testBackend{}, staticAuth{user: "root", pass: "x"})
	w := tokenCall(t, s, "x", "/json-api/api_token_create?api.version=1&token_name=nope")
	md := metadataOf(t, decodeEnvelope(t, w))
	if md["result"].(float64) != 0 {
		t.Fatalf("token create without manager: %v", md)
	}
}

type staticAuth struct{ user, pass string }

func (a staticAuth) Authenticate(user, credential string) bool {
	return user == a.user && credential == a.pass
}
