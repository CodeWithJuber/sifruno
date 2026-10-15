package whmapi

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"
)

// create_user_session goldens from licensed 138 captures (batch 3 + batch 6).

func sessionServer(t *testing.T) (*Server, *SessionStore, string) {
	t.Helper()
	ts, token := issueToken(t)
	ss := NewMemorySessionStore()
	s := New(testBackend{}, ts).WithSessionStore(ss, "https://panel.example.test")
	return s, ss, token
}

func TestUserSessionSuccessShape(t *testing.T) {
	s, ss, token := sessionServer(t)
	before := time.Now().Unix()
	w := post(t, s, "/json-api/create_user_session?api.version=1&user=example&service=cpaneld&locale=en", token)
	var body struct {
		Data struct {
			URL      string `json:"url"`
			Session  string `json:"session"`
			SecToken string `json:"cp_security_token"`
			Expires  int64  `json:"expires"`
			Service  string `json:"service"`
			Locale   string `json:"locale"`
		} `json:"data"`
		Metadata struct {
			Reason string `json:"reason"`
			Result int    `json:"result"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Metadata.Result != 1 || body.Metadata.Reason != "Created session" {
		t.Fatalf("metadata = %+v", body.Metadata)
	}
	// Observed: expires = created + 300; URL carries the per-service port
	// (cpaneld 2083) and /cpsess<digits>/login/?session= path.
	if d := body.Data.Expires - before; d < 299 || d > 301 {
		t.Fatalf("ttl = %d", d)
	}
	if !strings.HasPrefix(body.Data.URL, "https://panel.example.test:2083/cpsess") ||
		!strings.Contains(body.Data.URL, "/login/?session=") {
		t.Fatalf("url = %q", body.Data.URL)
	}
	if !regexp.MustCompile(`^/cpsess[0-9]{10}$`).MatchString(body.Data.SecToken) {
		t.Fatalf("sec token = %q", body.Data.SecToken)
	}
	if !regexp.MustCompile(`^example:[A-Za-z]{16}:create_user_session,[a-f0-9]{32}$`).MatchString(body.Data.Session) {
		t.Fatalf("session format = %q", body.Data.Session)
	}
	// The issued token validates; plaintext is not stored.
	rec, ok := ss.Validate(body.Data.Session)
	if !ok || rec.User != "example" || rec.Service != "cpaneld" {
		t.Fatalf("validate = %+v %v", rec, ok)
	}
	// Plaintext must never be recoverable from stored metadata.
	stored := ss.List()
	if len(stored) != 1 || strings.Contains(stored[0].SHA256, body.Data.Session) || strings.Contains(stored[0].ID, body.Data.Session) {
		t.Fatal("plaintext session persisted")
	}
}

func TestUserSessionServicePorts(t *testing.T) {
	s, _, token := sessionServer(t)
	// Observed: webmaild uses the 2096 webmail port.
	w := post(t, s, "/json-api/create_user_session?api.version=1&user=example&service=webmaild", token)
	var body struct {
		Data struct {
			URL string `json:"url"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.HasPrefix(body.Data.URL, "https://panel.example.test:2096/") {
		t.Fatalf("webmail url = %q", body.Data.URL)
	}
}

func TestUserSessionExactErrors(t *testing.T) {
	s, _, token := sessionServer(t)
	cases := []struct{ path, want string }{
		{"/json-api/create_user_session?api.version=1", "The “user” parameter is required."},
		{"/json-api/create_user_session?api.version=1&user=example", "The “service” parameter is required."},
		{"/json-api/create_user_session?api.version=1&user=example&service=nosuchd", "The “service” parameter is invalid. The only supported services for this API call are “cpaneld”, “webmaild”, and “whostmgrd”."},
		{"/json-api/create_user_session?api.version=1&user=ghost&service=cpaneld", "You cannot create a session for the user “ghost” because they do not exist."},
	}
	for _, c := range cases {
		w := post(t, s, c.path, token)
		md := metadataOf(t, decodeEnvelope(t, w))
		if md["result"].(float64) != 0 || md["reason"] != c.want {
			t.Fatalf("%s: metadata = %v", c.path, md)
		}
	}
}

func TestUserSessionFailClosedWithoutStore(t *testing.T) {
	ts, token := issueToken(t)
	s := New(testBackend{}, ts) // no session store configured
	w := post(t, s, "/json-api/create_user_session?api.version=1&user=example&service=cpaneld", token)
	md := metadataOf(t, decodeEnvelope(t, w))
	if md["result"].(float64) != 0 {
		t.Fatalf("session without store must fail: %v", md)
	}
}

func TestUserSessionExpiry(t *testing.T) {
	ss := NewMemorySessionStore()
	issued, err := ss.Create("example", "cpaneld", "")
	if err != nil {
		t.Fatal(err)
	}
	// Force expiry by backdating the record beyond the TTL.
	ss.mu.Lock()
	rec := ss.sessions[issued.Record.ID]
	rec.CreatedAt -= int64(SessionTTL.Seconds()) + 5
	rec.ExpiresAt -= int64(SessionTTL.Seconds()) + 5
	ss.sessions[issued.Record.ID] = rec
	ss.mu.Unlock()
	if _, ok := ss.Validate(issued.SessionToken); ok {
		t.Fatal("expired session validated")
	}
}
