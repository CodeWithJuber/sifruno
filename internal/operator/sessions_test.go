package operator

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const inventoryPath = "/api/v1/session/sessions"

func inventoryFor(t *testing.T, h http.Handler, c *http.Cookie) Inventory {
	t.Helper()
	w := opRequest(h, "GET", inventoryPath, "", c, "")
	if w.Code != 200 {
		t.Fatalf("inventory status %d", w.Code)
	}
	var v Inventory
	if json.Unmarshal(w.Body.Bytes(), &v) != nil {
		t.Fatal("inventory JSON")
	}
	return v
}
func currentID(t *testing.T, h http.Handler, c *http.Cookie) string {
	t.Helper()
	v := inventoryFor(t, h, c)
	for _, s := range v.Items {
		if s.Current {
			return s.ID
		}
	}
	t.Fatal("current session absent")
	return ""
}
func revokePath(id string) string { return inventoryPath + "/" + id + "/revoke" }
func TestManagementInventoryRevokeReplayAndCurrentProtection(t *testing.T) {
	m, h, key := fixture(t)
	a, as := signIn(t, h, key, nil)
	b, _ := signIn(t, h, key, nil)
	c, _ := signIn(t, h, key, nil)
	v := inventoryFor(t, h, a)
	if len(v.Items) != 3 || v.Capacity != 128 || v.LifetimeSeconds != 900 {
		t.Fatal("inventory bounds")
	}
	seen := map[string]bool{}
	current := 0
	for i, s := range v.Items {
		if !validManagementID(s.ID) || seen[s.ID] || s.CreatedAt.IsZero() || s.ExpiresAt.Sub(s.CreatedAt) != sessionLifetime {
			t.Fatal("inventory metadata")
		}
		seen[s.ID] = true
		if s.Current {
			current++
		}
		if i > 0 && (v.Items[i-1].CreatedAt.Before(s.CreatedAt) || v.Items[i-1].CreatedAt.Equal(s.CreatedAt) && v.Items[i-1].ID > s.ID) {
			t.Fatal("inventory unsorted")
		}
	}
	if current != 1 {
		t.Fatal("current marker")
	}
	body := opRequest(h, "GET", inventoryPath, "", a, "").Body.String()
	m.mu.Lock()
	for rawID, s := range m.active {
		if strings.Contains(body, rawID) || strings.Contains(body, fmt.Sprintf("%x", s.csrf)) {
			m.mu.Unlock()
			t.Fatal("sensitive metadata exposed")
		}
	}
	m.mu.Unlock()
	for _, secret := range []string{key, a.Value, as.CSRFToken} {
		if strings.Contains(body, secret) {
			t.Fatal("credential in inventory")
		}
	}
	own := currentID(t, h, a)
	target := currentID(t, h, b)
	if w := opRequest(h, "POST", revokePath(own), "{}", a, as.CSRFToken); w.Code != 409 {
		t.Fatal("current revoke allowed")
	}
	if w := opRequest(h, "POST", revokePath(target), "{}", a, as.CSRFToken); w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"revoked_count":1}` {
		t.Fatal("target revoke failed")
	}
	if w := opRequest(h, "GET", "/api/v1/session", "", b, ""); w.Code != 401 {
		t.Fatal("revoked cookie replay")
	}
	if w := opRequest(h, "POST", revokePath(target), "{}", a, as.CSRFToken); w.Code != 404 {
		t.Fatal("unknown target status")
	}
	if w := opRequest(h, "POST", "/api/v1/session/revoke-others", "{}", a, as.CSRFToken); w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"revoked_count":1}` {
		t.Fatal("revoke others failed")
	}
	if w := opRequest(h, "GET", "/api/v1/session", "", c, ""); w.Code != 401 {
		t.Fatal("other replay")
	}
	v = inventoryFor(t, h, a)
	if len(v.Items) != 1 || !v.Items[0].Current || v.Items[0].ID != own {
		t.Fatal("authorizer was not preserved")
	}
	if w := opRequest(h, "POST", "/api/v1/session/revoke-others", "{}", a, as.CSRFToken); w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"revoked_count":0}` {
		t.Fatal("empty revocation count")
	}
	next, _ := signIn(t, h, key, a)
	if currentID(t, h, next) == own {
		t.Fatal("rotation reused management ID")
	}
	if len(inventoryFor(t, h, next).Items) != 1 {
		t.Fatal("rotation retained old inventory")
	}
}

func TestManagementAdmissionAndStrictEmptyBodies(t *testing.T) {
	_, h, key := fixture(t)
	a, as := signIn(t, h, key, nil)
	b, _ := signIn(t, h, key, nil)
	target := currentID(t, h, b)
	for _, path := range []string{revokePath(target), "/api/v1/session/revoke-others"} {
		for _, test := range []struct {
			body   string
			status int
		}{{"", 400}, {" ", 400}, {"null", 400}, {"[]", 400}, {"{} {}", 400}, {`{"id":"x"}`, 400}, {`{"ID":"x"}`, 400}, {`{"revoked_count":0}`, 400}, {`{"current":true,"current":false}`, 400}, {"{\xff}", 400}, {strings.Repeat(" ", maxLoginBytes) + "{}", 413}} {
			if w := opRequest(h, "POST", path, test.body, a, as.CSRFToken); w.Code != test.status {
				t.Fatalf("body admission status %d wanted %d", w.Code, test.status)
			}
		}
		for _, test := range []struct {
			name   string
			mutate func(*http.Request)
			status int
		}{
			{"unauthenticated", func(r *http.Request) { r.Header.Del("Cookie") }, 401},
			{"nonlocal", func(r *http.Request) { r.RemoteAddr = "192.0.2.1:1234" }, 403},
			{"foreign host", func(r *http.Request) { r.Host = "evil.invalid:8080" }, 403},
			{"missing origin", func(r *http.Request) { r.Header.Del("Origin") }, 403},
			{"foreign origin", func(r *http.Request) { r.Header.Set("Origin", "http://foreign.invalid") }, 403},
			{"cross site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403},
			{"missing CSRF", func(r *http.Request) { r.Header.Del("X-CSRF-Token") }, 403},
			{"wrong CSRF", func(r *http.Request) { r.Header.Set("X-CSRF-Token", strings.Repeat("a", 43)) }, 403},
			{"wrong content type", func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 415},
		} {
			t.Run(test.name+path, func(t *testing.T) {
				r := managementRequest(path, "{}", a, as.CSRFToken)
				test.mutate(r)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != test.status {
					t.Fatalf("admission status %d wanted %d", w.Code, test.status)
				}
			})
		}
	}
	for _, id := range []string{strings.Repeat("A", 32), strings.Repeat("a", 31), strings.Repeat("g", 32)} {
		if w := opRequest(h, "POST", revokePath(id), "{}", a, as.CSRFToken); w.Code != 400 {
			t.Fatal("malformed management ID admitted")
		}
	}
	if len(inventoryFor(t, h, a).Items) != 2 {
		t.Fatal("refusal mutated inventory")
	}
	if w := opRequest(h, "GET", inventoryPath, "", nil, ""); w.Code != 401 {
		t.Fatal("unauthenticated inventory")
	}
	r := managementRequest(inventoryPath, "", a, "")
	r.Method = "GET"
	r.RemoteAddr = "192.0.2.1:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("nonlocal inventory")
	}
}
func managementRequest(path, body string, c *http.Cookie, csrf string) *http.Request {
	r := httptest.NewRequest("POST", "http://127.0.0.1:8080"+path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Origin", "http://127.0.0.1:8080")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	if c != nil {
		r.AddCookie(c)
	}
	return r
}

type gatedBody struct {
	entered, release chan struct{}
	once             sync.Once
	reader           io.Reader
}

func (b *gatedBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return b.reader.Read(p)
}
func (b *gatedBody) Close() error { return nil }
func TestManagementRevokedAuthorizerDuringBodyReadCannotMutate(t *testing.T) {
	for _, others := range []bool{false, true} {
		t.Run(fmt.Sprint(others), func(t *testing.T) {
			_, h, key := fixture(t)
			a, as := signIn(t, h, key, nil)
			b, bs := signIn(t, h, key, nil)
			c, _ := signIn(t, h, key, nil)
			aid := currentID(t, h, a)
			cid := currentID(t, h, c)
			path := revokePath(cid)
			if others {
				path = "/api/v1/session/revoke-others"
			}
			r := managementRequest(path, "", a, as.CSRFToken)
			gate := &gatedBody{make(chan struct{}), make(chan struct{}), sync.Once{}, strings.NewReader("{}")}
			r.Body = gate
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { w := httptest.NewRecorder(); h.ServeHTTP(w, r); done <- w }()
			select {
			case <-gate.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("body gate not reached")
			}
			w := opRequest(h, "POST", revokePath(aid), "{}", b, bs.CSRFToken)
			close(gate.release)
			if w.Code != 200 {
				t.Fatal("rescuer revoke failed")
			}
			select {
			case w = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("stale authorizer blocked")
			}
			if w.Code != 401 {
				t.Fatal("stale authorization mutated sessions")
			}
			if w := opRequest(h, "GET", "/api/v1/session", "", c, ""); w.Code != 200 {
				t.Fatal("stale revocation removed target")
			}
			if len(inventoryFor(t, h, b).Items) != 2 {
				t.Fatal("stale mutation changed inventory")
			}
		})
	}
}
func TestManagementInventoryExpiryBoundAndRestart(t *testing.T) {
	m, h, key := fixture(t)
	c, _ := signIn(t, h, key, nil)
	now := m.now()
	m.mu.Lock()
	for i := 1; i < maxSessions; i++ {
		m.active[fmt.Sprintf("fixture-%d", i)] = activeSession{managementID: fmt.Sprintf("%032x", i), created: now.Add(-time.Minute), expires: now.Add(time.Minute)}
	}
	m.active["fixture-expired"] = activeSession{managementID: strings.Repeat("f", 32), created: now.Add(-sessionLifetime), expires: now}
	m.mu.Unlock()
	v := inventoryFor(t, h, c)
	if len(v.Items) != maxSessions {
		t.Fatal("expiry pruning or capacity inventory")
	}
	m.mu.Lock()
	if len(m.active) != maxSessions {
		m.mu.Unlock()
		t.Fatal("expired entry retained")
	}
	m.mu.Unlock()
	if w := opRequest(h, "POST", "/api/v1/session/login", fmt.Sprintf(`{"access_key":%q}`, key), nil, ""); w.Code != 429 {
		t.Fatal("management bypassed session cap")
	}
	m.now = func() time.Time { return now.Add(16 * time.Minute) }
	if w := opRequest(h, "GET", inventoryPath, "", c, ""); w.Code != 401 {
		t.Fatal("expired current enumerated sessions")
	}
	m2, e := Open(strings.TrimSuffix(m.AccessKeyPath(), "access.key"))
	if e != nil {
		t.Fatal(e)
	}
	mux := http.NewServeMux()
	m2.Register(mux)
	if w := opRequest(mux, "GET", inventoryPath, "", c, ""); w.Code != 401 {
		t.Fatal("restart restored inventory")
	}
}

func TestManagementConcurrentRevokeOthersHasOneAuthorizer(t *testing.T) {
	_, h, key := fixture(t)
	a, as := signIn(t, h, key, nil)
	b, bs := signIn(t, h, key, nil)
	done := make(chan int, 2)
	gates := []*gatedBody{}
	for i, cookie := range []*http.Cookie{a, b} {
		csrf := []string{as.CSRFToken, bs.CSRFToken}[i]
		r := managementRequest("/api/v1/session/revoke-others", "", cookie, csrf)
		gate := &gatedBody{entered: make(chan struct{}), release: make(chan struct{}), reader: strings.NewReader("{}")}
		gates = append(gates, gate)
		r.Body = gate
		go func() { w := httptest.NewRecorder(); h.ServeHTTP(w, r); done <- w.Code }()
	}
	for _, gate := range gates {
		select {
		case <-gate.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("body gate not reached")
		}
	}
	for _, gate := range gates {
		close(gate.release)
	}
	statuses := map[int]int{}
	for i := 0; i < 2; i++ {
		select {
		case status := <-done:
			statuses[status]++
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent revoke blocked")
		}
	}
	if statuses[200] != 1 || statuses[401] != 1 {
		t.Fatal("concurrent stale authorizer accepted")
	}
	active := 0
	for _, cookie := range []*http.Cookie{a, b} {
		if opRequest(h, "GET", "/api/v1/session", "", cookie, "").Code == 200 {
			active++
		}
	}
	if active != 1 {
		t.Fatal("concurrent revocation lost current winner")
	}
}

func TestManagementAuthorizerExpiresDuringBodyRead(t *testing.T) {
	m, h, key := fixture(t)
	base := time.Now().UTC()
	m.now = func() time.Time { return base }
	a, as := signIn(t, h, key, nil)
	m.now = func() time.Time { return base.Add(2 * time.Minute) }
	b, _ := signIn(t, h, key, nil)
	target := currentID(t, h, b)
	r := managementRequest(revokePath(target), "", a, as.CSRFToken)
	gate := &gatedBody{entered: make(chan struct{}), release: make(chan struct{}), reader: strings.NewReader("{}")}
	r.Body = gate
	done := make(chan int, 1)
	go func() { w := httptest.NewRecorder(); h.ServeHTTP(w, r); done <- w.Code }()
	select {
	case <-gate.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("body gate not reached")
	}
	m.mu.Lock()
	m.now = func() time.Time { return base.Add(16 * time.Minute) }
	m.mu.Unlock()
	close(gate.release)
	select {
	case status := <-done:
		if status != 401 {
			t.Fatal("expired authorizer accepted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("expiry revoke blocked")
	}
	if opRequest(h, "GET", "/api/v1/session", "", b, "").Code != 200 {
		t.Fatal("expired authorizer removed target")
	}
}
