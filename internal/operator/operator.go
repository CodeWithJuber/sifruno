// Package operator authenticates a single local operator. This is a loopback
// deployment boundary, not remote production authentication or a role system.
package operator

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gofrs/flock"
	"github.com/gorilla/sessions"
	"golang.org/x/time/rate"
	"sifruno/internal/securestate"
)

const (
	cookieName      = "sifruno_operator"
	sessionLifetime = 15 * time.Minute
	maxSessions     = 128
	maxLoginBytes   = 2048
)

type Session struct {
	Authenticated bool      `json:"authenticated"`
	CSRFToken     string    `json:"csrf_token,omitempty"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
}

type activeSession struct {
	expires time.Time
	csrf    [32]byte
}

type Manager struct {
	keyPath string
	keyHash [32]byte
	cookies *sessions.CookieStore
	limiter *rate.Limiter
	now     func() time.Time
	mu      sync.Mutex
	active  map[string]activeSession
}

// Open creates project-owned private state without rotating existing secrets.
// access.key is 43 base64url characters followed by one newline. The key itself
// is never returned by the manager or by an HTTP response.
func Open(dir string) (*Manager, error) {
	dir, err := securestate.Dir(dir)
	if err != nil {
		return nil, errors.New("operator private state unavailable")
	}
	lockPath := filepath.Join(dir, "operator.lock")
	if err := securestate.CheckPath(lockPath); err != nil {
		return nil, errors.New("operator private state unavailable")
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, errors.New("operator private state unavailable")
	}
	lockInfo, err := f.Stat()
	if err != nil || privateHandle(f, lockInfo) != nil {
		f.Close()
		return nil, errors.New("operator private state unavailable")
	}
	if err = f.Close(); err != nil {
		return nil, errors.New("operator private state unavailable")
	}
	lock := flock.New(lockPath)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	locked, err := lock.TryLockContext(ctx, 50*time.Millisecond)
	if err != nil || !locked {
		return nil, errors.New("operator private state unavailable")
	}
	defer lock.Unlock()
	accessPath := filepath.Join(dir, "access.key")
	access, err := privateBytes(accessPath, 44, func() ([]byte, error) {
		v, err := randomToken()
		if err != nil {
			return nil, err
		}
		return []byte(v + "\n"), nil
	})
	if err != nil {
		return nil, errors.New("operator access key unavailable")
	}
	if len(access) != 44 || access[43] != '\n' || !validToken(string(access[:43])) {
		return nil, errors.New("operator access key invalid")
	}
	keys, err := privateBytes(filepath.Join(dir, "session.keys"), 64, func() ([]byte, error) {
		v := make([]byte, 64)
		_, err := rand.Read(v)
		return v, err
	})
	if err != nil {
		return nil, errors.New("operator session keys unavailable")
	}
	cookies := sessions.NewCookieStore(keys[:32], keys[32:])
	cookies.MaxAge(int(sessionLifetime.Seconds()))
	cookies.Options = &sessions.Options{Path: "/api/v1", MaxAge: int(sessionLifetime.Seconds()), HttpOnly: true, SameSite: http.SameSiteStrictMode}
	return &Manager{keyPath: accessPath, keyHash: sha256.Sum256(access[:43]), cookies: cookies,
		limiter: rate.NewLimiter(rate.Every(3*time.Second), 20), now: time.Now, active: make(map[string]activeSession)}, nil
}

func privateBytes(path string, size int64, generate func() ([]byte, error)) ([]byte, error) {
	if err := securestate.CheckPath(path); err != nil {
		return nil, err
	}
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		b, err := generate()
		if err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, err
		}
		st, err := f.Stat()
		if err != nil || privateHandle(f, st) != nil {
			f.Close()
			return nil, errors.New("invalid private file")
		}
		_, writeErr := f.Write(b)
		if writeErr == nil {
			writeErr = f.Sync()
		}
		closeErr := f.Close()
		if writeErr != nil {
			return nil, writeErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		return b, nil
	}
	if err != nil || !st.Mode().IsRegular() || st.Size() != size || (runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0) {
		return nil, errors.New("invalid private file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(st, opened) || privateHandle(f, opened) != nil {
		return nil, errors.New("private file changed")
	}
	b, err := io.ReadAll(io.LimitReader(f, size+1))
	if err != nil || int64(len(b)) != size {
		return nil, errors.New("invalid private file")
	}
	return b, nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b), err
}
func validToken(s string) bool {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return err == nil && len(s) == 43 && len(b) == 32
}
func (m *Manager) AccessKeyPath() string { return m.keyPath }

// WriteError uses fixed problem details and never includes an input value,
// private filesystem path, cookie, or underlying SDK error.
func WriteError(w http.ResponseWriter, status int, code, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(struct {
		Type          string `json:"type"`
		Title         string `json:"title"`
		Status        int    `json:"status"`
		Detail        string `json:"detail"`
		Error         string `json:"error"`
		Authenticated bool   `json:"authenticated"`
	}{"about:blank", http.StatusText(status), status, detail, code, false})
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	json.NewEncoder(w).Encode(value)
}

func localRequest(r *http.Request) bool {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host != "localhost" && host != "127.0.0.1" && host != "::1" {
		return false
	}
	remote, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(remote)
	return ip != nil && ip.IsLoopback()
}

func sameOrigin(r *http.Request) bool {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return r.Header.Get("Origin") == scheme+"://"+r.Host && r.Header.Get("Sec-Fetch-Site") != "cross-site"
}

func (m *Manager) session(r *http.Request) (*sessions.Session, string, activeSession, bool) {
	var cookieBytes int
	for _, value := range r.Header.Values("Cookie") {
		cookieBytes += len(value)
	}
	if cookieBytes > 4096 {
		return nil, "", activeSession{}, false
	}
	s, err := m.cookies.New(r, cookieName)
	if err != nil || s.IsNew {
		return nil, "", activeSession{}, false
	}
	id, idOK := s.Values["id"].(string)
	csrf, csrfOK := s.Values["csrf"].(string)
	expires, expOK := s.Values["expires"].(int64)
	if !idOK || !csrfOK || !expOK || !validToken(id) || !validToken(csrf) {
		return nil, "", activeSession{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked()
	a, ok := m.active[id]
	supplied := sha256.Sum256([]byte(csrf))
	if !ok || a.expires.Unix() != expires || subtle.ConstantTimeCompare(a.csrf[:], supplied[:]) != 1 {
		return nil, "", activeSession{}, false
	}
	return s, id, a, true
}

func (m *Manager) pruneLocked() {
	now := m.now()
	for id, a := range m.active {
		if !now.Before(a.expires) {
			delete(m.active, id)
		}
	}
}

// Authorize protects every website read. Mutations additionally require an
// exact request Origin and the active session's independent CSRF token.
func (m *Manager) Authorize(w http.ResponseWriter, r *http.Request, mutation bool) (string, bool) {
	if !localRequest(r) {
		WriteError(w, 403, "local_access_required", "Local operator access required")
		return "", false
	}
	s, _, a, ok := m.session(r)
	if !ok {
		WriteError(w, 401, "unauthorized", "Operator session required")
		return "", false
	}
	if mutation {
		if !sameOrigin(r) {
			WriteError(w, 403, "origin_not_allowed", "Exact local Origin required")
			return "", false
		}
		csrf := r.Header.Get("X-CSRF-Token")
		supplied := sha256.Sum256([]byte(csrf))
		if !validToken(csrf) || subtle.ConstantTimeCompare(a.csrf[:], supplied[:]) != 1 || s.Values["csrf"] != csrf {
			WriteError(w, 403, "csrf_invalid", "Valid session CSRF token required")
			return "", false
		}
	}
	return "local-operator", true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any, allowEmpty bool) bool {
	ct, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || ct != "application/json" || (params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8")) {
		WriteError(w, 415, "invalid_request", "JSON content type required")
		return false
	}
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(5 * time.Second))
	defer http.NewResponseController(w).SetReadDeadline(time.Time{})
	b, err := io.ReadAll(io.LimitReader(r.Body, maxLoginBytes+1))
	if err != nil {
		WriteError(w, 400, "invalid_request", "Invalid JSON request")
		return false
	}
	if len(b) > maxLoginBytes {
		WriteError(w, 413, "invalid_request", "Request body too large")
		return false
	}
	trimmed := strings.TrimSpace(string(b))
	if allowEmpty && len(trimmed) == 0 {
		return true
	}
	if len(trimmed) == 0 || trimmed[0] != '{' {
		WriteError(w, 400, "invalid_request", "JSON object required")
		return false
	}
	if DecodeObject(b, target) != nil {
		WriteError(w, 400, "invalid_request", "Invalid JSON request")
		return false
	}
	return true
}

// DecodeObject strictly decodes a single typed JSON object. Duplicate fields,
// unknown fields, trailing data, and a null root are rejected without exposing
// the decoder's error text. Callers must bound the bytes before calling it.
func DecodeObject(b []byte, target any) error {
	invalid := errors.New("invalid JSON object")
	if !utf8.Valid(b) {
		return invalid
	}
	d := json.NewDecoder(bytes.NewReader(b))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return invalid
	}
	seen := make(map[string]bool)
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] || len(seen) >= 16 {
			return invalid
		}
		seen[key] = true
		var raw json.RawMessage
		if d.Decode(&raw) != nil {
			return invalid
		}
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return invalid
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return invalid
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil || d.Decode(&struct{}{}) != io.EOF {
		return invalid
	}
	return nil
}

func (m *Manager) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/session/login", m.login)
	mux.HandleFunc("GET /api/v1/session", m.getSession)
	mux.HandleFunc("POST /api/v1/session/logout", m.logout)
}

func (m *Manager) login(w http.ResponseWriter, r *http.Request) {
	if !localRequest(r) {
		WriteError(w, 403, "local_access_required", "Local operator access required")
		return
	}
	if !sameOrigin(r) {
		WriteError(w, 403, "origin_not_allowed", "Exact local Origin required")
		return
	}
	if !m.limiter.Allow() {
		w.Header().Set("Retry-After", "3")
		WriteError(w, 429, "rate_limited", "Login attempt limit reached")
		return
	}
	var input struct {
		AccessKey string `json:"access_key"`
	}
	if !decodeJSON(w, r, &input, false) {
		return
	}
	supplied := sha256.Sum256([]byte(input.AccessKey))
	valid := subtle.ConstantTimeCompare(m.keyHash[:], supplied[:]) == 1 && validToken(input.AccessKey)
	if !valid {
		WriteError(w, 401, "unauthorized", "Invalid operator credential")
		return
	}
	_, oldID, _, _ := m.session(r)
	id, err := randomToken()
	if err != nil {
		WriteError(w, 503, "operator_unavailable", "Operator session unavailable")
		return
	}
	csrf, err := randomToken()
	if err != nil {
		WriteError(w, 503, "operator_unavailable", "Operator session unavailable")
		return
	}
	expires := m.now().UTC().Add(sessionLifetime).Truncate(time.Second)
	m.mu.Lock()
	m.pruneLocked()
	if oldID != "" {
		delete(m.active, oldID)
	}
	if len(m.active) >= maxSessions {
		m.mu.Unlock()
		WriteError(w, 429, "rate_limited", "Active session limit reached")
		return
	}
	m.active[id] = activeSession{expires: expires, csrf: sha256.Sum256([]byte(csrf))}
	m.mu.Unlock()
	s := sessions.NewSession(m.cookies, cookieName)
	s.Values = map[any]any{"id": id, "csrf": csrf, "expires": expires.Unix()}
	options := *m.cookies.Options
	options.Secure = r.TLS != nil
	s.Options = &options
	if err := m.cookies.Save(r, w, s); err != nil {
		m.mu.Lock()
		delete(m.active, id)
		m.mu.Unlock()
		WriteError(w, 503, "operator_unavailable", "Operator session unavailable")
		return
	}
	writeJSON(w, Session{Authenticated: true, CSRFToken: csrf, ExpiresAt: expires})
}

func (m *Manager) getSession(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.Authorize(w, r, false); !ok {
		return
	}
	s, _, a, ok := m.session(r)
	if !ok {
		WriteError(w, 401, "unauthorized", "Operator session required")
		return
	}
	writeJSON(w, Session{Authenticated: true, CSRFToken: s.Values["csrf"].(string), ExpiresAt: a.expires})
}

func (m *Manager) logout(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.Authorize(w, r, true); !ok {
		return
	}
	var input struct{}
	if !decodeJSON(w, r, &input, true) {
		return
	}
	s, id, _, ok := m.session(r)
	if !ok {
		WriteError(w, 401, "unauthorized", "Operator session required")
		return
	}
	m.mu.Lock()
	delete(m.active, id)
	m.mu.Unlock()
	options := *m.cookies.Options
	options.MaxAge = -1
	options.Secure = r.TLS != nil
	s.Options = &options
	s.Values = map[any]any{}
	if err := m.cookies.Save(r, w, s); err != nil {
		WriteError(w, 503, "operator_unavailable", "Operator session unavailable")
		return
	}
	writeJSON(w, struct {
		Authenticated bool `json:"authenticated"`
	}{false})
}
