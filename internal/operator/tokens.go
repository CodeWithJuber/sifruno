package operator

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/time/rate"
)

// API tokens let a program, such as the WHMCS module, call the panel API
// without a browser session. A token has the access an admin session has on
// every route Authorize guards, and none on /api/v1/session/...: it cannot
// sign in, list or end sessions, run setup, or create, list or revoke tokens.
// A token is not a session: no cookie, no CSRF token, no Origin check.
//
// A token is "sfr_" and 43 base64url characters (32 bytes from crypto/rand).
// It appears once, in the create response. tokens.json keeps an HMAC-SHA256
// of it, keyed with tokens.key (32 random bytes beside admins.json). The token
// already carries 256 random bits, so a keyed hash is enough; a slow password
// hash would only slow every API call. tokens.json follows admins.json: 0600,
// at most 64 KiB, written atomically.

const (
	tokensFile       = "tokens.json"
	tokensKeyFile    = "tokens.key"
	maxTokensBytes   = 64 << 10
	maxTokens        = 32
	maxTokenName     = 64 // characters
	tokenPrefix      = "sfr_"
	apiTokenLength   = len(tokenPrefix) + 43
	shownPrefixChars = 6 // of the random part: 36 of its 256 bits, shown in the list
	defaultTokenDays = 90
	maxTokenDays     = 365
	// The last-used time is saved at most once a minute per token, so a busy
	// client does not turn every request into a disk write.
	lastUsedStep = time.Minute
)

var shownPrefixPattern = regexp.MustCompile(`^sfr_[A-Za-z0-9_-]{6}$`)

type tokenRecord struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Hash       string     `json:"hash"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

type tokenFile struct {
	Version int           `json:"version"`
	Tokens  []tokenRecord `json:"tokens"`
}

// APIToken is what the panel shows about a token: never the token or its hash.
type APIToken struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	Expired    bool       `json:"expired"`
}

type TokenList struct {
	Items    []APIToken `json:"items"`
	Capacity int        `json:"capacity"`
}

// CreatedToken is the create response, the only place the token appears.
type CreatedToken struct {
	APIToken
	Token string `json:"token"`
}

func (t tokenRecord) public(now time.Time) APIToken {
	out := APIToken{ID: t.ID, Name: t.Name, Prefix: t.Prefix, CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, Expired: !now.Before(t.ExpiresAt)}
	if t.LastUsedAt != nil {
		used := *t.LastUsedAt
		out.LastUsedAt = &used
	}
	return out
}

// tokenNameProblem returns a sentence for the person naming the token, or ""
// when the name is acceptable. Names are shown in the panel, so control and
// formatting characters (which can reorder text) are refused.
func tokenNameProblem(name string) string {
	switch {
	case !utf8.ValidString(name) || strings.TrimSpace(name) == "":
		return "Give the token a name that says where it is used, such as WHMCS."
	case utf8.RuneCountInString(name) > maxTokenName:
		return "Use a name of at most 64 characters."
	case name != strings.TrimSpace(name):
		return "Remove the spaces at the start and end of the name."
	}
	for _, c := range name {
		if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) {
			return "Remove line breaks, tabs and other invisible characters from the name."
		}
	}
	return ""
}

// Names are unique regardless of case, so the list is never ambiguous.
func tokenNameKey(name string) string { return strings.ToLower(name) }

func (f tokenFile) validate() error {
	if f.Version != 1 || len(f.Tokens) > maxTokens {
		return errors.New("unsupported token file")
	}
	ids, names, hashes := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, t := range f.Tokens {
		hash, err := base64.RawStdEncoding.Strict().DecodeString(t.Hash)
		if !validManagementID(t.ID) || ids[t.ID] || tokenNameProblem(t.Name) != "" || names[tokenNameKey(t.Name)] ||
			!shownPrefixPattern.MatchString(t.Prefix) || err != nil || len(hash) != sha256.Size || hashes[t.Hash] ||
			t.CreatedAt.IsZero() || !t.ExpiresAt.After(t.CreatedAt) || t.ExpiresAt.Sub(t.CreatedAt) > maxTokenDays*24*time.Hour ||
			(t.LastUsedAt != nil && t.LastUsedAt.IsZero()) {
			return errors.New("invalid token record")
		}
		ids[t.ID], names[tokenNameKey(t.Name)], hashes[t.Hash] = true, true, true
	}
	return nil
}

func loadTokens(dir string) (tokenFile, error) {
	var out tokenFile
	found, err := readPrivateJSON(dir, tokensFile, maxTokensBytes, &out)
	if err != nil {
		return tokenFile{}, err
	}
	if !found {
		return tokenFile{Version: 1, Tokens: []tokenRecord{}}, nil
	}
	if err := out.validate(); err != nil {
		return tokenFile{}, err
	}
	return out, nil
}

func saveTokens(dir string, file tokenFile) error {
	if err := file.validate(); err != nil {
		return err
	}
	return writePrivateJSON(dir, tokensFile, maxTokensBytes, file)
}

func (m *Manager) tokenHash(token string) []byte {
	mac := hmac.New(sha256.New, m.tokenKey[:])
	mac.Write([]byte(token))
	return mac.Sum(nil)
}

// validAPIToken checks the shape only: "sfr_" and 43 strict base64url
// characters that decode to 32 bytes.
func validAPIToken(s string) bool {
	return len(s) == apiTokenLength && strings.HasPrefix(s, tokenPrefix) && validToken(s[len(tokenPrefix):])
}

// bearerToken reads exactly one "Authorization: Bearer <token>" header. The
// scheme name is case-insensitive (RFC 9110); anything else is not a token.
func bearerToken(r *http.Request) (string, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	scheme, token, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || !validAPIToken(token) {
		return "", false
	}
	return token, true
}

// sessionOnly keeps API tokens off every /api/v1/session route.
func sessionOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(r.Header.Values("Authorization")) > 0 {
			WriteError(w, 403, "token_not_allowed", "An API token cannot sign in, manage sessions or manage tokens. Sign in to the panel in a browser to do this.")
			return
		}
		next(w, r)
	}
}

// Failed bearer attempts are limited the way sign-ins are, with their own
// limiters, so bad tokens cannot use up sign-in attempts or the reverse. On
// the server: a 20-attempt burst refilling every 3 seconds. Over the network:
// a separate burst of the same size, plus 5 attempts per caller IP refilling
// one a minute, so one outside address cannot lock out the others. Only a
// failure uses an attempt; while a limit is used up, every bearer request
// from that caller waits, valid or not. Called with tokenMu held.
func (m *Manager) bearerLimiters(r *http.Request) (global, peer *rate.Limiter) {
	if !IsRemote(r) {
		return m.bearerLimiter, nil
	}
	addr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		addr = r.RemoteAddr
	}
	mac := hmac.New(sha256.New, m.bucketKey[:])
	mac.Write([]byte("bearer\x00"))
	mac.Write([]byte(addr))
	return m.remoteBearerLimiter, m.remoteBearerBuckets[binary.BigEndian.Uint16(mac.Sum(nil))%remoteLoginBuckets]
}

// authorizeToken admits a request that carries an Authorization header. Every
// wrong, expired or revoked token gets the same answer, so a response does not
// reveal whether a token ever existed.
func (m *Manager) authorizeToken(w http.ResponseWriter, r *http.Request) (string, bool) {
	if _, err := r.Cookie(cookieName); err == nil {
		WriteError(w, 400, "invalid_request", "The request carried both an API token and a panel session cookie. Send only the token: remove the cookie from the API client.")
		return "", false
	}
	// Remote already requires TLS. This keeps tokens off any plain-HTTP
	// listener other than loopback, should one ever be added.
	if !localRequest(r) && r.TLS == nil {
		WriteError(w, 403, "https_required", "API tokens work only over HTTPS or on the server itself. Use the panel's https:// address.")
		return "", false
	}
	m.tokenMu.Lock()
	defer m.tokenMu.Unlock()
	global, peer := m.bearerLimiters(r)
	if (peer != nil && peer.Tokens() < 1) || global.Tokens() < 1 {
		retry := "3"
		if peer != nil && peer.Tokens() < 1 {
			retry = "60"
		}
		w.Header().Set("Retry-After", retry)
		WriteError(w, 429, "rate_limited", "Too many requests with a wrong API token. Wait a minute, check the token in the API client, and try again.")
		return "", false
	}
	now := m.now()
	index := -1
	if token, ok := bearerToken(r); ok {
		sum := m.tokenHash(token)
		// Compare with every record, without stopping at a match.
		for i, t := range m.tokens.Tokens {
			stored, err := base64.RawStdEncoding.Strict().DecodeString(t.Hash)
			if err == nil && subtle.ConstantTimeCompare(sum, stored) == 1 {
				index = i
			}
		}
	}
	if index < 0 || !now.Before(m.tokens.Tokens[index].ExpiresAt) {
		global.Allow()
		if peer != nil {
			peer.Allow()
		}
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		WriteError(w, 401, "invalid_token", "The API token was not accepted. It may be mistyped, expired or revoked. Create a new token under Security, API tokens, and put it in the API client.")
		return "", false
	}
	m.recordTokenUseLocked(index, now)
	return "local-operator", true
}

// recordTokenUseLocked saves the last-used time, at most once a minute per
// token. A failed write does not refuse the request: the token is valid, and
// it must not stop working because a timestamp could not be saved. The new
// time is kept in memory and goes to disk with the next write that succeeds.
func (m *Manager) recordTokenUseLocked(index int, now time.Time) {
	used := now.UTC().Truncate(time.Second)
	if last := m.tokens.Tokens[index].LastUsedAt; last != nil && !used.Before(*last) && used.Sub(*last) < lastUsedStep {
		return
	}
	next := tokenFile{Version: 1, Tokens: append([]tokenRecord(nil), m.tokens.Tokens...)}
	next.Tokens[index].LastUsedAt = &used
	_ = saveTokens(m.dir, next) // see above: the in-memory copy carries the time.
	m.tokens = next
}

// newTokenIDLocked returns a public handle, as for sessions. Called with
// tokenMu held.
func (m *Manager) newTokenIDLocked() (string, error) {
	for attempt := 0; attempt < 4; attempt++ {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		id := hex.EncodeToString(b[:])
		taken := false
		for _, t := range m.tokens.Tokens {
			taken = taken || t.ID == id
		}
		if !taken {
			return id, nil
		}
	}
	return "", errors.New("token handle unavailable")
}

// stillActiveLocked rechecks the session that authorized a change, after the
// body was read (lock order tokenMu, then mu).
func (m *Manager) stillActiveLocked(id string, a activeSession) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.authorizingSessionLocked(id, a)
}

func (m *Manager) listTokens(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := m.managementAuthorization(w, r, false); !ok {
		return
	}
	now := m.now()
	m.tokenMu.Lock()
	out := TokenList{Items: make([]APIToken, 0, len(m.tokens.Tokens)), Capacity: maxTokens}
	for _, t := range m.tokens.Tokens {
		out.Items = append(out.Items, t.public(now))
	}
	m.tokenMu.Unlock()
	sort.Slice(out.Items, func(i, j int) bool {
		if out.Items[i].CreatedAt.Equal(out.Items[j].CreatedAt) {
			return out.Items[i].ID < out.Items[j].ID
		}
		return out.Items[i].CreatedAt.After(out.Items[j].CreatedAt)
	})
	writeJSON(w, out)
}

func (m *Manager) createToken(w http.ResponseWriter, r *http.Request) {
	id, a, ok := m.managementAuthorization(w, r, true)
	if !ok {
		return
	}
	var input struct {
		Name          string `json:"name"`
		ExpiresInDays *int   `json:"expires_in_days"`
	}
	if !decodeJSON(w, r, &input, false) {
		return
	}
	if problem := tokenNameProblem(input.Name); problem != "" {
		WriteError(w, 422, "invalid_token_name", problem)
		return
	}
	days := defaultTokenDays
	if input.ExpiresInDays != nil {
		days = *input.ExpiresInDays
	}
	if days < 1 || days > maxTokenDays {
		WriteError(w, 422, "invalid_expiry", "Choose an expiry from 1 to 365 days. A token cannot last longer than a year.")
		return
	}
	secret, err := randomToken()
	if err != nil {
		WriteError(w, 503, "operator_unavailable", "The token could not be made right now. Try again.")
		return
	}
	token := tokenPrefix + secret
	m.tokenMu.Lock()
	defer m.tokenMu.Unlock()
	if len(m.tokens.Tokens) >= maxTokens {
		WriteError(w, 409, "token_limit", "This panel already has 32 API tokens, the most it keeps. Revoke one you no longer use, then try again.")
		return
	}
	for _, t := range m.tokens.Tokens {
		if tokenNameKey(t.Name) == tokenNameKey(input.Name) {
			WriteError(w, 409, "token_name_taken", "Another token already has this name. Choose a different name.")
			return
		}
	}
	tokenID, err := m.newTokenIDLocked()
	if err != nil {
		WriteError(w, 503, "operator_unavailable", "The token could not be made right now. Try again.")
		return
	}
	created := m.now().UTC().Truncate(time.Second)
	record := tokenRecord{ID: tokenID, Name: input.Name, Prefix: token[:len(tokenPrefix)+shownPrefixChars],
		Hash: base64.RawStdEncoding.EncodeToString(m.tokenHash(token)), CreatedAt: created, ExpiresAt: created.Add(time.Duration(days) * 24 * time.Hour)}
	if !m.stillActiveLocked(id, a) {
		WriteError(w, 401, "unauthorized", "Your session ended before the token was made. Sign in again, then create the token again.")
		return
	}
	next := tokenFile{Version: 1, Tokens: append(append([]tokenRecord(nil), m.tokens.Tokens...), record)}
	if err := saveTokens(m.dir, next); err != nil {
		WriteError(w, 503, "operator_unavailable", "The token could not be saved on the server, so it was not made. Check the panel's disk, then try again.")
		return
	}
	m.tokens = next
	writeJSON(w, CreatedToken{APIToken: record.public(m.now()), Token: token})
}

func (m *Manager) revokeToken(w http.ResponseWriter, r *http.Request) {
	id, a, ok := m.managementAuthorization(w, r, true)
	if !ok {
		return
	}
	var input struct{}
	if !decodeJSON(w, r, &input, false) {
		return
	}
	target := r.PathValue("id")
	if !validManagementID(target) {
		WriteError(w, 400, "invalid_request", "That is not a token ID the panel made. Refresh the token list and try again.")
		return
	}
	m.tokenMu.Lock()
	defer m.tokenMu.Unlock()
	index := -1
	for i, t := range m.tokens.Tokens {
		if t.ID == target {
			index = i
		}
	}
	if index < 0 {
		WriteError(w, 404, "token_not_found", "That token is not on the list. It may have been revoked already. Refresh the token list.")
		return
	}
	if !m.stillActiveLocked(id, a) {
		WriteError(w, 401, "unauthorized", "Your session ended before the token was revoked. Sign in again, then revoke it again.")
		return
	}
	removed := m.tokens.Tokens[index]
	next := tokenFile{Version: 1, Tokens: make([]tokenRecord, 0, len(m.tokens.Tokens)-1)}
	next.Tokens = append(append(next.Tokens, m.tokens.Tokens[:index]...), m.tokens.Tokens[index+1:]...)
	if err := saveTokens(m.dir, next); err != nil {
		WriteError(w, 503, "operator_unavailable", "The token was not revoked: the change could not be saved on the server. Check the panel's disk, then try again.")
		return
	}
	m.tokens = next
	writeJSON(w, removed.public(m.now()))
}
