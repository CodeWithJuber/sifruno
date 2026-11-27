package operator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

const (
	passkeyHost   = "panel.example.com:8443"
	passkeyOrigin = "https://" + passkeyHost
)

// softKey is a passkey held in memory, answering as a browser's toJSON()
// does: an ES256 key, user verification done, discoverable.
type softKey struct {
	t      *testing.T
	id     []byte
	key    *ecdsa.PrivateKey
	handle []byte
	count  uint32
	synced bool
}

func newSoftKey(t *testing.T) *softKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	rand.Read(id)
	return &softKey{t: t, id: id, key: key, synced: true}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (k *softKey) authData(rpID string, attested bool) []byte {
	rp := sha256.Sum256([]byte(rpID))
	flags := byte(0x01 | 0x04) // user present, user verified
	if k.synced {
		flags |= 0x08 | 0x10 // backup eligible, backed up
	}
	out := append([]byte{}, rp[:]...)
	if attested {
		flags |= 0x40
	}
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, k.count)
	if attested {
		x, y := make([]byte, 32), make([]byte, 32)
		k.key.PublicKey.X.FillBytes(x)
		k.key.PublicKey.Y.FillBytes(y)
		cose, err := webauthncbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
		if err != nil {
			k.t.Fatal(err)
		}
		out = append(out, make([]byte, 16)...) // AAGUID
		out = binary.BigEndian.AppendUint16(out, uint16(len(k.id)))
		out = append(out, k.id...)
		out = append(out, cose...)
	}
	return out
}

func clientData(kind, challenge, origin string) []byte {
	b, _ := json.Marshal(map[string]any{"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false})
	return b
}

// create answers navigator.credentials.create() for the options the panel sent.
func (k *softKey) create(options passkeyOptions, origin string) json.RawMessage {
	k.t.Helper()
	handle, err := base64.RawURLEncoding.DecodeString(options.User.ID)
	if err != nil {
		k.t.Fatal(err)
	}
	k.handle = handle
	att, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": k.authData(options.RP.ID, true)})
	if err != nil {
		k.t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"id": b64(k.id), "rawId": b64(k.id), "type": "public-key", "authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{},
		"response": map[string]any{"clientDataJSON": b64(clientData("webauthn.create", options.Challenge, origin)), "attestationObject": b64(att), "transports": []string{"internal"}}})
	return b
}

// get answers navigator.credentials.get() for the challenge the panel sent.
func (k *softKey) get(rpID, challenge, origin string) json.RawMessage {
	k.t.Helper()
	k.count++
	auth := k.authData(rpID, false)
	cd := clientData("webauthn.get", challenge, origin)
	sum := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, auth...), sum[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.key, digest[:])
	if err != nil {
		k.t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"id": b64(k.id), "rawId": b64(k.id), "type": "public-key", "authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{},
		"response": map[string]any{"clientDataJSON": b64(cd), "authenticatorData": b64(auth), "signature": b64(sig), "userHandle": b64(k.handle)}})
	return b
}

type passkeyOptions struct {
	Challenge string `json:"challenge"`
	RPID      string `json:"rpId"`
	RP        struct {
		ID string `json:"id"`
	} `json:"rp"`
	User struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"user"`
	UserVerification       string `json:"userVerification"`
	AuthenticatorSelection struct {
		ResidentKey      string `json:"residentKey"`
		UserVerification string `json:"userVerification"`
	} `json:"authenticatorSelection"`
	ExcludeCredentials []struct {
		ID string `json:"id"`
	} `json:"excludeCredentials"`
	AllowCredentials []any `json:"allowCredentials"`
}

type passkeyFixture struct {
	m      *Manager
	h      http.Handler // remote, through the HTTPS listener
	local  http.Handler
	clock  *customerClock
	secret string
	key    string
}

// passkeyPanel is a panel with an admin, served over HTTPS at its name with a
// trusted certificate.
func passkeyPanel(t *testing.T) passkeyFixture {
	t.Helper()
	m, h, key := fixture(t)
	clock := &customerClock{now: time.Unix(1_800_000_000, 0)}
	m.now = func() time.Time { return clock.now }
	secret, _ := setUpAdmin(t, m, h, key, clock.now)
	m.SetPasskeySites([]string{passkeyOrigin, "https://203.0.113.10:8443"}, func() bool { return true })
	return passkeyFixture{m: m, h: Remote(h, []string{"panel.example.com", "203.0.113.10"}), local: h, clock: clock, secret: secret, key: key}
}

func remoteAt(h http.Handler, host, method, path, body string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://"+host+path, strings.NewReader(body))
	r.RemoteAddr = "198.51.100.7:40000"
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Origin", "https://"+host)
	r.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func (f passkeyFixture) remote(method, path, body string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	return remoteAt(f.h, passkeyHost, method, path, body, cookie, csrf)
}

// code is a fresh authenticator code: each one works once.
func (f passkeyFixture) code(t *testing.T, secret string) string {
	f.clock.now = f.clock.now.Add(30 * time.Second)
	return codeAt(t, secret, f.clock.now)
}

func (f passkeyFixture) signInWithPassword(t *testing.T, username, password, secret string) (*http.Cookie, string) {
	t.Helper()
	w := f.remote("POST", "/api/v1/session/login", adminLoginBody(username, password, f.code(t, secret)), nil, "")
	if w.Code != 200 {
		t.Fatalf("password sign-in: %d %s", w.Code, w.Body.String())
	}
	return w.Result().Cookies()[0], decodeBody[Session](t, w.Body.Bytes()).CSRFToken
}

// addPasskey adds k to the signed-in login and returns the passkey.
func (f passkeyFixture) addPasskey(t *testing.T, k *softKey, cookie *http.Cookie, csrf, password, secret, name string) Passkey {
	t.Helper()
	w := f.remote("POST", "/api/v1/session/passkeys/begin", confirmBody(password, f.code(t, secret)), cookie, csrf)
	if w.Code != 200 {
		t.Fatalf("begin passkey: %d %s", w.Code, w.Body.String())
	}
	creation := decodeBody[struct {
		Options passkeyOptions `json:"options"`
	}](t, w.Body.Bytes())
	if creation.Options.RP.ID != "panel.example.com" || creation.Options.AuthenticatorSelection.ResidentKey != "required" || creation.Options.AuthenticatorSelection.UserVerification != "required" {
		t.Fatalf("creation options: %+v", creation.Options)
	}
	w = f.remote("POST", "/api/v1/session/passkeys/finish", jsonBody(map[string]any{"name": name, "credential": k.create(creation.Options, passkeyOrigin)}), cookie, csrf)
	if w.Code != 200 {
		t.Fatalf("finish passkey: %d %s", w.Code, w.Body.String())
	}
	return decodeBody[Passkey](t, w.Body.Bytes())
}

// passkeySignIn runs a passkey sign-in and returns the finish answer.
func (f passkeyFixture) passkeySignIn(t *testing.T, k *softKey, remember bool) *httptest.ResponseRecorder {
	t.Helper()
	w := f.remote("POST", "/api/v1/session/passkey-login/begin", "{}", nil, "")
	if w.Code != 200 {
		t.Fatalf("begin passkey sign-in: %d %s", w.Code, w.Body.String())
	}
	begun := decodeBody[struct {
		Ceremony string         `json:"ceremony"`
		Options  passkeyOptions `json:"options"`
	}](t, w.Body.Bytes())
	if begun.Options.RPID != "panel.example.com" || begun.Options.UserVerification != "required" || len(begun.Options.AllowCredentials) != 0 {
		t.Fatalf("request options: %+v", begun.Options)
	}
	return f.remote("POST", "/api/v1/session/passkey-login/finish", jsonBody(map[string]any{"ceremony": begun.Ceremony, "credential": k.get(begun.Options.RPID, begun.Options.Challenge, passkeyOrigin), "remember": remember}), nil, "")
}

// refill gives every login its sign-in tries back. The limiters run on real
// time, which the fixed test clock does not move.
func (f passkeyFixture) refill() {
	refillLoginBuckets(f.m)
	f.m.adminMu.Lock()
	defer f.m.adminMu.Unlock()
	for i := range f.m.remoteBuckets {
		f.m.remoteBuckets[i] = newAccountLimiter()
	}
}

func passkeysOf(t *testing.T, f passkeyFixture, cookie *http.Cookie) PasskeyList {
	t.Helper()
	w := f.remote("GET", "/api/v1/session/passkeys", "", cookie, "")
	if w.Code != 200 {
		t.Fatalf("list passkeys: %d %s", w.Code, w.Body.String())
	}
	return decodeBody[PasskeyList](t, w.Body.Bytes())
}

func TestPasskeysWorkOnlyAtThePanelsNameWithATrustedCertificate(t *testing.T) {
	m, h, _ := fixture(t)
	status := func(handler http.Handler, host string, local bool) PasskeyStatus {
		var w *httptest.ResponseRecorder
		if local {
			w = opRequest(handler, "GET", "/api/v1/session/passkey-login", "", nil, "")
		} else {
			w = remoteAt(handler, host, "GET", "/api/v1/session/passkey-login", "", nil, "")
		}
		if w.Code != 200 {
			t.Fatalf("status at %s: %d %s", host, w.Code, w.Body.String())
		}
		return decodeBody[PasskeyStatus](t, w.Body.Bytes())
	}
	remote := Remote(h, []string{"panel.example.com", "203.0.113.10"})
	if s := status(remote, passkeyHost, false); s.Available || !strings.Contains(s.Detail, "--panel-host") {
		t.Fatalf("without a panel name: %+v", s)
	}
	trusted := false
	m.SetPasskeySites([]string{passkeyOrigin, "https://203.0.113.10:8443"}, func() bool { return trusted })
	if s := status(h, "", true); s.Available || !strings.Contains(s.Detail, "Passkeys need the panel's name") || s.Address != passkeyOrigin {
		t.Fatalf("on the server itself: %+v", s)
	}
	if s := status(remote, "203.0.113.10:8443", false); s.Available || !strings.Contains(s.Detail, "Passkeys need the panel's name") || !strings.Contains(s.Detail, passkeyOrigin) {
		t.Fatalf("by IP address: %+v", s)
	}
	if s := status(remote, passkeyHost, false); s.Available || !strings.Contains(s.Detail, "certificate") {
		t.Fatalf("before the certificate is trusted: %+v", s)
	}
	trusted = true
	if s := status(remote, passkeyHost, false); !s.Available || s.Detail != "" {
		t.Fatalf("at the name with a trusted certificate: %+v", s)
	}
	// Where passkeys are off, their routes say so and do nothing.
	if w := remoteAt(remote, "203.0.113.10:8443", "POST", "/api/v1/session/passkey-login/begin", "{}", nil, ""); w.Code != 409 || problemCode(t, w.Body.Bytes()) != "passkeys_unavailable" {
		t.Fatalf("begin by IP: %d %s", w.Code, w.Body.String())
	}
	if w := opRequest(h, "POST", "/api/v1/session/passkey-login/begin", "{}", nil, ""); w.Code != 409 {
		t.Fatalf("begin on loopback: %d", w.Code)
	}
}

func TestAdminAddsAPasskeyAndSignsInWithItAlone(t *testing.T) {
	f := passkeyPanel(t)
	cookie, csrf := f.signInWithPassword(t, "admin", setupWords, f.secret)
	if l := passkeysOf(t, f, cookie); len(l.Items) != 0 || l.Capacity != 10 || !l.Available || l.UserID != "" {
		t.Fatalf("before: %+v", l)
	}
	k := newSoftKey(t)
	added := f.addPasskey(t, k, cookie, csrf, setupWords, f.secret, "Laptop")
	if added.Name != "Laptop" || added.CredentialID != b64(k.id) || !added.Synced || added.LastUsedAt != nil {
		t.Fatalf("added: %+v", added)
	}
	l := passkeysOf(t, f, cookie)
	if len(l.Items) != 1 || l.RPID != "panel.example.com" || l.UserID != b64(k.handle) || l.Items[0].ID != added.ID {
		t.Fatalf("list: %+v", l)
	}
	// Kept in admins.json, never the private key, and through a restart.
	raw, _ := os.ReadFile(filepath.Join(f.m.dir, adminsFile))
	if !strings.Contains(string(raw), b64(k.id)) || !strings.Contains(string(raw), `"passkey_user"`) {
		t.Fatal("the passkey is not in admins.json")
	}

	if w := f.remote("POST", "/api/v1/session/logout", "{}", cookie, csrf); w.Code != 200 {
		t.Fatal(w.Code)
	}
	w := f.passkeySignIn(t, k, true)
	if w.Code != 200 {
		t.Fatalf("passkey sign-in: %d %s", w.Code, w.Body.String())
	}
	s := decodeBody[Session](t, w.Body.Bytes())
	if s.Username != "admin" || s.Role != "admin" || !s.KeptSignedIn || w.Result().Cookies()[0].MaxAge != int(keptMax.Seconds()) {
		t.Fatalf("passkey session: %+v", s)
	}
	pkCookie := w.Result().Cookies()[0]
	if l := passkeysOf(t, f, pkCookie); l.Items[0].LastUsedAt == nil {
		t.Fatal("last use not recorded")
	}
	// The passkey session survives a restart like a password one.
	if err := f.m.Close(); err != nil {
		t.Fatal(err)
	}
	m2, err := Open(filepath.Dir(f.m.AccessKeyPath()))
	if err != nil {
		t.Fatal(err)
	}
	m2.now = f.m.now
	m2.SetPasskeySites([]string{passkeyOrigin}, func() bool { return true })
	mux := http.NewServeMux()
	m2.Register(mux)
	if w := remoteAt(Remote(mux, []string{"panel.example.com"}), passkeyHost, "GET", "/api/v1/session", "", pkCookie, ""); w.Code != 200 {
		t.Fatalf("passkey session after a restart: %d", w.Code)
	}
}

func TestPasskeySignInRefusesWhatItShould(t *testing.T) {
	f := passkeyPanel(t)
	cookie, csrf := f.signInWithPassword(t, "admin", setupWords, f.secret)
	k := newSoftKey(t)
	f.addPasskey(t, k, cookie, csrf, setupWords, f.secret, "Phone")

	// A ceremony works once.
	w := f.remote("POST", "/api/v1/session/passkey-login/begin", "{}", nil, "")
	begun := decodeBody[struct {
		Ceremony string         `json:"ceremony"`
		Options  passkeyOptions `json:"options"`
	}](t, w.Body.Bytes())
	answer := k.get(begun.Options.RPID, begun.Options.Challenge, passkeyOrigin)
	body := jsonBody(map[string]any{"ceremony": begun.Ceremony, "credential": answer})
	if w := f.remote("POST", "/api/v1/session/passkey-login/finish", body, nil, ""); w.Code != 200 {
		t.Fatalf("first use: %d %s", w.Code, w.Body.String())
	}
	if w := f.remote("POST", "/api/v1/session/passkey-login/finish", body, nil, ""); w.Code != 409 || problemCode(t, w.Body.Bytes()) != "passkey_expired" {
		t.Fatalf("replayed ceremony: %d %s", w.Code, w.Body.String())
	}
	// An old answer does not fit a new ceremony.
	w = f.remote("POST", "/api/v1/session/passkey-login/begin", "{}", nil, "")
	fresh := decodeBody[struct {
		Ceremony string `json:"ceremony"`
	}](t, w.Body.Bytes())
	if w := f.remote("POST", "/api/v1/session/passkey-login/finish", jsonBody(map[string]any{"ceremony": fresh.Ceremony, "credential": answer}), nil, ""); w.Code != 401 || problemCode(t, w.Body.Bytes()) != "invalid_credentials" {
		t.Fatalf("old answer, new ceremony: %d %s", w.Code, w.Body.String())
	}
	// Another origin's answer, and a passkey the panel does not have.
	w = f.remote("POST", "/api/v1/session/passkey-login/begin", "{}", nil, "")
	other := decodeBody[struct {
		Ceremony string         `json:"ceremony"`
		Options  passkeyOptions `json:"options"`
	}](t, w.Body.Bytes())
	if w := f.remote("POST", "/api/v1/session/passkey-login/finish", jsonBody(map[string]any{"ceremony": other.Ceremony, "credential": k.get(other.Options.RPID, other.Options.Challenge, "https://evil.example")}), nil, ""); w.Code != 401 {
		t.Fatalf("answer for another origin: %d %s", w.Code, w.Body.String())
	}
	f.refill()
	stranger := newSoftKey(t)
	stranger.handle = k.handle
	if w := f.passkeySignIn(t, stranger, false); w.Code != 404 || problemCode(t, w.Body.Bytes()) != "passkey_unknown" {
		t.Fatalf("unknown passkey: %d %s", w.Code, w.Body.String())
	}
	// A use count that goes back blocks the passkey.
	k.count -= 2
	if w := f.passkeySignIn(t, k, false); w.Code != 401 || problemCode(t, w.Body.Bytes()) != "passkey_blocked" {
		t.Fatalf("count went back: %d %s", w.Code, w.Body.String())
	}
	k.count += 10
	if w := f.passkeySignIn(t, k, false); w.Code != 401 || problemCode(t, w.Body.Bytes()) != "passkey_blocked" {
		t.Fatalf("a blocked passkey signed in: %d %s", w.Code, w.Body.String())
	}
	if l := passkeysOf(t, f, cookie); !l.Items[0].Blocked {
		t.Fatal("the blocked passkey is not shown as blocked")
	}
	// Every try counts against the login's sign-in limit.
	f.refill()
	for i := 0; i < 5; i++ {
		f.passkeySignIn(t, k, false)
	}
	if w := f.passkeySignIn(t, k, false); w.Code != 429 {
		t.Fatalf("sixth try: %d", w.Code)
	}
}

func TestAddingAndRemovingPasskeysNeedsTheOwnLogin(t *testing.T) {
	f := passkeyPanel(t)
	cookie, csrf := f.signInWithPassword(t, "admin", setupWords, f.secret)

	// Adding needs the current password and a current code, with one answer
	// for either being wrong.
	wrongPassword := f.remote("POST", "/api/v1/session/passkeys/begin", confirmBody("not the password at all", f.code(t, f.secret)), cookie, csrf)
	wrongCode := f.remote("POST", "/api/v1/session/passkeys/begin", confirmBody(setupWords, "000000"), cookie, csrf)
	if wrongPassword.Code != 422 || wrongCode.Code != 422 || wrongPassword.Body.String() != wrongCode.Body.String() {
		t.Fatalf("wrong password %d, wrong code %d", wrongPassword.Code, wrongCode.Code)
	}
	if w := f.remote("POST", "/api/v1/session/passkeys/begin", confirmBody(setupWords, f.code(t, f.secret)), cookie, ""); w.Code != 403 {
		t.Fatalf("without CSRF: %d", w.Code)
	}
	if w := bearer(f.local, "POST", "/api/v1/session/passkeys/begin", "sfr_"+strings.Repeat("A", 43)); w.Code != 403 || problemCode(t, w.Body.Bytes()) != "token_not_allowed" {
		t.Fatalf("API token: %d", w.Code)
	}
	keyCookie, keySession := signIn(t, f.local, f.key, nil)
	if w := opRequest(f.local, "POST", "/api/v1/session/passkeys/begin", confirmBody(setupWords, f.code(t, f.secret)), keyCookie, keySession.CSRFToken); w.Code != 403 || problemCode(t, w.Body.Bytes()) != "admin_sign_in_required" {
		t.Fatalf("access key: %d %s", w.Code, w.Body.String())
	}
	if w := opRequest(f.local, "GET", "/api/v1/session/passkeys", "", keyCookie, ""); w.Code != 403 {
		t.Fatalf("access key list: %d", w.Code)
	}

	// A name is needed, and the step works once, for 5 minutes.
	w := f.remote("POST", "/api/v1/session/passkeys/begin", confirmBody(setupWords, f.code(t, f.secret)), cookie, csrf)
	options := decodeBody[struct {
		Options passkeyOptions `json:"options"`
	}](t, w.Body.Bytes()).Options
	k := newSoftKey(t)
	for _, name := range []string{"", "   ", strings.Repeat("x", 65), "tab\there"} {
		if w := f.remote("POST", "/api/v1/session/passkeys/finish", jsonBody(map[string]any{"name": name, "credential": k.create(options, passkeyOrigin)}), cookie, csrf); w.Code != 422 || problemCode(t, w.Body.Bytes()) != "invalid_name" {
			t.Fatalf("name %q: %d", name, w.Code)
		}
	}
	f.clock.now = f.clock.now.Add(passkeyLifetime)
	w = f.remote("POST", "/api/v1/session/passkeys/begin", confirmBody(setupWords, f.code(t, f.secret)), cookie, csrf)
	options = decodeBody[struct {
		Options passkeyOptions `json:"options"`
	}](t, w.Body.Bytes()).Options
	f.clock.now = f.clock.now.Add(passkeyLifetime)
	if w := f.remote("POST", "/api/v1/session/passkeys/finish", jsonBody(map[string]any{"name": "Late", "credential": k.create(options, passkeyOrigin)}), cookie, csrf); w.Code != 409 || problemCode(t, w.Body.Bytes()) != "passkey_expired" {
		t.Fatalf("after 5 minutes: %d %s", w.Code, w.Body.String())
	}

	// At most 10, each once; the options exclude the ones the login has.
	keys := []*softKey{}
	for i := 0; i < maxPasskeys; i++ {
		f.refill()
		k := newSoftKey(t)
		f.addPasskey(t, k, cookie, csrf, setupWords, f.secret, "Key "+string(rune('A'+i)))
		keys = append(keys, k)
	}
	if w := f.remote("POST", "/api/v1/session/passkeys/begin", confirmBody(setupWords, f.code(t, f.secret)), cookie, csrf); w.Code != 409 || problemCode(t, w.Body.Bytes()) != "passkey_limit" {
		t.Fatalf("eleventh: %d %s", w.Code, w.Body.String())
	}
	// Removing one answers the rest; then it no longer signs in.
	l := passkeysOf(t, f, cookie)
	w = f.remote("POST", "/api/v1/session/passkeys/"+l.Items[0].ID+"/remove", "{}", cookie, csrf)
	if w.Code != 200 || len(decodeBody[PasskeyList](t, w.Body.Bytes()).Items) != maxPasskeys-1 {
		t.Fatalf("remove: %d %s", w.Code, w.Body.String())
	}
	if w := f.remote("POST", "/api/v1/session/passkeys/"+l.Items[0].ID+"/remove", "{}", cookie, csrf); w.Code != 404 {
		t.Fatalf("remove again: %d", w.Code)
	}
	if w := f.passkeySignIn(t, keys[0], false); w.Code != 404 {
		t.Fatalf("removed passkey: %d %s", w.Code, w.Body.String())
	}
	if w := f.remote("POST", "/api/v1/session/passkeys/"+l.Items[1].ID+"/remove", "{}", cookie, ""); w.Code != 403 {
		t.Fatalf("remove without CSRF: %d", w.Code)
	}
	// A password change keeps them.
	w = f.remote("POST", passwordPath, changeBody(setupWords, f.code(t, f.secret), "a brand new long password"), cookie, csrf)
	if w.Code != 200 {
		t.Fatalf("password change: %d %s", w.Code, w.Body.String())
	}
	if w := f.passkeySignIn(t, keys[1], false); w.Code != 200 {
		t.Fatalf("passkey after a password change: %d %s", w.Code, w.Body.String())
	}
}

func TestCustomerPasskeysFollowItsLogin(t *testing.T) {
	f := passkeyPanel(t)
	adminCookie, adminCSRF := f.signInWithPassword(t, "admin", setupWords, f.secret)
	created := decodeBody[CustomerSetupLink](t, f.remote("POST", "/api/v1/session/customers", jsonBody(map[string]any{"username": "alice", "websites": []string{siteA}}), adminCookie, adminCSRF).Body.Bytes())
	secret, _, _ := setUpCustomer(t, f.local, linkToken(t, created.SetupLink), f.clock.now)
	cookie, csrf := f.signInWithPassword(t, "alice", customerPassword, secret)
	k := newSoftKey(t)
	f.addPasskey(t, k, cookie, csrf, customerPassword, secret, "Alice's phone")
	w := f.passkeySignIn(t, k, false)
	if w.Code != 200 {
		t.Fatalf("customer passkey sign-in: %d %s", w.Code, w.Body.String())
	}
	if s := decodeBody[Session](t, w.Body.Bytes()); s.Role != "customer" || s.Username != "alice" {
		t.Fatalf("customer passkey session: %+v", s)
	}
	// An admin viewing as the customer cannot add or remove its passkeys,
	// nor see them.
	if w := f.remote("POST", "/api/v1/session/view-as", `{"username":"alice"}`, adminCookie, adminCSRF); w.Code != 200 {
		t.Fatal(w.Code)
	}
	l := passkeysOf(t, f, cookie)
	for _, req := range []struct{ method, path, body string }{
		{"GET", "/api/v1/session/passkeys", ""},
		{"POST", "/api/v1/session/passkeys/begin", confirmBody(setupWords, "123456")},
		{"POST", "/api/v1/session/passkeys/" + l.Items[0].ID + "/remove", "{}"},
	} {
		if w := f.remote(req.method, req.path, req.body, adminCookie, adminCSRF); w.Code != 403 || problemCode(t, w.Body.Bytes()) != "viewing_as_customer" {
			t.Fatalf("%s while viewing: %d %s", req.path, w.Code, w.Body.String())
		}
	}
	f.remote("POST", "/api/v1/session/view-as/end", "{}", adminCookie, adminCSRF)

	// Turned off, its passkeys do not sign in; turned on, they do again.
	f.remote("POST", "/api/v1/session/customers/alice/state", `{"disabled":true}`, adminCookie, adminCSRF)
	if w := f.passkeySignIn(t, k, false); w.Code != 404 {
		t.Fatalf("passkey of a turned-off login: %d %s", w.Code, w.Body.String())
	}
	f.remote("POST", "/api/v1/session/customers/alice/state", `{"disabled":false}`, adminCookie, adminCSRF)
	if w := f.passkeySignIn(t, k, false); w.Code != 200 {
		t.Fatalf("passkey after turning on: %d %s", w.Code, w.Body.String())
	}
	// A new setup link removes them.
	w = f.remote("POST", "/api/v1/session/customers/alice/setup-link", "{}", adminCookie, adminCSRF)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if c, _ := f.m.customers.Load().find("alice"); len(f.m.customers.Load().Customers[c].Passkeys) != 0 || f.m.customers.Load().Customers[c].PasskeyUser != "" {
		t.Fatal("a new setup link left the passkeys")
	}
	f.clock.now = f.clock.now.Add(time.Minute)
	setUpCustomer(t, f.local, linkToken(t, decodeBody[CustomerSetupLink](t, w.Body.Bytes()).SetupLink), f.clock.now)
	if w := f.passkeySignIn(t, k, false); w.Code != 404 {
		t.Fatalf("passkey after a new setup link: %d %s", w.Code, w.Body.String())
	}
}

func TestStoredPasskeysAreChecked(t *testing.T) {
	good := loginPasskeys{PasskeyUser: strings.Repeat("A", 43), Passkeys: []passkeyRecord{{ID: "AQID", PublicKey: "AQID", Name: "Phone", CreatedAt: time.Unix(1, 0)}}}
	if good.validate(map[string]bool{}) != nil {
		t.Fatal("a good login refused")
	}
	for name, bad := range map[string]func(*loginPasskeys){
		"no handle":     func(l *loginPasskeys) { l.PasskeyUser = "" },
		"bad handle":    func(l *loginPasskeys) { l.PasskeyUser = "short" },
		"bad id":        func(l *loginPasskeys) { l.Passkeys[0].ID = "A+/=" },
		"long id":       func(l *loginPasskeys) { l.Passkeys[0].ID = b64(make([]byte, 1024)) },
		"no key":        func(l *loginPasskeys) { l.Passkeys[0].PublicKey = "" },
		"no name":       func(l *loginPasskeys) { l.Passkeys[0].Name = "" },
		"no time":       func(l *loginPasskeys) { l.Passkeys[0].CreatedAt = time.Time{} },
		"backup flags":  func(l *loginPasskeys) { l.Passkeys[0].BackupState = true },
		"twice":         func(l *loginPasskeys) { l.Passkeys = append(l.Passkeys, l.Passkeys[0]) },
		"more than ten": func(l *loginPasskeys) { l.Passkeys = make([]passkeyRecord, 11) },
	} {
		l := good.clone()
		bad(&l)
		if l.validate(map[string]bool{}) == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// One handle or ID in two logins is refused.
	seen := map[string]bool{}
	if good.validate(seen) != nil || good.validate(seen) == nil {
		t.Fatal("a passkey shared by two logins was accepted")
	}
}
