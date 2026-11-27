package whmsource_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sifruno/internal/cpsource"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/whmsource"
	"sifruno/internal/whmsource/whmtest"
)

const keyID = "0123456789abcdef0123456789abcdef"

var keyLine = "restrict ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureFixtureFixtureFixtureFixtureFixtureFix sifruno-migration-" + keyID

func TestParseAddress(t *testing.T) {
	for in, want := range map[string]whmsource.Address{
		"server1.example.com":                                  {Host: "server1.example.com", Port: 2087},
		"server1.example.com:2083":                             {Host: "server1.example.com", Port: 2083},
		"https://server1.example.com:2087":                     {Host: "server1.example.com", Port: 2087},
		" https://203.0.113.9:2087/cpsess0123456789/scripts/ ": {Host: "203.0.113.9", Port: 2087},
	} {
		got, err := whmsource.ParseAddress(in)
		if err != nil || got != want {
			t.Errorf("%q: %+v %v", in, got, err)
		}
	}
	for _, in := range []string{"", "http://server1.example.com:2087", "https://root:pw@server1.example.com:2087", "https://[2001:db8::1]:2087", "https://169.254.169.254:2087",
		"https://0.0.0.0:2087", "https://224.0.0.1", "server1", "Server1.Example.com", "https://server1.example.com:0", "https://server1.example.com:99999", "ftp://server1.example.com", "server one.example.com"} {
		if got, err := whmsource.ParseAddress(in); !errors.Is(err, whmsource.ErrAddress) {
			t.Errorf("%q was accepted: %+v", in, got)
		}
	}
}

func TestLoginIsNeverShown(t *testing.T) {
	l := whmsource.Login{Token: "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"}
	raw, _ := json.Marshal(struct{ L whmsource.Login }{l})
	for _, s := range []string{fmt.Sprint(l), fmt.Sprintf("%+v %#v %s %q", l, l, l, l), string(raw)} {
		if strings.Contains(s, l.Token) {
			t.Fatalf("the token is shown: %s", s)
		}
	}
	for _, bad := range []whmsource.Login{{}, {Token: "short"}, {Token: "has space in it 0123456789"}, {Password: "a\nb"}, {Token: l.Token, Password: "both"}} {
		if bad.Valid() {
			t.Errorf("%#v is valid", bad.Token+"/"+bad.Password)
		}
	}
	if !(whmsource.Login{Password: "correct horse: battery"}).Valid() {
		t.Error("a password with a colon is refused")
	}
}

func step(err error) string {
	var failed *hostaccounts.MigrationError
	if errors.As(err, &failed) {
		return failed.Step
	}
	return ""
}

// A self-signed certificate is read without sending the login, and is
// used only once it is pinned by its fingerprint.
func TestSelfSignedCertificateMustBePinned(t *testing.T) {
	whm := whmtest.New()
	defer whm.Close()
	ctx := context.Background()
	cert, err := whmsource.Probe(ctx, whm.Address())
	if err != nil || cert.Trusted || cert.Fingerprint != whm.Fingerprint() || !whmsource.ValidFingerprint(cert.Fingerprint) {
		t.Fatalf("probe: %+v %v", cert, err)
	}
	if len(whm.Headers()) != 0 {
		t.Fatalf("the probe sent a request: %q", whm.Headers())
	}
	c, err := whmsource.New(whm.Address(), whmsource.Login{Token: whm.Token}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Accounts(ctx); step(err) != "whm_tls" {
		t.Fatalf("an unpinned self-signed certificate: %v", err)
	}
	if len(whm.Headers()) != 0 {
		t.Fatal("the login went to an untrusted certificate")
	}
	other := strings.Repeat("AB:", 31) + "AB"
	if c, _ = whmsource.New(whm.Address(), whmsource.Login{Token: whm.Token}, other); c != nil {
		if _, err = c.Accounts(ctx); step(err) != "whm_tls" || !strings.Contains(err.(*hostaccounts.MigrationError).Detail, "another certificate") {
			t.Fatalf("another pinned certificate: %v", err)
		}
	}
	if len(whm.Headers()) != 0 {
		t.Fatal("the login went to a certificate other than the pinned one")
	}
	c, _ = whmsource.New(whm.Address(), whmsource.Login{Token: whm.Token}, whm.Fingerprint())
	accounts, err := c.Accounts(ctx)
	if err != nil || len(accounts) != 1 || accounts[0].User != whmtest.User || accounts[0].DiskUsedMiB != 40 {
		t.Fatalf("pinned: %+v %v", accounts, err)
	}
	if h := whm.Headers(); len(h) != 1 || h[0] != "whm root:"+whm.Token {
		t.Fatalf("the token header: %q", h)
	}
}

func client(t *testing.T, whm *whmtest.Server, login whmsource.Login) *whmsource.Client {
	t.Helper()
	c, err := whmsource.New(whm.Address(), login, whm.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLoginFailureAndPassword(t *testing.T) {
	whm := whmtest.New()
	defer whm.Close()
	ctx := context.Background()
	_, err := client(t, whm, whmsource.Login{Token: "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"}).Accounts(ctx)
	var failed *hostaccounts.MigrationError
	if !errors.As(err, &failed) || failed.Step != "whm_login" || strings.Contains(failed.Detail+failed.Output, "ZZZZZZZZ") {
		t.Fatalf("a wrong token: %+v", err)
	}
	if _, err = client(t, whm, whmsource.Login{Password: "wrong"}).Accounts(ctx); step(err) != "whm_login" {
		t.Fatalf("a wrong password: %v", err)
	}
	if _, err = client(t, whm, whmsource.Login{Password: whm.Password}).Accounts(ctx); err != nil {
		t.Fatalf("root's password: %v", err)
	}
	whm.Failing["listaccts"] = "Access denied"
	if _, err = client(t, whm, whmsource.Login{Token: whm.Token}).Accounts(ctx); step(err) != "whm_login" {
		t.Fatalf("a reason of access denied: %v", err)
	}
}

// What the owner's server printed in place of JSON is named as such, and
// kept for Technical details only.
func TestNonJSONAnswer(t *testing.T) {
	whm := whmtest.New()
	defer whm.Close()
	whm.Broken = "2026/01/02 03:04:05 LD_Preload detected, refusing to run\n"
	_, err := client(t, whm, whmsource.Login{Token: whm.Token}).Accounts(context.Background())
	var failed *hostaccounts.MigrationError
	if !errors.As(err, &failed) || failed.Step != "whm_output" || strings.Contains(failed.Detail, "LD_Preload") || !strings.Contains(failed.Output, "LD_Preload detect") {
		t.Fatalf("%+v", err)
	}
}

// The key is imported and authorized with "restrict", and removed with a
// check that WHM no longer lists it authorized.
func TestKeyCalls(t *testing.T) {
	whm := whmtest.New()
	defer whm.Close()
	ctx := context.Background()
	c := client(t, whm, whmsource.Login{Token: whm.Token})
	if err := c.AuthorizeKey(ctx, "ssh-ed25519 AAAA someone-else", keyID); !errors.Is(err, hostaccounts.ErrInvalid) {
		t.Fatalf("another key line: %v", err)
	}
	if err := c.AuthorizeKey(ctx, keyLine, keyID); err != nil {
		t.Fatal(err)
	}
	text := strings.TrimPrefix(keyLine, "restrict ")
	if ok, options := whm.Authorized(text); !ok || options != "restrict" {
		t.Fatalf("authorized %v with %q", ok, options)
	}
	if calls := whm.CallList(); strings.Join(calls, ",") != "importsshkey,authorizesshkey" {
		t.Fatalf("calls: %q", calls)
	}
	removed, err := c.RemoveKey(ctx, keyLine, keyID)
	if err != nil || !removed {
		t.Fatalf("remove: %v %v", removed, err)
	}
	if ok, _ := whm.Authorized(text); ok {
		t.Fatal("the key is still authorized")
	}
	// A WHM that keeps the key says so: it is not reported gone.
	if err = c.AuthorizeKey(ctx, keyLine, keyID); err != nil {
		t.Fatal(err)
	}
	whm.Failing["authorizesshkey"], whm.Failing["deletesshkey"] = "Locked", "Locked"
	if removed, err = c.RemoveKey(ctx, keyLine, keyID); removed || step(err) != "whm_failed" {
		t.Fatalf("a key WHM kept: %v %v", removed, err)
	}
}

// The copy's answers have the shapes the broker's parsers read.
func TestAnswersParseAsOverSSH(t *testing.T) {
	whm := whmtest.New()
	defer whm.Close()
	a, err := client(t, whm, whmsource.Login{Token: whm.Token}).Answers(context.Background(), whmtest.User)
	if err != nil {
		t.Fatal(err)
	}
	if items, err := cpsource.ParseAccounts(a.Accounts); err != nil || len(items) != 1 || items[0].Domain != whmtest.Domain {
		t.Fatalf("accounts: %+v %v", items, err)
	}
	if site, err := cpsource.ParseSite(a.Site, whmtest.User, whmtest.Domain); err != nil || !site.WWW {
		t.Fatalf("site: %+v %v", site, err)
	}
	if php, err := cpsource.ParseVhostPHP(a.PHP, whmtest.User, whmtest.Domain); err != nil || php != "ea-php82" || strings.Contains(string(a.PHP), "other.example.test") {
		t.Fatalf("php: %q %v %s", php, err, a.PHP)
	}
	if dbs, err := cpsource.ParseDatabases(a.Databases, whmtest.User); err != nil || len(dbs) != 1 {
		t.Fatalf("databases: %+v %v", dbs, err)
	}
	if users, err := cpsource.ParseDatabaseUsers(a.DatabaseUsers, whmtest.User); err != nil || len(users) != 1 {
		t.Fatalf("users: %+v %v", users, err)
	}
}

// A redirect is not followed: the login goes nowhere else.
func TestRedirectIsNotFollowed(t *testing.T) {
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the redirect was followed with %q", r.Header.Get("Authorization"))
	}))
	defer elsewhere.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusFound)
	}))
	defer redirect.Close()
	whm := whmtest.New()
	defer whm.Close()
	host := strings.TrimPrefix(redirect.URL, "https://")
	a, err := whmsource.ParseAddress(host)
	if err != nil {
		t.Fatal(err)
	}
	c, err := whmsource.New(a, whmsource.Login{Token: whm.Token}, whmsource.Fingerprint(redirect.Certificate().Raw))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Accounts(context.Background()); step(err) != "whm_output" {
		t.Fatalf("a redirect: %v", err)
	}
}

func TestUnreachable(t *testing.T) {
	whm := whmtest.New()
	a := whm.Address()
	whm.Close()
	if _, err := whmsource.Probe(context.Background(), a); step(err) != "whm_unreachable" {
		t.Fatalf("probe: %v", err)
	}
}
