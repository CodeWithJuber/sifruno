package acme

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestRefreshAsksForTheAliasesThatReachHere: one certificate names the
// site's domain and the aliases that reach this server; the others wait for
// their DNS and are recorded as waiting.
func TestRefreshAsksForTheAliasesThatReachHere(t *testing.T) {
	f := newManagerFixture(t)
	id := strings.Repeat("b", 32)
	f.issuer.unreachable = map[string]bool{"nodns.example.com": true}
	site := Site{AccountID: id, Domain: "example.com", Aliases: []string{"shop.example.com", "nodns.example.com", "www.example.com"}, Revision: 4, Active: true}
	if err := f.m.Refresh(context.Background(), site); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.issuer.domains, []string{"example.com,shop.example.com,www.example.com"}) {
		t.Fatalf("asked for %q", f.issuer.domains)
	}
	if !slices.Equal(f.installer.calls, []string{id + " rev=4 chain example.com,shop.example.com,www.example.com"}) {
		t.Fatalf("installed %q", f.installer.calls)
	}
	if got := f.m.Waiting(id); !slices.Equal(got, []string{"nodns.example.com"}) {
		t.Fatalf("waiting %q", got)
	}
	// The installed certificate names those: nothing to do until the
	// waiting alias reaches this server.
	site.Covered, site.NotAfter, site.Revision = []string{"example.com", "shop.example.com", "www.example.com"}, f.installer.notAfter, 5
	f.issuer.domains = nil
	if err := f.m.Refresh(context.Background(), site); err != nil || len(f.issuer.domains) != 0 {
		t.Fatalf("an up-to-date certificate was asked for again: %v %q", err, f.issuer.domains)
	}
	delete(f.issuer.unreachable, "nodns.example.com")
	if err := f.m.Refresh(context.Background(), site); err != nil || !slices.Equal(f.issuer.domains, []string{"example.com,shop.example.com,nodns.example.com,www.example.com"}) {
		t.Fatalf("a newly reachable alias: %v %q", err, f.issuer.domains)
	}
	if got := f.m.Waiting(id); len(got) != 0 {
		t.Fatalf("still waiting %q", got)
	}
	// An alias removed from the site leaves the certificate.
	site.Aliases, site.Covered = []string{"www.example.com"}, []string{"example.com", "nodns.example.com", "shop.example.com", "www.example.com"}
	f.issuer.domains = nil
	if err := f.m.Refresh(context.Background(), site); err != nil || !slices.Equal(f.issuer.domains, []string{"example.com,www.example.com"}) {
		t.Fatalf("a removed alias: %v %q", err, f.issuer.domains)
	}
	// A suspended site is left alone.
	site.Active = false
	f.issuer.domains = nil
	if err := f.m.Refresh(context.Background(), site); err != nil || len(f.issuer.domains) != 0 {
		t.Fatalf("a suspended site: %v %q", err, f.issuer.domains)
	}
}

// TestRefreshIgnoresTheRetryWait: a person changed the site, so a refreshed
// site is asked for even a day after a refused install.
func TestRefreshIgnoresTheRetryWait(t *testing.T) {
	f := newManagerFixture(t)
	id := strings.Repeat("c", 32)
	f.m.records.change(id, func(r *record) {
		r.Domain, r.LastAttempt, r.LastResult = "example.com", f.now.Add(-24*time.Hour), ErrInstall.Error()
	})
	site := Site{AccountID: id, Domain: "example.com", Aliases: []string{"www.example.com"}, Covered: []string{"example.com"}, NotAfter: f.now.Add(60 * 24 * time.Hour), Revision: 2, Active: true}
	if err := f.m.Refresh(context.Background(), site); err != nil || !slices.Equal(f.issuer.domains, []string{"example.com,www.example.com"}) {
		t.Fatalf("refresh: %v %q", err, f.issuer.domains)
	}
	// The renewal loop still waits the week.
	f.issuer.domains = nil
	f.m.records.change(id, func(r *record) { r.LastAttempt, r.LastResult = f.now.Add(-24*time.Hour), ErrInstall.Error() })
	f.sites.sites = []Site{site}
	f.m.check(context.Background())
	if len(f.issuer.domains) != 0 {
		t.Fatalf("the loop tried a refused install again after a day: %q", f.issuer.domains)
	}
}

// TestRenewalCheckFollowsTheAliases: the loop also looks at a site whose
// certificate is not due when its aliases may change what it should name.
func TestRenewalCheckFollowsTheAliases(t *testing.T) {
	f := newManagerFixture(t)
	day := 24 * time.Hour
	fresh, waiting, plain := strings.Repeat("d", 32), strings.Repeat("e", 32), strings.Repeat("f", 32)
	for _, id := range []string{fresh, waiting, plain} {
		f.m.records.change(id, func(r *record) { r.LastAttempt, r.NotAfter = f.now.Add(-30*day), f.now.Add(60*day) })
	}
	f.issuer.unreachable = map[string]bool{"later.waiting.example": true}
	f.sites.sites = []Site{
		// An alias that now reaches this server: a new certificate.
		{AccountID: fresh, Domain: "fresh.example", Aliases: []string{"www.fresh.example"}, Covered: []string{"fresh.example"}, NotAfter: f.now.Add(60 * day), Revision: 3, Active: true},
		// An alias still waiting for its DNS: nothing to ask for.
		{AccountID: waiting, Domain: "waiting.example", Aliases: []string{"later.waiting.example"}, Covered: []string{"waiting.example"}, NotAfter: f.now.Add(60 * day), Revision: 4, Active: true},
		// No aliases: only the expiry matters, and no alias is probed.
		{AccountID: plain, Domain: "plain.example", Covered: []string{"plain.example"}, NotAfter: f.now.Add(60 * day), Revision: 5, Active: true},
	}
	f.m.check(context.Background())
	if !slices.Equal(f.issuer.domains, []string{"fresh.example,www.fresh.example"}) {
		t.Fatalf("asked for %q", f.issuer.domains)
	}
	if !slices.Equal(f.issuer.probes, []string{"www.fresh.example", "later.waiting.example"}) {
		t.Fatalf("probed %q", f.issuer.probes)
	}
	if got := f.m.Waiting(waiting); !slices.Equal(got, []string{"later.waiting.example"}) {
		t.Fatalf("waiting %q", got)
	}
}

// TestExpiringCertificateFallsBackToTheDomain: an alias the certificate
// authority cannot validate must not let the site's certificate run out.
func TestExpiringCertificateFallsBackToTheDomain(t *testing.T) {
	f := newManagerFixture(t)
	id := strings.Repeat("9", 32)
	f.issuer.failMany = fmt.Errorf("%w: www.example.com: connection refused", ErrValidation)
	site := Site{AccountID: id, Domain: "example.com", Aliases: []string{"www.example.com"}, Covered: []string{"example.com"}, NotAfter: f.now.Add(10 * 24 * time.Hour), Revision: 7, Active: true}
	if err := f.m.Refresh(context.Background(), site); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.issuer.domains, []string{"example.com,www.example.com", "example.com"}) || !slices.Equal(f.installer.calls, []string{id + " rev=7 chain example.com"}) {
		t.Fatalf("asked %q, installed %q", f.issuer.domains, f.installer.calls)
	}
	if got := f.m.Waiting(id); !slices.Equal(got, []string{"www.example.com"}) {
		t.Fatalf("waiting %q", got)
	}
	// Not expiring: the old certificate stays, and nothing else is asked for.
	f.issuer.domains, f.installer.calls = nil, nil
	site.NotAfter = f.now.Add(60 * 24 * time.Hour)
	if err := f.m.Refresh(context.Background(), site); !errors.Is(err, ErrValidation) || len(f.issuer.domains) != 1 || len(f.installer.calls) != 0 {
		t.Fatalf("%v, asked %q, installed %q", err, f.issuer.domains, f.installer.calls)
	}
}

// TestReachesAsksTheChallengePath runs the probe against a web server that
// serves the challenge directory as OpenLiteSpeed's challenge context does.
func TestReachesAsksTheChallengePath(t *testing.T) {
	dir := t.TempDir()
	files := challengeFiles{dir: dir}
	var asked []string
	serve := func(answer func(token string) (int, string)) *http.Client {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			asked = append(asked, r.Host+r.URL.Path)
			token, ok := strings.CutPrefix(r.URL.Path, challengePath)
			if !ok {
				http.NotFound(w, r)
				return
			}
			code, body := answer(token)
			if code == http.StatusFound {
				http.Redirect(w, r, "https://elsewhere.example/", code)
				return
			}
			w.WriteHeader(code)
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		// Every name resolves to the test server, as DNS pointing here would.
		dialer := &net.Dialer{}
		return &http.Client{Timeout: reachTimeout, CheckRedirect: defaultReachClient.CheckRedirect, Transport: &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, srv.Listener.Addr().String())
		}}}
	}
	fromDir := func(token string) (int, string) {
		data, err := os.ReadFile(filepath.Join(dir, token))
		if err != nil {
			return http.StatusNotFound, ""
		}
		return http.StatusOK, string(data)
	}
	ctx := context.Background()
	if !reaches(ctx, serve(fromDir), files, "www.example.com") {
		t.Fatal("a domain that serves the challenge directory does not reach")
	}
	if len(asked) != 1 || !strings.HasPrefix(asked[0], "www.example.com"+challengePath) {
		t.Fatalf("asked %q", asked)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("the probe left %d files in the challenge directory", len(entries))
	}
	for name, answer := range map[string]func(string) (int, string){
		"another server":  func(string) (int, string) { return http.StatusNotFound, "" },
		"a wrong answer":  func(string) (int, string) { return http.StatusOK, "something else" },
		"a redirect":      func(string) (int, string) { return http.StatusFound, "" },
		"an error page":   func(token string) (int, string) { _, body := fromDir(token); return http.StatusForbidden, body },
		"a longer answer": func(token string) (int, string) { _, body := fromDir(token); return http.StatusOK, body + "x" },
	} {
		if reaches(ctx, serve(answer), files, "www.example.com") {
			t.Errorf("%s counts as reaching", name)
		}
	}
	// Names that are not plain domains are not asked for at all.
	asked = nil
	for _, bad := range []string{"", "localhost", "example.com/x", "user@example.com", "example.com:8080", "Example.com", "-example.com"} {
		if reaches(ctx, serve(fromDir), files, bad) {
			t.Errorf("%q counts as reaching", bad)
		}
	}
	if len(asked) != 0 {
		t.Fatalf("asked %q", asked)
	}
}
