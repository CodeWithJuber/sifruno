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
	"sync"
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
	f.now = f.now.Add(2 * time.Hour)
	if err := f.m.Refresh(context.Background(), site); err != nil || !slices.Equal(f.issuer.domains, []string{"example.com,shop.example.com,nodns.example.com,www.example.com"}) {
		t.Fatalf("a newly reachable alias: %v %q", err, f.issuer.domains)
	}
	if got := f.m.Waiting(id); len(got) != 0 {
		t.Fatalf("still waiting %q", got)
	}
	// An alias removed from the site stays on the certificate: an extra
	// name is harmless, and nothing is asked for.
	site.Aliases, site.Covered = []string{"www.example.com"}, []string{"example.com", "nodns.example.com", "shop.example.com", "www.example.com"}
	f.issuer.domains = nil
	f.now = f.now.Add(2 * time.Hour)
	if err := f.m.Refresh(context.Background(), site); err != nil || len(f.issuer.domains) != 0 {
		t.Fatalf("a removed alias: %v %q", err, f.issuer.domains)
	}
	// The renewal of the expiring certificate drops it.
	site.NotAfter = f.now.Add(10 * 24 * time.Hour)
	if err := f.m.Refresh(context.Background(), site); err != nil || !slices.Equal(f.issuer.domains, []string{"example.com,www.example.com"}) {
		t.Fatalf("the renewal after a removed alias: %v %q", err, f.issuer.domains)
	}
	// A suspended site is left alone.
	site.Active = false
	f.issuer.domains = nil
	if err := f.m.Refresh(context.Background(), site); err != nil || len(f.issuer.domains) != 0 {
		t.Fatalf("a suspended site: %v %q", err, f.issuer.domains)
	}
}

// TestRefreshWaitsForTheSitesLastAttempt: a person changed the site, so a
// refresh does not wait for the renewal loop's 6 hours, but it asks for
// nothing within an hour of the site's last attempt, or within a week of a
// refused install.
func TestRefreshWaitsForTheSitesLastAttempt(t *testing.T) {
	f := newManagerFixture(t)
	id := strings.Repeat("c", 32)
	site := Site{AccountID: id, Domain: "example.com", Aliases: []string{"www.example.com"}, Covered: []string{"example.com"}, NotAfter: f.now.Add(60 * 24 * time.Hour), Revision: 2, Active: true}
	for _, c := range []struct {
		name   string
		ago    time.Duration
		result string
		asks   bool
	}{
		{"a failed validation half an hour ago", 30 * time.Minute, ErrValidation.Error(), false},
		{"a failed validation two hours ago", 2 * time.Hour, ErrValidation.Error(), true},
		{"a certificate installed half an hour ago", 30 * time.Minute, "installed", false},
		{"a refused install a day ago", 24 * time.Hour, ErrInstall.Error(), false},
		{"a refused install eight days ago", 8 * 24 * time.Hour, ErrInstall.Error(), true},
	} {
		f.issuer.domains = nil
		f.m.records.change(id, func(r *record) {
			r.Domain, r.LastAttempt, r.LastResult = "example.com", f.now.Add(-c.ago), c.result
		})
		err := f.m.Refresh(context.Background(), site)
		if asked := len(f.issuer.domains) == 1; asked != c.asks || c.asks && err != nil || !c.asks && !errors.Is(err, ErrTooSoon) {
			t.Errorf("%s: %v, asked %q", c.name, err, f.issuer.domains)
		}
	}
	if !strings.Contains(f.log.String(), "no certificate asked for: the last attempt was at") {
		t.Fatalf("a refresh asked for nothing without saying so:\n%s", f.log)
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

// TestAliasFlipsCostOneOrder: adding and removing an alias over and over
// asks for one certificate, the first time; removing names asks for none;
// new names are asked for at most once an hour; and two refreshes of one
// site at once make one order.
func TestAliasFlipsCostOneOrder(t *testing.T) {
	f := newManagerFixture(t)
	id := strings.Repeat("5", 32)
	site := Site{AccountID: id, Domain: "example.com", Covered: []string{"example.com"}, NotAfter: f.now.Add(60 * 24 * time.Hour), Revision: 2, Active: true}
	for i := range 10 {
		f.now = f.now.Add(2 * time.Hour)
		site.Aliases = []string{"flip.example.com"}
		if err := f.m.Refresh(context.Background(), site); err != nil {
			t.Fatalf("flip %d, alias added: %v", i, err)
		}
		if i == 0 {
			// The broker now reports the certificate the panel installed.
			site.Covered = []string{"example.com", "flip.example.com"}
		}
		site.Aliases = nil
		if err := f.m.Refresh(context.Background(), site); err != nil {
			t.Fatalf("flip %d, alias removed: %v", i, err)
		}
	}
	if !slices.Equal(f.issuer.domains, []string{"example.com,flip.example.com"}) {
		t.Fatalf("ten flips asked for %q", f.issuer.domains)
	}
	// A new alias every ten minutes: one order an hour.
	f.issuer.domains = nil
	f.now = f.now.Add(2 * time.Hour)
	for i := range 12 {
		site.Aliases = []string{fmt.Sprintf("new%d.example.com", i)}
		err := f.m.Refresh(context.Background(), site)
		if i%6 != 0 && !errors.Is(err, ErrTooSoon) {
			t.Fatalf("alias %d: %v", i, err)
		}
		f.now = f.now.Add(10 * time.Minute)
	}
	if len(f.issuer.domains) != 2 {
		t.Fatalf("two hours of new aliases asked for %q", f.issuer.domains)
	}
	// Two refreshes at once: one order.
	f.issuer.domains = nil
	f.now = f.now.Add(2 * time.Hour)
	site.Aliases = []string{"together.example.com"}
	errs := make(chan error, 2)
	for range 2 {
		go func() { errs <- f.m.Refresh(context.Background(), site) }()
	}
	first, second := <-errs, <-errs
	if len(f.issuer.domains) != 1 || (first == nil) == (second == nil) {
		t.Fatalf("two refreshes at once: %v, %v, asked %q", first, second, f.issuer.domains)
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
	f.now = f.now.Add(2 * time.Hour)
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

// TestProbesRunTogetherWithoutHoldingTheManager: a site whose aliases answer
// slowly holds up no other certificate, and its probes take one probe's
// time, not one per alias.
func TestProbesRunTogetherWithoutHoldingTheManager(t *testing.T) {
	f := newManagerFixture(t)
	release := make(chan struct{})
	var started sync.WaitGroup
	aliases := []string{}
	for i := range 15 {
		aliases = append(aliases, fmt.Sprintf("a%d.slow.example", i))
	}
	started.Add(len(aliases))
	f.m.reaches = func(context.Context, string) bool { started.Done(); <-release; return true }
	done := make(chan error, 1)
	go func() {
		done <- f.m.Refresh(context.Background(), Site{AccountID: strings.Repeat("7", 32), Domain: "slow.example", Aliases: aliases, Revision: 3, Active: true})
	}()
	// Every probe is under way at once.
	started.Wait()
	// Meanwhile another site gets its certificate.
	if _, _, err := f.m.Secure(context.Background(), strings.Repeat("8", 32), "other.example", 2); err != nil {
		t.Fatalf("another site waited for the probes: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := f.issuer.domains; len(got) != 2 || got[0] != "other.example" || !strings.HasPrefix(got[1], "slow.example,a0.slow.example,a1.slow.example") {
		t.Fatalf("asked for %q", got)
	}
}
