package hostaccounts

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"sifruno/internal/olsweb"
)

// The tests run in a synctest bubble: its clock is the one webSites reads
// and the loop's timer waits on, and time.Sleep moves it without waiting.

// runHTTPSExpiry starts the expiry loop as the broker does, with the store's
// changes waking it, and returns a stop function that ends it and waits
// until it has returned.
func runHTTPSExpiry(t *testing.T, s *store, rendered time.Time) func() {
	t.Helper()
	h := newHTTPSExpiry(s.httpsExpiresAfter, s.reloadWebServer)
	s.mu.Lock()
	s.httpsWake = h.wake
	s.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		h.run(ctx, rendered)
		close(done)
	}()
	return func() {
		cancel()
		<-done
	}
}

// served is the site as the last install left it and the number of
// installs so far, read under the store lock the installs hold.
func served(t *testing.T, s *store, f *fakeNative, id string) (olsweb.Site, int) {
	t.Helper()
	synctest.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	return siteOf(t, f.sites, id), f.siteApplies
}

// chainUntil is newTestChainFor with the leaf's NotAfter at notAfter.
func chainUntil(t *testing.T, notAfter time.Time, domains ...string) testChain {
	t.Helper()
	root := newTestIssuer(t, "Test Root", nil)
	mid := newTestIssuer(t, "Test Intermediate", root)
	key := newTestKey(t, elliptic.P256())
	leaf, leafPEM := mid.leaf(t, leafSpec{dns: domains, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, key: key, notAfter: notAfter})
	return testChain{leaf: leaf, leafPEM: leafPEM, intermediate: pemOf("CERTIFICATE", mid.cert.Raw), root: pemOf("CERTIFICATE", root.cert.Raw), key: key}
}

// TestAlwaysHTTPSStopsWhenTheCertificateExpires: a certificate in force
// passes its NotAfter with no renewal. The broker renders the config again
// at that second, so plain http no longer goes to an expired https, and
// the account and its journal stay as they were.
func TestAlwaysHTTPSStopsWhenTheCertificateExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, f := webStore(t)
		secured := securedFixture(t, s, liveFixture(t, s))
		id := secured.Account.ID
		defer runHTTPSExpiry(t, s, time.Now())()
		notAfter := time.Unix(secured.TLS.NotAfter, 0)
		site, applies := served(t, s, f, id)
		if !site.AlwaysHTTPS {
			t.Fatal("the certificate in force does not redirect")
		}
		time.Sleep(time.Until(notAfter) - time.Second)
		if site, n := served(t, s, f, id); !site.AlwaysHTTPS || n != applies {
			t.Fatalf("a second before NotAfter: redirect %v, %d installs", site.AlwaysHTTPS, n-applies)
		}
		time.Sleep(time.Second)
		site, n := served(t, s, f, id)
		if site.AlwaysHTTPS || n != applies+1 {
			t.Fatalf("at NotAfter: redirect %v, %d installs", site.AlwaysHTTPS, n-applies)
		}
		if site.TLS.CertFile == "" {
			t.Fatal("the expired certificate's files left the config: only the redirect stops")
		}
		if after := recordFor(t, s, id); after.Account.Revision != secured.Account.Revision || after.HistorySequence != secured.HistorySequence || after.Pending != nil {
			t.Fatalf("the render at expiry changed the account: %+v", after.Account)
		}
		// Nothing more is in force: no further render, however long.
		time.Sleep(400 * 24 * time.Hour)
		if _, m := served(t, s, f, id); m != n {
			t.Fatalf("%d installs with nothing in force", m-n)
		}
	})
}

// A renewal before NotAfter moves the render to the new NotAfter.
func TestAlwaysHTTPSExpiryFollowsARenewal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, f := webStore(t)
		secured := securedFixture(t, s, liveFixture(t, s))
		id := secured.Account.ID
		defer runHTTPSExpiry(t, s, time.Now())()
		first := time.Unix(secured.TLS.NotAfter, 0)
		time.Sleep(time.Until(first) - 30*24*time.Hour)
		renewed, err := s.setCertificate(context.Background(), id, newTestChainFor(t, "fixture.test", "www.fixture.test").input(t, secured.Account.Revision), "test operator")
		if err != nil {
			t.Fatal(err)
		}
		r := recordFor(t, s, id)
		second := time.Unix(r.TLS.NotAfter, 0)
		if !second.After(first) || renewed.Account.Revision != secured.Account.Revision+1 {
			t.Fatalf("renewal: %v then %v", first, second)
		}
		_, applies := served(t, s, f, id)
		time.Sleep(time.Until(first) + time.Minute)
		if site, n := served(t, s, f, id); !site.AlwaysHTTPS || n != applies {
			t.Fatalf("past the old NotAfter: redirect %v, %d installs", site.AlwaysHTTPS, n-applies)
		}
		time.Sleep(time.Until(second))
		if site, n := served(t, s, f, id); site.AlwaysHTTPS || n != applies+1 {
			t.Fatalf("at the new NotAfter: redirect %v, %d installs", site.AlwaysHTTPS, n-applies)
		}
	})
}

// With the switch off nothing is in force, so nothing renders at NotAfter;
// turned on again, the render at NotAfter comes back. Of two sites, the one
// whose certificate ends first goes first, and the other at its own time.
func TestAlwaysHTTPSExpiryFollowsTheSwitchAndTheEarliestSite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, f := webStore(t)
		ctx := context.Background()
		secured := securedFixture(t, s, liveFixture(t, s))
		id := secured.Account.ID
		defer runHTTPSExpiry(t, s, time.Now())()
		off, err := s.setAlwaysHTTPS(ctx, id, alwaysHTTPSInput(secured, false), "test operator")
		if err != nil {
			t.Fatal(err)
		}
		notAfter := time.Unix(secured.TLS.NotAfter, 0)
		_, applies := served(t, s, f, id)
		time.Sleep(time.Until(notAfter) - time.Hour)
		on, err := s.setAlwaysHTTPS(ctx, id, alwaysHTTPSInput(recordFor(t, s, id), true), "test operator")
		if err != nil || on.PlainHTTP || on.Revision != off.Revision+1 {
			t.Fatal(err)
		}
		// The other site's certificate ends half an hour before this one's.
		other := createFixtureNamed(t, s, "secondacct", "second.test")
		if _, err := s.setWeb(ctx, other.ID, WebInput{PHPVersion: "8.3", QuotaMiB: 200, ExpectedRevision: other.Revision, Reason: "Go live"}, "test operator"); err != nil {
			t.Fatal(err)
		}
		live := recordFor(t, s, other.ID)
		if _, err := s.setCertificate(ctx, other.ID, chainUntil(t, notAfter.Add(-30*time.Minute), "second.test").input(t, live.Account.Revision), "test operator"); err != nil {
			t.Fatal(err)
		}
		_, applies = served(t, s, f, id)
		if site, _ := served(t, s, f, other.ID); !site.AlwaysHTTPS {
			t.Fatal("the other site does not redirect")
		}
		time.Sleep(30 * time.Minute)
		if mine, n := served(t, s, f, id); !mine.AlwaysHTTPS || n != applies+1 {
			t.Fatalf("at the other's NotAfter: this site's redirect %v, %d installs", mine.AlwaysHTTPS, n-applies)
		}
		if theirs, _ := served(t, s, f, other.ID); theirs.AlwaysHTTPS {
			t.Fatal("the other site still redirects past its NotAfter")
		}
		time.Sleep(30 * time.Minute)
		if mine, n := served(t, s, f, id); mine.AlwaysHTTPS || n != applies+2 {
			t.Fatalf("at this site's NotAfter: redirect %v, %d installs", mine.AlwaysHTTPS, n-applies)
		}
	})
}

// A render that fails is logged by its class, with no account named, and
// tried again a minute later; until then nothing more is installed.
func TestAlwaysHTTPSExpiryRetriesAFailedRender(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logs := captureRecoveryLog(t)
		s, f := webStore(t)
		secured := securedFixture(t, s, liveFixture(t, s))
		id := secured.Account.ID
		defer runHTTPSExpiry(t, s, time.Now())()
		_, applies := served(t, s, f, id)
		s.mu.Lock()
		f.failure = "sites"
		s.mu.Unlock()
		time.Sleep(time.Until(time.Unix(secured.TLS.NotAfter, 0)))
		if _, n := served(t, s, f, id); n != applies+1 {
			t.Fatalf("at NotAfter: %d installs", n-applies)
		}
		out := logged(logs)
		if !strings.Contains(out, "operation=https_expiry account=- user=-") || strings.Contains(out, id) || strings.Contains(out, secured.Account.Username) {
			t.Fatalf("log %q", out)
		}
		time.Sleep(httpsExpiryRetry - time.Second)
		if _, n := served(t, s, f, id); n != applies+1 {
			t.Fatalf("before the retry: %d installs", n-applies)
		}
		s.mu.Lock()
		f.failure = ""
		s.mu.Unlock()
		time.Sleep(time.Second)
		if site, n := served(t, s, f, id); site.AlwaysHTTPS || n != applies+2 {
			t.Fatalf("the retry: redirect %v, %d installs", site.AlwaysHTTPS, n-applies)
		}
	})
}

// A broker that starts after a certificate in force expired, with no
// render of its own at start, renders at once; one whose start render came
// after it renders nothing more.
func TestAlwaysHTTPSExpiryAtStart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, f := webStore(t)
		secured := securedFixture(t, s, liveFixture(t, s))
		id := secured.Account.ID
		time.Sleep(time.Until(time.Unix(secured.TLS.NotAfter, 0)) + time.Hour)
		_, applies := served(t, s, f, id)
		stop := runHTTPSExpiry(t, s, time.Now())
		if _, n := served(t, s, f, id); n != applies {
			t.Fatalf("after a start render: %d installs", n-applies)
		}
		stop()
		defer runHTTPSExpiry(t, s, time.Time{})()
		if site, n := served(t, s, f, id); site.AlwaysHTTPS || n != applies+1 {
			t.Fatalf("with no start render: redirect %v, %d installs", site.AlwaysHTTPS, n-applies)
		}
	})
}

// firstHTTPSExpiry counts only what webSites renders with the redirect on.
func TestFirstHTTPSExpiry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	mk := func(notAfter int64) record {
		cert := CertificateState{NotAfter: notAfter, Fingerprint: strings.Repeat("ab", 32)}
		return record{Account: Account{ID: strings.Repeat("a", 32), Certificate: cert}, Web: WebState{PHPVersion: "8.3", QuotaMiB: 200}, TLS: cert}
	}
	at := func(items ...record) int64 {
		t.Helper()
		got, ok := firstHTTPSExpiry(items, now)
		if !ok {
			return 0
		}
		return got.Unix()
	}
	plain := mk(now.Unix() + 10)
	plain.Account.PlainHTTP = true
	offline := mk(now.Unix() + 10)
	offline.Web = WebState{}
	deleting := mk(now.Unix() + 10)
	deleting.Pending = &pending{Action: "delete"}
	none := mk(0)
	none.TLS = CertificateState{}
	if got := at(mk(now.Unix()+50), mk(now.Unix()+20), mk(now.Unix()), mk(now.Unix()-5), plain, offline, deleting, none); got != now.Unix()+20 {
		t.Fatalf("first expiry %d, want %d", got, now.Unix()+20)
	}
	if got := at(mk(now.Unix()), plain); got != 0 {
		t.Fatalf("nothing in force: %d", got)
	}
	// A change in flight counts as done, as webSites renders it.
	turningOn := plain
	turningOn.Pending = &pending{Action: "https", Target: "on"}
	installing := mk(0)
	installing.TLS = CertificateState{}
	installing.TLSNext = CertificateState{NotAfter: now.Unix() + 7, Fingerprint: strings.Repeat("cd", 32)}
	installing.Pending = &pending{Action: "certificate"}
	if got := at(turningOn, installing); got != now.Unix()+7 {
		t.Fatalf("changes in flight: %d", got)
	}
}
