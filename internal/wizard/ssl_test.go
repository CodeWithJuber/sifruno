package wizard

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"sifruno/internal/acme"
	"sifruno/internal/hostaccounts"
)

// The certificate step runs acme.Manager over a fake issuer (no ACME server)
// and a fake installer that changes the fake broker's account the way the
// broker's certificate operation does.

type fakeIssuer struct{ err error }

func (f fakeIssuer) Issue(_ context.Context, domains []string) (acme.Certificate, error) {
	domain := strings.Join(domains, ",")
	if f.err != nil {
		return acme.Certificate{}, f.err
	}
	return acme.Certificate{ChainPEM: []byte("chain for " + domain), KeyPEM: []byte("key for " + domain)}, nil
}

var testNotAfter = time.Date(2027, 2, 21, 10, 0, 0, 0, time.UTC)

type fakeInstaller struct {
	acc   *fakeAccounts
	err   error
	bumps bool // the broker applied it although the answer is err, as a timed-out call can
}

func (f fakeInstaller) Install(_ context.Context, id string, revision uint64, certPEM, keyPEM []byte) (uint64, time.Time, error) {
	f.acc.record(fmt.Sprintf("certificate %s rev=%d", id[28:], revision))
	if f.err != nil && !f.bumps {
		return 0, time.Time{}, f.err
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return 0, time.Time{}, hostaccounts.ErrInvalid
	}
	f.acc.mu.Lock()
	defer f.acc.mu.Unlock()
	i := slices.IndexFunc(f.acc.accounts, func(a hostaccounts.Account) bool { return a.ID == id })
	if i < 0 || f.acc.accounts[i].Revision != revision {
		return 0, time.Time{}, hostaccounts.ErrConflict
	}
	f.acc.accounts[i].Revision++
	if f.err != nil {
		return 0, time.Time{}, f.err
	}
	return f.acc.accounts[i].Revision, testNotAfter, nil
}

type noSites struct{}

func (noSites) Sites(context.Context) ([]acme.Site, error) { return nil, nil }

func withCertificates(t *testing.T, f fixture, issuer acme.Issuer, installer acme.Installer) {
	t.Helper()
	m, err := acme.NewManager(issuer, installer, noSites{}, filepath.Join(t.TempDir(), "acme"))
	if err != nil {
		t.Fatal(err)
	}
	f.runner.certificates = m
}

func sslStep(t *testing.T, j Job) Step {
	t.Helper()
	i := slices.IndexFunc(j.Steps, func(s Step) bool { return s.Name == StepSSL })
	if i != 2 || j.Steps[1].Name != StepWeb || j.Steps[3].Name != StepDatabase {
		t.Fatalf("ssl is not the step between web and database: %s", stepStates(j))
	}
	return j.Steps[i]
}

func TestSSLStepInstallsTheCertificateAndWordPressUsesHTTPS(t *testing.T) {
	f := newFixture(t)
	withCertificates(t, f, fakeIssuer{}, fakeInstaller{acc: f.acc})
	done := f.runJob(t, input("example.com"))
	if done.State != StateSucceeded || done.Error != nil {
		t.Fatalf("job %s %+v", done.State, done.Error)
	}
	if got := stepStates(done); got != "account=done web=done ssl=done database=done wordpress=done" {
		t.Fatal(got)
	}
	step := sslStep(t, done)
	if step.Message != "Installed a certificate for example.com, valid until 2027-02-21." || step.StartedAt == "" || step.FinishedAt == "" {
		t.Fatalf("ssl step %+v", step)
	}
	// The certificate moves the revision on; the install uses the new one.
	want := []string{"list", "create example", "web 0001 php=8.3 quota=1024 rev=1 reason=WordPress wizard", "certificate 0001 rev=2", "install 0001 rev=3"}
	if !slices.Equal(f.acc.calls, want) {
		t.Fatalf("broker calls %q", f.acc.calls)
	}
	if !f.acc.install.HTTPS {
		t.Fatal("WordPress was not installed with https")
	}
	wantResult := Result{URL: "https://example.com/", AdminURL: "https://example.com/wp-admin/", WordPressVersion: "7.1.5", AccountID: fmt.Sprintf("%032x", 1)}
	if done.Result == nil || *done.Result != wantResult {
		t.Fatalf("result %+v", done.Result)
	}
}

func TestSSLFailureIsSkippedAndTheSiteUsesHTTP(t *testing.T) {
	for _, tc := range []struct {
		name      string
		issuer    acme.Issuer
		installer func(*fakeAccounts) acme.Installer
		message   string
		calls     []string // after SetWeb
	}{
		{
			name:      "domain not pointing here",
			issuer:    fakeIssuer{err: fmt.Errorf("%w: acme: error: 403 :: urn:ietf:params:acme:error:connection :: refused", acme.ErrValidation)},
			installer: func(a *fakeAccounts) acme.Installer { return fakeInstaller{acc: a} },
			message:   "The domain does not point at this server yet, so the site uses http. The panel tries again every few hours.",
			calls:     []string{"list", "install 0001 rev=2"},
		},
		{
			name:      "rate limited",
			issuer:    fakeIssuer{err: fmt.Errorf("%w: too many certificates", acme.ErrRateLimited)},
			installer: func(a *fakeAccounts) acme.Installer { return fakeInstaller{acc: a} },
			message:   "The certificate authority is not issuing more certificates for this domain right now, so the site uses http. The panel tries again every few hours.",
			calls:     []string{"list", "install 0001 rev=2"},
		},
		{
			name:      "certificate authority unreachable",
			issuer:    fakeIssuer{err: errors.New("dial tcp: connection refused")},
			installer: func(a *fakeAccounts) acme.Installer { return fakeInstaller{acc: a} },
			message:   "The certificate authority could not be reached or did not issue a certificate, so the site uses http. The panel tries again every few hours.",
			calls:     []string{"list", "install 0001 rev=2"},
		},
		{
			name:      "web server refused the certificate",
			issuer:    fakeIssuer{},
			installer: func(a *fakeAccounts) acme.Installer { return fakeInstaller{acc: a, err: hostaccounts.ErrWebRejected} },
			message:   "A certificate was issued, but the web server did not take it, so the site uses http. The panel tries again every few hours.",
			calls:     []string{"certificate 0001 rev=2", "list", "install 0001 rev=2"},
		},
		{
			// The broker applied it but the panel stopped waiting: the
			// install step reads the account's new revision instead of
			// failing on the old one.
			name:   "broker answered late",
			issuer: fakeIssuer{},
			installer: func(a *fakeAccounts) acme.Installer {
				return fakeInstaller{acc: a, err: hostaccounts.ErrUnavailable, bumps: true}
			},
			message: "A certificate was issued, but the web server did not take it, so the site uses http. The panel tries again every few hours.",
			calls:   []string{"certificate 0001 rev=2", "list", "install 0001 rev=3"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			withCertificates(t, f, tc.issuer, tc.installer(f.acc))
			done := f.runJob(t, input("example.com"))
			if done.State != StateSucceeded || done.Error != nil {
				t.Fatalf("job %s %+v", done.State, done.Error)
			}
			if got := stepStates(done); got != "account=done web=done ssl=skipped database=done wordpress=done" {
				t.Fatal(got)
			}
			if step := sslStep(t, done); step.Message != tc.message || step.FinishedAt == "" {
				t.Fatalf("ssl step %+v", step)
			}
			if got := f.acc.calls[3:]; !slices.Equal(got, tc.calls) {
				t.Fatalf("broker calls after web %q", got)
			}
			if f.acc.install.HTTPS {
				t.Fatal("WordPress was installed with https without a certificate")
			}
			if done.Result == nil || done.Result.URL != "http://example.com/" || done.Result.AdminURL != "http://example.com/wp-admin/" {
				t.Fatalf("result %+v", done.Result)
			}
			if slices.ContainsFunc(f.acc.calls, func(c string) bool { return strings.HasPrefix(c, "delete") }) || len(undoCalls(f)) != 0 {
				t.Fatal("a skipped certificate undid something")
			}
		})
	}
}

func TestSSLNotConfiguredIsSkipped(t *testing.T) {
	f := newFixture(t) // no certificate service
	done := f.runJob(t, input("example.com"))
	if done.State != StateSucceeded || stepStates(done) != "account=done web=done ssl=skipped database=done wordpress=done" {
		t.Fatalf("job %s %s", done.State, stepStates(done))
	}
	if step := sslStep(t, done); step.Message != "Certificates are not set up on this server." {
		t.Fatalf("ssl step %+v", step)
	}
	if f.acc.install.HTTPS || done.Result.URL != "http://example.com/" {
		t.Fatalf("install https=%v result %+v", f.acc.install.HTTPS, done.Result)
	}
}

// A failure after the certificate removes the account, and the certificate
// with it.
func TestSSLStepIsUndoneWithTheAccount(t *testing.T) {
	f := newFixture(t)
	withCertificates(t, f, fakeIssuer{}, fakeInstaller{acc: f.acc})
	f.acc.installF = func(context.Context) error { return &hostaccounts.InstallError{Step: "install", Detail: "failed"} }
	done := f.runJob(t, input("example.com"))
	if got := stepStates(done); got != "account=undone web=undone ssl=undone database=undone wordpress=failed" {
		t.Fatal(got)
	}
	if !slices.Contains(f.acc.calls, "delete 0001 rev=3") || len(f.acc.accounts) != 0 {
		t.Fatalf("broker calls %q", f.acc.calls)
	}
}

// Jobs recorded before the "ssl" step have four steps; an upgraded panel
// still reads them.
func TestFourStepJobsFromAnOlderPanelStillLoad(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "wizard")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	old := `{"version":1,"jobs":[{"id":"` + strings.Repeat("a", 32) + `","kind":"wordpress","domain":"example.com","username":"example","state":"succeeded","steps":[` +
		`{"name":"account","title":"Create the hosting account","state":"done","message":"","started_at":"","finished_at":""},` +
		`{"name":"web","title":"Put the site live with PHP","state":"done","message":"","started_at":"","finished_at":""},` +
		`{"name":"database","title":"Create the database","state":"done","message":"","started_at":"","finished_at":""},` +
		`{"name":"wordpress","title":"Install WordPress","state":"done","message":"","started_at":"","finished_at":""}],` +
		`"error":null,"result":{"url":"http://example.com/","admin_url":"http://example.com/wp-admin/","wordpress_version":"7.1.5","account_id":""},"actor":"local-operator","created_at":"2026-11-01T10:00:00Z","updated_at":"2026-11-01T10:05:00Z"}]}`
	if err := os.WriteFile(filepath.Join(dir, storeFile), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	j, ok := store.Get(strings.Repeat("a", 32))
	if !ok || stepStates(j) != "account=done web=done database=done wordpress=done" {
		t.Fatalf("old job %v %s", ok, stepStates(j))
	}
	if aside, _ := filepath.Glob(filepath.Join(dir, storeFile+".corrupt-*")); len(aside) != 0 {
		t.Fatalf("old job file set aside: %q", aside)
	}
}
