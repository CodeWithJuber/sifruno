// Package acme gets and renews the websites' certificates in the panel, which
// runs without root. lego talks to the certificate authority and answers
// HTTP-01 challenges with files in one shared directory; the finished
// certificate and key go to the account broker through an Installer, the
// only way a certificate reaches the web server. Nothing here runs as root.
//
// One certificate covers a site's domain and those of its aliases that
// reach this server when it is asked for: the panel first asks each alias's
// challenge path itself (Reaches), so an alias whose DNS does not point here
// yet waits on http instead of failing the certificate for every domain.
package acme

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	// LetsEncrypt is Let's Encrypt's production directory, the default.
	LetsEncrypt = "https://acme-v02.api.letsencrypt.org/directory"
	// ChallengeDir holds the HTTP-01 answers. It is outside every tenant
	// home, owned by the panel's user, and every vhost the broker renders
	// maps /.well-known/acme-challenge/ to it. Provisioning creates it.
	ChallengeDir = "/var/lib/sifruno-acme"
)

const (
	issueLimit = 3 * time.Minute // lego's part of one attempt: order, challenge, download
	firstCheck = 2 * time.Minute // the renewal loop's first look after start
	checkEvery = 12 * time.Hour  // and every 12 hours after that
	retryEvery = 6 * time.Hour   // at most one attempt per site in this time
	// After the broker refused to install an issued certificate, wait a
	// week: each refused install takes two rows of the account's journal,
	// which holds 256, so retrying every 6 hours would fill it in a month.
	installRetryEvery = 7 * 24 * time.Hour
	renewBefore       = 30 * 24 * time.Hour // renew once less than this is left
	minWait           = time.Minute         // the loop never spins faster than this
	logLimit          = 300                 // bytes of error text in one log line
	stateDirMode      = 0o700
)

// Installer installs a finished certificate (the chain, leaf first) and its
// key for one hosting account at its expected revision, and answers the
// account's new revision and the leaf's expiry. Root wires it to the account
// broker's certificate operation. Install must not keep keyPEM after it
// returns: the Manager clears those bytes then.
type Installer interface {
	Install(ctx context.Context, accountID string, revision uint64, certPEM, keyPEM []byte) (newRevision uint64, notAfter time.Time, err error)
}

// Issuer gets one certificate naming these domains, the first the site's
// own. The lego client is the real one; tests use a fake.
type Issuer interface {
	Issue(ctx context.Context, domains []string) (Certificate, error)
}

// Reacher is what an Issuer may also do: say whether a domain reaches this
// server's HTTP-01 challenge path now. Without it every alias is asked for.
type Reacher interface {
	Reaches(ctx context.Context, domain string) bool
}

// Certificate is what an Issuer answers: the chain PEM, leaf first, and the
// private key PEM.
type Certificate struct {
	ChainPEM []byte
	KeyPEM   []byte
}

// Site is a hosting account as the renewal loop sees it. NotAfter is the
// expiry of the certificate the broker reports for it, zero when the broker
// does not say; the loop then uses its own record.
type Site struct {
	AccountID string
	Domain    string
	// Aliases are the site's other domains. A certificate names those of
	// them that reach this server when it is asked for; the others wait for
	// their DNS and are served over http.
	Aliases []string
	// Covered are the domains the installed certificate names, as the broker
	// reports them; empty when it reports none.
	Covered  []string
	Revision uint64
	Active   bool
	NotAfter time.Time
}

// Sites lists the hosting accounts.
type Sites interface {
	Sites(context.Context) ([]Site, error)
}

var (
	// ErrValidation: the certificate authority could not reach the domain on
	// this server, usually because the domain does not point here yet.
	ErrValidation = errors.New("acme: the certificate authority could not validate the domain")
	// ErrRateLimited: the certificate authority's rate limit was reached.
	ErrRateLimited = errors.New("acme: the certificate authority's rate limit was reached")
	// ErrAuthority: the certificate authority did not answer or refused.
	ErrAuthority = errors.New("acme: the certificate authority did not issue a certificate")
	// ErrInstall: a certificate was issued, but the broker did not install it.
	ErrInstall = errors.New("acme: the certificate could not be installed")
)

// Manager gets, installs and renews certificates, one at a time, and keeps a
// record of every site it has tried, so the renewal loop can come back to it.
type Manager struct {
	issuer    Issuer
	installer Installer
	sites     Sites
	records   *records
	busy      chan struct{} // one attempt at a time
	log       io.Writer
	now       func() time.Time
	reaches   func(context.Context, string) bool
}

// NewManager returns a manager over any issuer, keeping its records in
// stateDir (made 0700).
func NewManager(issuer Issuer, installer Installer, sites Sites, stateDir string) (*Manager, error) {
	if issuer == nil || installer == nil || sites == nil {
		return nil, errors.New("acme: an issuer, an installer and a site list are all needed")
	}
	dir, err := privateDir(stateDir)
	if err != nil {
		return nil, err
	}
	m := &Manager{issuer: issuer, installer: installer, sites: sites, busy: make(chan struct{}, 1), log: os.Stderr, now: time.Now}
	m.reaches = func(context.Context, string) bool { return true }
	if r, ok := issuer.(Reacher); ok {
		m.reaches = r.Reaches
	}
	if m.records, err = openRecords(dir, m.log); err != nil {
		return nil, err
	}
	return m, nil
}

// Secure gets a certificate for domain and installs it on the account at
// revision. It answers the account's new revision and the certificate's
// expiry. Every attempt is recorded, so a site that fails now is tried again
// by the renewal loop, and logged as one line without secrets. The error
// wraps ErrValidation, ErrRateLimited, ErrAuthority or ErrInstall; running
// out of time while issuing counts as ErrAuthority. Only a context that ends
// while another attempt holds the manager answers the bare context error.
func (m *Manager) Secure(ctx context.Context, accountID, domain string, revision uint64) (uint64, time.Time, error) {
	if accountID == "" || domain == "" {
		return 0, time.Time{}, errors.New("acme: an account and a domain are needed")
	}
	select {
	case m.busy <- struct{}{}:
	case <-ctx.Done():
		return 0, time.Time{}, ctx.Err()
	}
	defer func() { <-m.busy }()
	return m.secure(ctx, accountID, []string{domain}, revision)
}

// secure gets and installs one certificate for names, the site's own domain
// first, while the caller holds m.busy.
func (m *Manager) secure(ctx context.Context, accountID string, names []string, revision uint64) (uint64, time.Time, error) {
	label := strings.Join(names, ", ")
	m.records.attempt(accountID, names[0], m.now())
	issueCtx, cancel := context.WithTimeout(ctx, issueLimit)
	cert, err := m.issuer.Issue(issueCtx, names)
	cancel()
	if err != nil {
		err = classify(err)
		m.records.failed(accountID, err)
		m.logf("acme: %s (account %s): no certificate: %s", label, accountID, oneLine(err))
		return 0, time.Time{}, err
	}
	newRevision, notAfter, err := m.installer.Install(ctx, accountID, revision, cert.ChainPEM, cert.KeyPEM)
	// The panel keeps no copy of the key; the broker holds the installed one.
	clear(cert.KeyPEM)
	if err != nil {
		err = fmt.Errorf("%w: %w", ErrInstall, err)
		m.records.failed(accountID, err)
		m.logf("acme: %s (account %s): certificate issued but not installed: %s", label, accountID, oneLine(err))
		return 0, time.Time{}, err
	}
	m.records.installed(accountID, notAfter)
	m.logf("acme: %s (account %s): certificate installed, valid until %s", label, accountID, notAfter.UTC().Format(time.DateOnly))
	return newRevision, notAfter, nil
}

// Refresh brings a live site's certificate up to date after its domains
// changed: it asks for one naming the site's domain and those of its aliases
// that reach this server now, unless the installed one names exactly those
// and has more than 30 days left. The aliases that do not reach this server
// are recorded (Waiting). A person changed the site, so it does not wait
// for the 6-hour retry or the week after a refused install. It answers the
// attempt's error, nil when nothing was needed.
func (m *Manager) Refresh(ctx context.Context, s Site) error {
	if s.AccountID == "" || s.Domain == "" {
		return errors.New("acme: an account and a domain are needed")
	}
	if !s.Active {
		return nil
	}
	notAfter := s.NotAfter
	if notAfter.IsZero() {
		r, _ := m.records.get(s.AccountID)
		notAfter = r.NotAfter
	}
	return m.renew(ctx, s, due(notAfter, time.Time{}, m.now()))
}

// Waiting names the site's aliases its last certificate request left out
// because they did not reach this server: their DNS does not point here
// yet.
func (m *Manager) Waiting(accountID string) []string {
	r, _ := m.records.get(accountID)
	return slices.Clone(r.Waiting)
}

// renew asks for a certificate naming the site's domain and its aliases
// that reach this server, when the installed one is expiring (or missing)
// or names other domains than those. A failed validation of an expiring
// certificate with aliases is tried once more for the site's own domain
// alone, so an alias the certificate authority cannot reach does not let the
// site's certificate run out.
func (m *Manager) renew(ctx context.Context, s Site, expiring bool) error {
	// The probes run before the manager is taken, all at once: a domain
	// that answers slowly holds up neither another site's certificate nor
	// its own for longer than one probe's limit.
	names, waiting := m.probe(ctx, s)
	select {
	case m.busy <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-m.busy }()
	m.records.waiting(s.AccountID, s.Domain, waiting)
	if !expiring && sameNames(names, covered(s)) {
		return nil
	}
	_, _, err := m.secure(ctx, s.AccountID, names, s.Revision)
	if errors.Is(err, ErrValidation) && expiring && len(names) > 1 {
		m.records.waiting(s.AccountID, s.Domain, append(waiting, names[1:]...))
		_, _, err = m.secure(ctx, s.AccountID, names[:1], s.Revision)
	}
	return err
}

// probe asks every alias of the site at once whether it reaches this
// server, and answers the names to ask a certificate for (the site's domain
// first, then the aliases that reach it, in the site's order) and the
// aliases that wait for their DNS.
func (m *Manager) probe(ctx context.Context, s Site) (names, waiting []string) {
	aliases := []string{}
	for _, alias := range s.Aliases {
		if alias != s.Domain && !slices.Contains(aliases, alias) {
			aliases = append(aliases, alias)
		}
	}
	reached := make([]bool, len(aliases))
	var wg sync.WaitGroup
	for i, alias := range aliases {
		wg.Go(func() { reached[i] = m.reaches(ctx, alias) })
	}
	wg.Wait()
	names, waiting = []string{s.Domain}, []string{}
	for i, alias := range aliases {
		if reached[i] {
			names = append(names, alias)
		} else {
			waiting = append(waiting, alias)
		}
	}
	return names, waiting
}

// covered are the domains the site's installed certificate names: what the
// broker reports, or the site's own domain alone for a certificate the
// broker reports no names for, or none without a certificate.
func covered(s Site) []string {
	if len(s.Covered) > 0 {
		return s.Covered
	}
	if !s.NotAfter.IsZero() {
		return []string{s.Domain}
	}
	return nil
}

// sameNames compares two lists of domains as sets.
func sameNames(a, b []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
}

// mayChange reports whether the names a site's certificate should carry
// can differ from the site's own domain: it has aliases, or the installed
// certificate names other domains.
func mayChange(s Site) bool {
	c := covered(s)
	return len(s.Aliases) > 0 || (len(c) > 0 && !slices.Equal(c, []string{s.Domain}))
}

// Run renews certificates until ctx ends: once 2 minutes after start, then
// every 12 hours, sooner when a site that has no certificate is due to be
// tried again.
func (m *Manager) Run(ctx context.Context) {
	timer := time.NewTimer(firstCheck)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		timer.Reset(m.check(ctx))
	}
}

// check renews what is due and answers how long to wait for the next check.
// A site is due when it has no certificate or less than 30 days left, and
// was not tried in the last 6 hours. A site the panel has not tried and the
// broker reports no certificate for is left alone: the panel cannot tell
// whether it is live.
func (m *Manager) check(ctx context.Context) time.Duration {
	sites, err := m.sites.Sites(ctx)
	if err != nil {
		m.logf("acme: renewal check: the account list could not be read: %s", oneLine(err))
		return m.nextWait()
	}
	byID := map[string]Site{}
	for _, s := range sites {
		byID[s.AccountID] = s
	}
	for _, r := range m.records.all() {
		s, ok := byID[r.AccountID]
		switch {
		case !ok:
			m.records.forget(r.AccountID)
			m.logf("acme: %s (account %s): the account is gone, so its certificate is no longer renewed", r.Domain, r.AccountID)
		case s.Domain != r.Domain:
			m.records.forget(r.AccountID)
			m.logf("acme: %s (account %s): the account's domain is now %s, so the old certificate is no longer renewed", r.Domain, r.AccountID, s.Domain)
		}
	}
	now := m.now()
	for _, s := range sites {
		if ctx.Err() != nil {
			break
		}
		r, known := m.records.get(s.AccountID)
		if !s.Active || (!known && s.NotAfter.IsZero()) {
			continue
		}
		notAfter := s.NotAfter
		if notAfter.IsZero() {
			notAfter = r.NotAfter
		}
		retryAt := r.LastAttempt.Add(retryWait(r))
		// A site with aliases is looked at too when its certificate is not
		// due: an alias whose DNS now points here, or one removed, changes
		// the names it should carry.
		expiring := due(notAfter, retryAt, now)
		if expiring || (!now.Before(retryAt) && mayChange(s)) {
			// secure logs the outcome; the error is already in the record.
			_ = m.renew(ctx, s, expiring)
		}
	}
	return m.nextWait()
}

// due: no certificate yet, or less than 30 days left, and the site may be
// tried again (now is past retryAt).
func due(notAfter, retryAt, now time.Time) bool {
	if now.Before(retryAt) {
		return false
	}
	return notAfter.IsZero() || notAfter.Sub(now) < renewBefore
}

// retryWait is how long a site waits after its last attempt: 6 hours, or a
// week after the broker refused to install what was issued.
func retryWait(r record) time.Duration {
	if r.LastResult == ErrInstall.Error() {
		return installRetryEvery
	}
	return retryEvery
}

// nextWait is the time to the next check: 12 hours, or sooner when a
// recorded site becomes due, but never less than a minute. A site already
// due was left alone by the check just made (its account is suspended, or
// the list could not be read), so it waits for the regular check.
func (m *Manager) nextWait() time.Duration {
	now := m.now()
	wait := checkEvery
	for _, r := range m.records.all() {
		at := r.LastAttempt.Add(retryWait(r))
		if !r.NotAfter.IsZero() {
			if renew := r.NotAfter.Add(-renewBefore); renew.After(at) {
				at = renew
			}
		}
		if d := at.Sub(now); d > 0 && d < wait {
			wait = d
		}
	}
	return max(wait, minWait)
}

func (m *Manager) logf(format string, args ...any) {
	fmt.Fprintf(m.log, format+"\n", args...)
}

// oneLine keeps error text to one short line, and drops it entirely if it
// looks like it carries a private key.
func oneLine(err error) string {
	text := strings.Join(strings.Fields(err.Error()), " ")
	if strings.Contains(text, "PRIVATE KEY") {
		return "[error text removed: it quoted key material]"
	}
	if len(text) > logLimit {
		text = text[:logLimit] + "..."
	}
	return text
}
