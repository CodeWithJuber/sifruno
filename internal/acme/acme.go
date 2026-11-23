// Package acme gets and renews the websites' certificates in the panel, which
// runs without root. lego talks to the certificate authority and answers
// HTTP-01 challenges with files in one shared directory; the finished
// certificate and key go to the account broker through an Installer, the
// only way a certificate reaches the web server. Nothing here runs as root.
package acme

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
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
	issueLimit   = 3 * time.Minute     // lego's part of one attempt: order, challenge, download
	firstCheck   = 2 * time.Minute     // the renewal loop's first look after start
	checkEvery   = 12 * time.Hour      // and every 12 hours after that
	retryEvery   = 6 * time.Hour       // at most one attempt per site in this time
	renewBefore  = 30 * 24 * time.Hour // renew once less than this is left
	minWait      = time.Minute         // the loop never spins faster than this
	logLimit     = 300                 // bytes of error text in one log line
	stateDirMode = 0o700
)

// Installer installs a finished certificate (the chain, leaf first) and its
// key for one hosting account at its expected revision, and answers the
// account's new revision and the leaf's expiry. Root wires it to the account
// broker's certificate operation. Install must not keep keyPEM after it
// returns: the Manager clears those bytes then.
type Installer interface {
	Install(ctx context.Context, accountID string, revision uint64, certPEM, keyPEM []byte) (newRevision uint64, notAfter time.Time, err error)
}

// Issuer gets a certificate for one domain. The lego client is the real one;
// tests use a fake.
type Issuer interface {
	Issue(ctx context.Context, domain string) (Certificate, error)
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
	Revision  uint64
	Active    bool
	NotAfter  time.Time
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
	m.records.attempt(accountID, domain, m.now())
	issueCtx, cancel := context.WithTimeout(ctx, issueLimit)
	cert, err := m.issuer.Issue(issueCtx, domain)
	cancel()
	if err != nil {
		err = classify(err)
		m.records.failed(accountID, err)
		m.logf("acme: %s (account %s): no certificate: %s", domain, accountID, oneLine(err))
		return 0, time.Time{}, err
	}
	newRevision, notAfter, err := m.installer.Install(ctx, accountID, revision, cert.ChainPEM, cert.KeyPEM)
	// The panel keeps no copy of the key; the broker holds the installed one.
	clear(cert.KeyPEM)
	if err != nil {
		err = fmt.Errorf("%w: %w", ErrInstall, err)
		m.records.failed(accountID, err)
		m.logf("acme: %s (account %s): certificate issued but not installed: %s", domain, accountID, oneLine(err))
		return 0, time.Time{}, err
	}
	m.records.installed(accountID, notAfter)
	m.logf("acme: %s (account %s): certificate installed, valid until %s", domain, accountID, notAfter.UTC().Format(time.DateOnly))
	return newRevision, notAfter, nil
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
		if due(notAfter, r.LastAttempt, now) {
			// Secure logs the outcome; the error is already in the record.
			_, _, _ = m.Secure(ctx, s.AccountID, s.Domain, s.Revision)
		}
	}
	return m.nextWait()
}

// due: no certificate yet, or less than 30 days left, and no attempt in the
// last 6 hours.
func due(notAfter, lastAttempt, now time.Time) bool {
	if now.Sub(lastAttempt) < retryEvery {
		return false
	}
	return notAfter.IsZero() || notAfter.Sub(now) < renewBefore
}

// nextWait is the time to the next check: 12 hours, or sooner when a
// recorded site becomes due, but never less than a minute. A site already
// due was left alone by the check just made (its account is suspended, or
// the list could not be read), so it waits for the regular check.
func (m *Manager) nextWait() time.Duration {
	now := m.now()
	wait := checkEvery
	for _, r := range m.records.all() {
		at := r.LastAttempt.Add(retryEvery)
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
