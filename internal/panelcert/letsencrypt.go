package panelcert

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sifruno/internal/acme"
	"sifruno/internal/securestate"
)

// AccountID names the panel's own certificate to the certificate manager:
// in its records and in its log lines. A hosting account's ID is 32 hex
// characters, so it never takes this one.
const AccountID = "panel"

// issuedFile holds the panel's Let's Encrypt certificate, the chain leaf
// first and then its key, in one private file: one rename replaces both, so
// a crash never leaves a certificate beside another one's key.
const issuedFile = "letsencrypt.pem"

const (
	// How long Obtain waits for the panel's name to answer on port 80 here
	// before it asks anyway, and how often it looks meanwhile.
	reachWait  = 2 * time.Minute
	reachEvery = 5 * time.Second
)

// notPublic are the top-level names kept out of public DNS: for tests,
// examples, local networks and onion services (RFC 2606, 6761, 6762, 7686,
// 8375 for home.arpa under arpa) and ICANN's .internal. Let's Encrypt
// issues for none of them.
var notPublic = map[string]bool{"test": true, "example": true, "invalid": true, "localhost": true, "local": true, "onion": true, "arpa": true, "internal": true}

// PublicNames are the panel host names Let's Encrypt can issue a
// certificate for, in their order, once each: DNS names of two labels or
// more outside the reserved names (notPublic, and RFC 2606's example.com,
// example.net and example.org). An IP address is left out: it keeps the
// self-signed certificate.
func PublicNames(hosts []string) []string {
	var out []string
	for _, h := range hosts {
		labels := strings.Split(h, ".")
		if net.ParseIP(h) != nil || !ValidHost(h) || len(labels) < 2 || slices.Contains(out, h) {
			continue
		}
		top, second := labels[len(labels)-1], labels[len(labels)-2]
		if notPublic[top] || (second == "example" && (top == "com" || top == "net" || top == "org")) {
			continue
		}
		out = append(out, h)
	}
	return out
}

// Issued is the panel's own certificate from Let's Encrypt, kept in
// <state>/tls. The HTTPS listeners serve it, through GetCertificate, to a
// client that asks for a name it covers; every other client, and one that
// asks for an IP address, gets the self-signed certificate. As the
// certificate manager's Installer and Sites it gets the certificate, and a
// renewed one, and serves it at once, without a restart.
type Issued struct {
	dir   string
	names []string
	now   func() time.Time
	// reachEvery and reachWait are the package's; tests shorten them.
	reachEvery, reachWait time.Duration

	mu       sync.Mutex // one Install at a time
	current  atomic.Pointer[issuedCert]
	revision atomic.Uint64
}

type issuedCert struct {
	cert     tls.Certificate // Leaf set
	notAfter time.Time
}

// OpenIssued reads the certificate saved in stateDir/tls, if there is one
// it can serve now. names are PublicNames of the panel's hosts, the first
// the one the certificate is for. A saved file it cannot use (others may
// read it, it is not a certificate with its key, or it has expired) is left
// where it is: the next certificate replaces it.
func OpenIssued(stateDir string, names []string, now func() time.Time) (*Issued, error) {
	if len(names) == 0 || !slices.Equal(PublicNames(names), names) {
		return nil, errors.New("panelcert: the panel's certificate needs public DNS names")
	}
	dir, err := securestate.Dir(filepath.Join(stateDir, "tls"))
	if err != nil {
		return nil, errors.New("panel TLS state unavailable")
	}
	i := &Issued{dir: dir, names: slices.Clone(names), now: now, reachEvery: reachEvery, reachWait: reachWait}
	if raw, err := readPrivate(filepath.Join(dir, issuedFile)); err == nil {
		if c, err := parseIssued(raw, now()); err == nil {
			i.current.Store(c)
		}
		clear(raw)
	}
	return i, nil
}

// parseIssued reads a chain and its key, leaf first, valid at now.
func parseIssued(chainAndKey []byte, now time.Time) (*issuedCert, error) {
	cert, err := tls.X509KeyPair(chainAndKey, chainAndKey)
	if err != nil {
		return nil, errors.New("not a certificate with its key")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil || leaf.IsCA || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errors.New("not a server certificate valid now")
	}
	cert.Leaf = leaf
	return &issuedCert{cert: cert, notAfter: leaf.NotAfter}, nil
}

// GetCertificate is the HTTPS listeners' tls.Config.GetCertificate: the
// Let's Encrypt certificate for a name it covers while it is valid, and
// nothing otherwise, so the listener's own certificate, the self-signed
// one, answers.
func (i *Issued) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := i.current.Load()
	if c == nil || hello.ServerName == "" || !i.now().Before(c.notAfter) || c.cert.Leaf.VerifyHostname(hello.ServerName) != nil {
		return nil, nil
	}
	return &c.cert, nil
}

// Install is the certificate manager's acme.Installer for the panel: it
// checks that the chain and key make a pair valid now for the panel's
// first name, saves them (0600) and serves them from the next handshake. It
// keeps no copy of keyPEM, only the parsed key the listener needs. The
// revision is a counter the manager hands back; the panel has no other.
func (i *Issued) Install(_ context.Context, accountID string, _ uint64, certPEM, keyPEM []byte) (uint64, time.Time, error) {
	if accountID != AccountID {
		return 0, time.Time{}, errors.New("panelcert: the certificate is not the panel's")
	}
	// The chain without a key block, then the key, as the file holds them.
	if bytes.Contains(certPEM, []byte("PRIVATE KEY")) {
		return 0, time.Time{}, errors.New("panelcert: the chain holds a key")
	}
	data := make([]byte, 0, len(certPEM)+len(keyPEM)+1)
	data = append(append(data, bytes.TrimRight(certPEM, "\n")...), '\n')
	data = append(data, keyPEM...)
	defer clear(data)
	c, err := parseIssued(data, i.now())
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("panelcert: the issued certificate is %s", err)
	}
	if c.cert.Leaf.VerifyHostname(i.names[0]) != nil {
		return 0, time.Time{}, fmt.Errorf("panelcert: the issued certificate does not name %s", i.names[0])
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := writePrivate(i.dir, issuedFile, data); err != nil {
		return 0, time.Time{}, fmt.Errorf("panelcert: saving the certificate in %s: %w", i.dir, err)
	}
	i.current.Store(c)
	return i.revision.Add(1), c.notAfter, nil
}

// Site is the panel as the certificate manager sees it: its first name, the
// others as aliases (asked for once they reach this server), and what the
// certificate it serves names.
func (i *Issued) Site() acme.Site {
	s := acme.Site{AccountID: AccountID, Domain: i.names[0], Aliases: slices.Clone(i.names[1:]), Revision: i.revision.Load(), Active: true}
	if c := i.current.Load(); c != nil {
		s.Covered = slices.Clone(c.cert.Leaf.DNSNames)
		s.NotAfter = c.notAfter
	}
	return s
}

// Sites is the certificate manager's acme.Sites for the panel: the panel
// alone.
func (i *Issued) Sites(context.Context) ([]acme.Site, error) {
	return []acme.Site{i.Site()}, nil
}

// NotAfter is the expiry of the certificate the panel has, zero for none.
func (i *Issued) NotAfter() time.Time {
	if c := i.current.Load(); c != nil {
		return c.notAfter
	}
	return time.Time{}
}

// Certificates is what Obtain needs of the certificate manager
// (*acme.Manager).
type Certificates interface {
	Refresh(ctx context.Context, s acme.Site) error
	Reaches(ctx context.Context, domain string) bool
}

// Obtain runs once at start. A certificate that names every panel name and
// has more than 30 days left is kept, and the renewal loop renews it.
// Otherwise it asks the manager for one (Refresh), after waiting up to two
// minutes for the first name to answer on port 80 here: on a fresh start
// the broker may still be loading the web server's config with it. Either
// way it writes one line in plain words: the certificate, or why the panel
// keeps its self-signed one and what to do.
func (i *Issued) Obtain(ctx context.Context, certs Certificates, log io.Writer) {
	if c := i.current.Load(); c != nil && c.notAfter.Sub(i.now()) > 30*24*time.Hour && i.coversAll(c) {
		fmt.Fprintln(log, i.valid(c))
		return
	}
	if !i.waitReachable(ctx, certs) {
		fmt.Fprintf(log, "Panel certificate: %s does not answer on port 80 from this server yet; asking Let's Encrypt anyway.\n", i.names[0])
	}
	if ctx.Err() != nil {
		return
	}
	err := certs.Refresh(ctx, i.Site())
	if err == nil {
		if c := i.current.Load(); c != nil {
			fmt.Fprintln(log, i.valid(c))
			return
		}
	}
	if ctx.Err() != nil {
		return
	}
	fmt.Fprintln(log, explain(err, i.names[0]))
}

// waitReachable reports whether the first name answered within reachWait.
func (i *Issued) waitReachable(ctx context.Context, certs Certificates) bool {
	deadline := time.Now().Add(i.reachWait)
	for !certs.Reaches(ctx, i.names[0]) {
		if !time.Now().Before(deadline) {
			return false
		}
		t := time.NewTimer(i.reachEvery)
		select {
		case <-ctx.Done():
			t.Stop()
			return false
		case <-t.C:
		}
	}
	return true
}

func (i *Issued) coversAll(c *issuedCert) bool {
	for _, n := range i.names {
		if c.cert.Leaf.VerifyHostname(n) != nil {
			return false
		}
	}
	return true
}

func (i *Issued) valid(c *issuedCert) string {
	return fmt.Sprintf("Panel certificate: from Let's Encrypt for %s, valid until %s. The renewal check, 2 minutes after start and then every 12 hours, renews it 30 days before then.",
		strings.Join(c.cert.Leaf.DNSNames, ", "), c.notAfter.UTC().Format(time.DateOnly))
}

// explain says in plain words why the panel has no Let's Encrypt
// certificate for name after err, and what to do. The manager's own line
// before it has the technical details.
func explain(err error, name string) string {
	switch {
	case errors.Is(err, acme.ErrValidation):
		return "Panel certificate: Let's Encrypt could not check " + name + " over http on port 80 of this server, so the panel keeps its self-signed certificate. Point the name's DNS at this server and open TCP port 80 to the internet; the panel asks again within 6 hours."
	case errors.Is(err, acme.ErrRateLimited):
		return "Panel certificate: Let's Encrypt has had too many requests for " + name + " or from this server, so the panel keeps its self-signed certificate. The panel asks again within 6 hours; if this lasts more than a day, read https://letsencrypt.org/docs/rate-limits/."
	case errors.Is(err, acme.ErrInstall):
		return "Panel certificate: Let's Encrypt issued a certificate for " + name + ", but the panel could not save it in its state folder, so it keeps its self-signed certificate. Check that the folder belongs to the panel's user and the disk has room; the panel asks again in a week."
	case errors.Is(err, acme.ErrTooSoon):
		return "Panel certificate: the panel asked Let's Encrypt for " + name + " less than an hour ago, so it does not ask again now and keeps its self-signed certificate. The renewal check asks again within 6 hours of that try."
	}
	return "Panel certificate: Let's Encrypt did not answer or did not issue a certificate for " + name + ", so the panel keeps its self-signed certificate. Check that this server reaches acme-v02.api.letsencrypt.org on port 443; the panel asks again within 6 hours."
}
