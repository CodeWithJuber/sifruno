package hostaccounts

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"strings"
	"time"

	"sifruno/internal/olsweb"
)

// The certificate operation installs a finished certificate and key for an
// account's live site. The broker never runs ACME: the panel obtains the
// certificate, and the broker checks it, stages it, journals the intent and
// installs it with the rendered OpenLiteSpeed config, tested before a
// graceful restart, as the web operation does. It needs the web operation on.

// CertificateInput is a certificate chain (leaf first, 1 to 4 certificates)
// and its private key for the account's own domain and any of its aliases,
// each PEM at most 64 KiB.
type CertificateInput struct {
	ExpectedRevision uint64 `json:"expected_revision"`
	CertPEM          string `json:"cert_pem"`
	KeyPEM           string `json:"key_pem"`
	Reason           string `json:"reason"`
}

// CertificateState names an installed certificate by its leaf. The zero
// value means none.
type CertificateState struct {
	NotAfter    int64  `json:"not_after"`   // Unix seconds of the leaf's NotAfter
	Fingerprint string `json:"fingerprint"` // SHA-256 of the leaf DER, lowercase hex
	// Names are the leaf's DNS names, sorted and joined with commas, each
	// one of the site's domains when it was installed. Empty for a
	// certificate installed before the broker kept them: it named the
	// account's own domain. A string, so an Account stays comparable.
	Names string `json:"names,omitempty"`
}

type CertificateResult struct {
	Account     Account          `json:"account"`
	Certificate CertificateState `json:"certificate"`
}

// CertificateService is implemented by the client; the broker serves it from
// its store.
type CertificateService interface {
	SetCertificate(ctx context.Context, id string, in CertificateInput, actor string) (CertificateResult, error)
}

// ErrCertificateRejected means a well-formed certificate does not fit the
// site now: its leaf does not name the account's domain, names a name the
// site does not have, or it is expired or not yet valid. Nothing was
// journaled or changed.
var ErrCertificateRejected = errors.New("certificate rejected")

const (
	maxCertificatePEM    = 64 << 10
	maxChainCertificates = 4
	// maxCertificateRequestBytes fits two PEMs of the largest size with their
	// newlines escaped in JSON, plus the reason, the actor and the keys.
	maxCertificateRequestBytes = 160 << 10
)

// File names in olsweb.TLSRoot. A site's files are in its own directory,
// olsweb.TLSRoot/<site name>/; the listener's are in olsweb.TLSRoot itself.
const (
	siteCertFile = "cert.pem" // full chain, leaf first
	siteKeyFile  = "key.pem"
	// The staged pair is written before the intent is journaled, so an
	// interrupted install is finished from it. OpenLiteSpeed never reads it.
	stagedCertFile   = "cert.pem.next"
	stagedKeyFile    = "key.pem.next"
	listenerCertFile = "listener.crt"
	listenerKeyFile  = "listener.key"
)

var (
	certificateFingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	certificateDigestPattern      = regexp.MustCompile(`^sha256=[0-9a-f]{64};not_after=[1-9][0-9]{0,18}$`)
)

func (c CertificateState) installed() bool { return c.Fingerprint != "" }

func validCertificateState(c CertificateState) bool {
	return c.NotAfter > 0 && certificateFingerprintPattern.MatchString(c.Fingerprint) && (c.Names == "" || validCertificateNames(c.Names))
}

// certificateDigest is the journal target for a certificate operation.
func certificateDigest(c CertificateState) string {
	return fmt.Sprintf("sha256=%s;not_after=%d", c.Fingerprint, c.NotAfter)
}

// validCertificateInput checks the parts of a request that need no parsing.
func validCertificateInput(in CertificateInput, actor string) bool {
	return in.ExpectedRevision != 0 && in.CertPEM != "" && in.KeyPEM != "" && len(in.CertPEM) <= maxCertificatePEM && len(in.KeyPEM) <= maxCertificatePEM && validText(in.Reason, 500) && validText(actor, 120)
}

// siteTLS names a site's certificate files as OpenLiteSpeed reads them.
func siteTLS(name string) olsweb.TLS {
	dir := olsweb.TLSRoot + "/" + name
	return olsweb.TLS{CertFile: dir + "/" + siteCertFile, KeyFile: dir + "/" + siteKeyFile}
}

// certificateBundle is a checked chain and key in the canonical form the
// broker writes: each certificate re-encoded from its DER, leaf first, and
// the key as PKCS #8. No other text the caller sent reaches a file.
type certificateBundle struct {
	leaf     *x509.Certificate
	chainPEM []byte
	keyPEM   []byte
	state    CertificateState
}

// parseCertificate checks the form of a chain and key; every failure is
// ErrInvalid. Each PEM is at most 64 KiB with nothing but whitespace around
// its blocks. The chain is 1 to 4 CERTIFICATE blocks without headers, each
// signed by the next, so the leaf comes first. When the leaf lists extended
// key usages, serverAuth is one. The key is one block that matches the
// leaf's public key. Whether the leaf fits the account is checked by fits.
func parseCertificate(certPEM, keyPEM string) (certificateBundle, error) {
	if certPEM == "" || keyPEM == "" || len(certPEM) > maxCertificatePEM || len(keyPEM) > maxCertificatePEM {
		return certificateBundle{}, ErrInvalid
	}
	blocks, ok := pemBlocks([]byte(certPEM))
	if !ok || len(blocks) < 1 || len(blocks) > maxChainCertificates {
		return certificateBundle{}, ErrInvalid
	}
	chain := make([]*x509.Certificate, 0, len(blocks))
	var chainPEM bytes.Buffer
	for _, b := range blocks {
		if b.Type != "CERTIFICATE" || len(b.Headers) != 0 {
			return certificateBundle{}, ErrInvalid
		}
		c, e := x509.ParseCertificate(b.Bytes)
		if e != nil {
			return certificateBundle{}, ErrInvalid
		}
		chain = append(chain, c)
		if pem.Encode(&chainPEM, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}) != nil {
			return certificateBundle{}, ErrInvalid
		}
	}
	// CheckSignatureFrom also requires the signer to be a CA, so a chain in
	// any other order fails here.
	for i := 0; i+1 < len(chain); i++ {
		if chain[i].CheckSignatureFrom(chain[i+1]) != nil {
			return certificateBundle{}, ErrInvalid
		}
	}
	leaf := chain[0]
	if (len(leaf.ExtKeyUsage) > 0 || len(leaf.UnknownExtKeyUsage) > 0) && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return certificateBundle{}, ErrInvalid
	}
	keys, ok := pemBlocks([]byte(keyPEM))
	if !ok || len(keys) != 1 || len(keys[0].Headers) != 0 {
		return certificateBundle{}, ErrInvalid
	}
	key, ok := parsePrivateKey(keys[0])
	if !ok || !samePublicKey(key, leaf.PublicKey) {
		return certificateBundle{}, ErrInvalid
	}
	pkcs8, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return certificateBundle{}, ErrInvalid
	}
	sum := sha256.Sum256(leaf.Raw)
	state := CertificateState{NotAfter: leaf.NotAfter.Unix(), Fingerprint: hex.EncodeToString(sum[:])}
	names := slices.Sorted(slices.Values(leaf.DNSNames))
	if joined := strings.Join(names, ","); validCertificateNames(joined) {
		state.Names = joined
	}
	return certificateBundle{
		leaf:     leaf,
		chainPEM: chainPEM.Bytes(),
		keyPEM:   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
		state:    state,
	}, nil
}

// fits returns ErrCertificateRejected unless the leaf's names are exactly
// domains the site has: DNS names only (no IP address, email or URI), each
// one of domains, each once, the account's own domain (primary) among them
// (the common name is ignored, and a wildcard is no site's domain), and
// NotBefore <= now < NotAfter. A domain of the site that the leaf leaves out
// is served over http only (its DNS may not point here yet).
func (b certificateBundle) fits(domains []string, primary string, now time.Time) error {
	leaf := b.leaf
	if len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 0 || b.state.Names == "" {
		return ErrCertificateRejected
	}
	for _, name := range leaf.DNSNames {
		if !slices.Contains(domains, name) {
			return ErrCertificateRejected
		}
	}
	if !slices.Contains(leaf.DNSNames, primary) || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return ErrCertificateRejected
	}
	return nil
}

// stagedIsJournaled reports whether a re-read staged pair is the certificate
// its intent journaled: the same leaf (fingerprint and expiry), and the same
// names unless the intent was journaled by a broker that kept none. An
// install interrupted across that upgrade is then finished, not left
// pending, which would hold up every account.
func stagedIsJournaled(staged, journaled CertificateState) bool {
	return staged.Fingerprint == journaled.Fingerprint && staged.NotAfter == journaled.NotAfter && (journaled.Names == "" || staged.Names == journaled.Names)
}

// validCertificateNames checks a certificate's names as the record holds
// them: 1 to olsweb.MaxDomainsPerSite valid domains, sorted, each once,
// joined with commas.
func validCertificateNames(s string) bool {
	names := strings.Split(s, ",")
	if s == "" || len(names) > olsweb.MaxDomainsPerSite {
		return false
	}
	for i, name := range names {
		if !validDomain(name) || (i > 0 && names[i-1] >= name) {
			return false
		}
	}
	return true
}

// coveredDomains are the site's domains its certificate names, in the
// site's order: those in state.Names, or the account's own domain alone for
// a certificate recorded before the broker kept its names (fits required
// the domain then). The account's own domain is always one of them.
func coveredDomains(state CertificateState, domains []string, primary string) []string {
	if state.Names == "" {
		return []string{primary}
	}
	names := strings.Split(state.Names, ",")
	out := []string{}
	for _, d := range domains {
		if slices.Contains(names, d) {
			out = append(out, d)
		}
	}
	if !slices.Contains(out, primary) {
		out = append([]string{primary}, out...)
	}
	return out
}

// pemBlocks splits data into PEM blocks. Anything but whitespace before,
// between or after them makes the whole input invalid.
func pemBlocks(data []byte) ([]*pem.Block, bool) {
	begin := []byte("-----BEGIN ")
	var blocks []*pem.Block
	for rest := bytes.TrimSpace(data); len(rest) > 0; rest = bytes.TrimSpace(rest) {
		if !bytes.HasPrefix(rest, begin) {
			return nil, false
		}
		b, next := pem.Decode(rest)
		if b == nil {
			return nil, false
		}
		blocks = append(blocks, b)
		rest = next
	}
	// pem.Decode passes over a malformed block to the next one; equal counts
	// show that it skipped none.
	if bytes.Count(data, begin) != len(blocks) {
		return nil, false
	}
	return blocks, true
}

// parsePrivateKey accepts an EC key on P-256 or P-384 (SEC 1 or PKCS #8) or
// an RSA key of 2048 to 4096 bits (PKCS #1 or PKCS #8).
func parsePrivateKey(b *pem.Block) (crypto.Signer, bool) {
	var key any
	var e error
	switch b.Type {
	case "EC PRIVATE KEY":
		key, e = x509.ParseECPrivateKey(b.Bytes)
	case "RSA PRIVATE KEY":
		key, e = x509.ParsePKCS1PrivateKey(b.Bytes)
	case "PRIVATE KEY":
		key, e = x509.ParsePKCS8PrivateKey(b.Bytes)
	default:
		return nil, false
	}
	if e != nil {
		return nil, false
	}
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return nil, false
		}
		return k, true
	case *rsa.PrivateKey:
		if bits := k.N.BitLen(); bits < 2048 || bits > 4096 {
			return nil, false
		}
		return k, true
	}
	return nil, false
}

func samePublicKey(key crypto.Signer, pub crypto.PublicKey) bool {
	k, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	return ok && k.Equal(pub)
}

// newListenerCertificate makes the secure listener's default certificate:
// self-signed, CN "sifruno", ECDSA P-256, valid for ten years. OpenLiteSpeed
// needs one for the listener; a client only sees it when its name matches no
// site, and nothing trusts it.
func newListenerCertificate(now time.Time) (certPEM, keyPEM []byte, err error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, nil, ErrUnavailable
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return nil, nil, ErrUnavailable
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "sifruno"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		return nil, nil, ErrUnavailable
	}
	pkcs8, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, nil, ErrUnavailable
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), nil
}

// listenerCertificateUsable reports whether a stored listener pair can stay:
// one certificate and an ECDSA P-256 key that match, valid at now.
func listenerCertificateUsable(certPEM, keyPEM []byte, now time.Time) bool {
	certs, ok := pemBlocks(certPEM)
	if !ok || len(certs) != 1 || certs[0].Type != "CERTIFICATE" {
		return false
	}
	keys, ok := pemBlocks(keyPEM)
	if !ok || len(keys) != 1 {
		return false
	}
	cert, e := x509.ParseCertificate(certs[0].Bytes)
	if e != nil {
		return false
	}
	key, ok := parsePrivateKey(keys[0])
	if !ok {
		return false
	}
	if ec, isEC := key.(*ecdsa.PrivateKey); !isEC || ec.Curve != elliptic.P256() {
		return false
	}
	return samePublicKey(key, cert.PublicKey) && !now.Before(cert.NotBefore) && now.Before(cert.NotAfter)
}
