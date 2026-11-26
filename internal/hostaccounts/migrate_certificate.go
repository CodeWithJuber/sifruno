package hostaccounts

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"sifruno/internal/cpsource"
)

// Copying the old site's certificate (README, Migration): when a site moves
// here, the broker reads the certificate, private key and CA bundle the old
// server's virtual host serves for the account's domain
// (cpsource.VhostSSLCommand over SSH, or the panel's copy of WHM's answer
// for a WHM migration), checks them, and installs them through the
// certificate operation's own steps (installCertificate: staged, journaled,
// tested with the web server's config), so the moved site answers https
// before its DNS changes. A certificate that cannot be used is left on the
// old server: the answer says why, nothing changes here, and the move goes
// on. The key is never logged, journaled or answered: it reaches the staged
// pair and the site's live files only, as an issued certificate's does.

// MigrateCertificateInput copies the old site's certificate into the live
// site of the account of the same name and domain.
type MigrateCertificateInput struct {
	Migration        string         `json:"migration"`
	ExpectedRevision uint64         `json:"expected_revision"`
	CPanel           *CPanelAnswers `json:"cpanel,omitempty"`
	Reason           string         `json:"reason"`
}

// MigrateCertificateResult says whether the certificate was copied. When it
// was, Certificate is the one installed, Issuer the authority that issued
// it, and Revision the account's new revision. When it was not, Refused
// names why: no_certificate, self_signed, not_yet_valid, expired,
// expires_soon (less than 7 days left), other_domain, untrusted (no
// authority this server trusts vouches for it), key_mismatch or unusable;
// Detail says it in plain words, and Revision is the account's unchanged
// one. It never holds the key.
type MigrateCertificateResult struct {
	Copied      bool             `json:"copied"`
	Certificate CertificateState `json:"certificate"`
	Issuer      string           `json:"issuer,omitempty"`
	Revision    uint64           `json:"revision"`
	Refused     string           `json:"refused,omitempty"`
	Detail      string           `json:"detail,omitempty"`
}

// minCopiedValidity is how long a copied certificate must still be valid:
// one that runs out sooner would lapse right after the move, before the
// panel's renewal loop can replace it.
const minCopiedValidity = 7 * 24 * time.Hour

func validMigrateCertificate(in MigrateCertificateInput, actor string) bool {
	return idPattern.MatchString(in.Migration) && in.ExpectedRevision > 0 && validText(in.Reason, 500) && validText(actor, 120)
}

// certificateRefusal is why a certificate from the old server is not
// copied: a code and plain words, which never quote the key.
type certificateRefusal struct {
	Code   string
	Detail string
}

func refuseCopy(code, detail string) (certificateBundle, *certificateRefusal) {
	return certificateBundle{}, &certificateRefusal{Code: code, Detail: installDetail([]byte(detail))}
}

// copiedCertificate checks the old site's certificate for domain and
// returns it in the form the certificate operation installs: the leaf and
// the intermediates of its path to a root in roots (nil: this system's
// trust store), leaf first, the root left out, and the key as PKCS #8. It
// refuses, in this order: text that is not PEM certificates, a self-signed
// leaf, one not valid now or for 7 days more, one that does not cover
// domain as a browser checks it, one no authority in roots vouches for
// through the certificate's own text and the CA bundle (in any order;
// certificates off the path are left out), a path longer than 4
// certificates, and a key that is not PEM, not of a kind the broker
// installs, or not the leaf's.
func copiedCertificate(ssl cpsource.VhostSSL, domain string, roots *x509.CertPool, now time.Time) (certificateBundle, *certificateRefusal) {
	given, ok := pemCertificates(ssl.Certificate)
	if !ok || len(given) == 0 {
		return refuseCopy("unusable", "Its certificate text could not be read.")
	}
	leaf := given[0]
	intermediates := x509.NewCertPool()
	for _, c := range given[1:] {
		intermediates.AddCert(c)
	}
	if strings.TrimSpace(ssl.CABundle) != "" {
		bundle, ok := pemCertificates(ssl.CABundle)
		if !ok {
			return refuseCopy("unusable", "Its CA bundle could not be read.")
		}
		for _, c := range bundle {
			intermediates.AddCert(c)
		}
	}
	if selfSigned(leaf) {
		return refuseCopy("self_signed", "It is self-signed, so visitors' browsers would warn about it.")
	}
	switch {
	case now.Before(leaf.NotBefore):
		return refuseCopy("not_yet_valid", "It is valid only from "+day(leaf.NotBefore)+".")
	case !now.Before(leaf.NotAfter):
		return refuseCopy("expired", "It expired on "+day(leaf.NotAfter)+".")
	case leaf.NotAfter.Sub(now) < minCopiedValidity:
		return refuseCopy("expires_soon", "It expires on "+day(leaf.NotAfter)+", in less than 7 days.")
	}
	if leaf.VerifyHostname(domain) != nil {
		return refuseCopy("other_domain", "It is for "+leafNames(leaf)+", not "+domain+".")
	}
	chains, err := leaf.Verify(x509.VerifyOptions{DNSName: domain, Intermediates: intermediates, Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if err != nil || len(chains) == 0 {
		return refuseCopy("untrusted", "No certificate authority this server trusts vouches for it (it names "+issuerName(leaf)+" as its issuer), so visitors' browsers would warn about it.")
	}
	chain := chains[0]
	for _, c := range chains[1:] {
		if len(c) < len(chain) {
			chain = c
		}
	}
	// The root ends every verified chain; visitors have their own copy.
	served := chain[:len(chain)-1]
	if len(served) > maxChainCertificates {
		return refuseCopy("unusable", "Its chain is longer than the 4 certificates this server installs.")
	}
	keys, ok := pemBlocks([]byte(ssl.Key))
	if !ok || len(keys) != 1 || len(keys[0].Headers) != 0 {
		return refuseCopy("unusable", "Its private key could not be read.")
	}
	key, ok := parsePrivateKey(keys[0])
	if !ok {
		return refuseCopy("unusable", "Its private key is not of a kind this server installs: an RSA key of 2048 to 4096 bits, or an ECDSA P-256 or P-384 key.")
	}
	if !samePublicKey(key, leaf.PublicKey) {
		return refuseCopy("key_mismatch", "Its private key on the old server does not match it.")
	}
	var chainPEM bytes.Buffer
	for _, c := range served {
		if pem.Encode(&chainPEM, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}) != nil {
			return refuseCopy("unusable", "Its certificate text could not be read.")
		}
	}
	b, err := parseCertificate(chainPEM.String(), ssl.Key)
	if err != nil {
		return refuseCopy("unusable", "It does not have the form this server installs.")
	}
	return b, nil
}

// pemCertificates reads PEM text that holds certificates only, each a
// CERTIFICATE block without headers.
func pemCertificates(text string) ([]*x509.Certificate, bool) {
	blocks, ok := pemBlocks([]byte(text))
	if !ok || len(blocks) > 16 {
		return nil, false
	}
	out := make([]*x509.Certificate, 0, len(blocks))
	for _, b := range blocks {
		if b.Type != "CERTIFICATE" || len(b.Headers) != 0 {
			return nil, false
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, false
		}
		out = append(out, c)
	}
	return out, true
}

// selfSigned reports a certificate that names itself as its issuer and is
// signed by its own key.
func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

func day(t time.Time) string { return t.UTC().Format(time.DateOnly) }

// leafNames are the first five DNS names a certificate names, for a
// refusal's words.
func leafNames(c *x509.Certificate) string {
	names := c.DNSNames
	more := ""
	if len(names) > 5 {
		names, more = names[:5], " and more"
	}
	if len(names) == 0 {
		return "no domain name"
	}
	return strings.Join(names, ", ") + more
}

// issuerName is the issuing authority's common name, or its organization.
func issuerName(c *x509.Certificate) string {
	name := c.Issuer.CommonName
	if name == "" && len(c.Issuer.Organization) > 0 {
		name = c.Issuer.Organization[0]
	}
	if name = installDetail([]byte(name)); len(name) > 100 {
		name = name[:100]
	}
	if name == "" {
		return "an unnamed authority"
	}
	return name
}

// migrateCertificate copies the old site's certificate into the account's
// live site. The old server is first checked to have the account of the
// same name with the account's own domain, as for the copy of its files;
// then it is asked for the certificate of that domain's virtual host,
// which copiedCertificate checks and installCertificate installs with the
// rule fitsCopy. A certificate that cannot be used, or none, is answered
// with Copied false and the reason, and changes nothing.
func (s *store) migrateCertificate(ctx context.Context, id string, in MigrateCertificateInput, actor string) (MigrateCertificateResult, error) {
	if snapshotReentry(ctx, s) {
		return MigrateCertificateResult{}, ErrConflict
	}
	if ctx == nil || !idPattern.MatchString(id) || !validMigrateCertificate(in, actor) {
		return MigrateCertificateResult{}, ErrInvalid
	}
	m, err := s.lockedMigration(in.Migration)
	if err != nil {
		return MigrateCertificateResult{}, err
	}
	// The account as it is now; the install checks it again under the
	// lock, after the old server has answered.
	s.mu.Lock()
	r, err := s.recordByID(id)
	s.mu.Unlock()
	switch {
	case err != nil:
		return MigrateCertificateResult{}, err
	case s.web == nil:
		return MigrateCertificateResult{}, ErrUnavailable
	case r.Account.Revision != in.ExpectedRevision || r.Account.State != "active" || !r.Web.enabled():
		return MigrateCertificateResult{}, ErrConflict
	}
	work, cancel := backupContext(ctx, 2*migrateRemoteTimeout)
	defer cancel()
	if _, _, err = s.lockedSourceSite(work, m, r.Account.Username, r.Account.Domain, in.CPanel); err != nil {
		return MigrateCertificateResult{}, err
	}
	command, err := cpsource.VhostSSLCommand(r.Account.Domain)
	if err != nil {
		return MigrateCertificateResult{}, ErrInvalid
	}
	out, err := s.cpanelAnswer(work, m, in.CPanel, func(a *CPanelAnswers) json.RawMessage { return a.SSL }, command)
	if err != nil {
		return MigrateCertificateResult{}, err
	}
	ssl, err := cpsource.ParseVhostSSL(out, r.Account.Domain)
	clear(out)
	unchanged := MigrateCertificateResult{Revision: r.Account.Revision}
	switch {
	case errors.Is(err, cpsource.ErrNoCertificate):
		unchanged.Refused, unchanged.Detail = "no_certificate", "The old server has no certificate for "+r.Account.Domain+"."
		return unchanged, nil
	case err != nil:
		return MigrateCertificateResult{}, &MigrationError{Step: "cpanel_output", Detail: "The old server's certificate for the site could not be read (whmapi1 fetch_vhost_ssl_components)."}
	}
	bundle, refusal := copiedCertificate(ssl, r.Account.Domain, s.certRoots, time.Now())
	if refusal != nil {
		unchanged.Refused, unchanged.Detail = refusal.Code, refusal.Detail
		return unchanged, nil
	}
	defer clear(bundle.keyPEM)
	fits := func(_ []string, primary string, now time.Time) error { return bundle.fitsCopy(primary, now) }
	s.mu.Lock()
	res, err := s.installCertificate(ctx, id, in.ExpectedRevision, bundle, fits, actor, in.Reason)
	s.mu.Unlock()
	if err != nil {
		return MigrateCertificateResult{}, err
	}
	return MigrateCertificateResult{Copied: true, Certificate: res.Certificate, Issuer: issuerName(bundle.leaf), Revision: res.Account.Revision}, nil
}
