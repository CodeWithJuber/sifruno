// Package tlshost stores and inspects TLS certificates for account
// domains — the tls.autossl obligation's storage layer. Truth is PEM files
// under <root>/<domain>.{crt,key,cabundle} with the key at 0600, parsed
// with crypto/x509 on every read so panel answers always reflect real
// certificate material.
package tlshost

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Store is the per-domain certificate store.
type Store struct {
	Root string
}

var domainRe = regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9_-]{1,63}\.)+[a-zA-Z]{2,}\.?$`)

// ValidateDomain rejects anything that is not a plain domain name, so a
// domain can never escape the store root via path traversal.
func ValidateDomain(domain string) error {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if !domainRe.MatchString(d) {
		return errors.New("invalid domain")
	}
	return nil
}

// CertInfo is the parsed truth about one installed certificate.
type CertInfo struct {
	Domain        string   `json:"domain"`
	SubjectCN     string   `json:"subject_cn"`
	IssuerCN      string   `json:"issuer_cn"`
	SANs          []string `json:"sans"`
	NotBefore     int64    `json:"not_before"`
	NotAfter      int64    `json:"not_after"`
	SelfSigned    bool     `json:"self_signed"`
	DaysRemaining int      `json:"days_remaining"`
	Serial        string   `json:"serial"`
}

func (s *Store) paths(domain string) (crt, key, cab string) {
	d := strings.TrimSuffix(strings.ToLower(domain), ".")
	return filepath.Join(s.Root, d+".crt"),
		filepath.Join(s.Root, d+".key"),
		filepath.Join(s.Root, d+".cabundle")
}

// matchDomain reports whether the certificate covers the domain
// (CN or any SAN, with wildcard support).
func matchDomain(cert *x509.Certificate, domain string) bool {
	d := strings.TrimSuffix(strings.ToLower(domain), ".")
	names := append([]string{cert.Subject.CommonName}, cert.DNSNames...)
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == d {
			return true
		}
		if strings.HasPrefix(n, "*.") && strings.HasSuffix(d, n[1:]) && strings.Count(d, ".") == strings.Count(n, ".") {
			return true
		}
	}
	return false
}

// ParseInfo parses a PEM certificate into CertInfo.
func ParseInfo(domain string, crtPEM []byte) (CertInfo, error) {
	block, _ := pem.Decode(crtPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return CertInfo{}, errors.New("no PEM certificate found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return CertInfo{}, fmt.Errorf("certificate parse: %w", err)
	}
	return CertInfo{
		Domain:        strings.TrimSuffix(strings.ToLower(domain), "."),
		SubjectCN:     cert.Subject.CommonName,
		IssuerCN:      cert.Issuer.CommonName,
		SANs:          cert.DNSNames,
		NotBefore:     cert.NotBefore.Unix(),
		NotAfter:      cert.NotAfter.Unix(),
		SelfSigned:    cert.Subject.String() == cert.Issuer.String(),
		DaysRemaining: int(time.Until(cert.NotAfter).Hours() / 24),
		Serial:        cert.SerialNumber.Text(16),
	}, nil
}

// Install validates and stores a certificate/key(/cabundle) set for the
// domain. The key must match the certificate, and the certificate must
// cover the domain — the reference rejects mismatches the same way.
func (s *Store) Install(ctx context.Context, domain string, crtPEM, keyPEM, cabPEM []byte) (CertInfo, error) {
	if err := ValidateDomain(domain); err != nil {
		return CertInfo{}, err
	}
	if len(crtPEM) == 0 || len(keyPEM) == 0 {
		return CertInfo{}, errors.New("certificate and key are required")
	}
	if _, err := tls.X509KeyPair(crtPEM, keyPEM); err != nil {
		return CertInfo{}, fmt.Errorf("certificate and key do not match: %v", err)
	}
	info, err := ParseInfo(domain, crtPEM)
	if err != nil {
		return CertInfo{}, err
	}
	if !matchDomainCert(crtPEM, domain) {
		return CertInfo{}, fmt.Errorf("certificate does not cover %s", domain)
	}
	if len(cabPEM) > 0 {
		if block, _ := pem.Decode(cabPEM); block == nil || block.Type != "CERTIFICATE" {
			return CertInfo{}, errors.New("cabundle contains no PEM certificate")
		}
	}
	if err := os.MkdirAll(s.Root, 0o700); err != nil {
		return CertInfo{}, err
	}
	crt, key, cab := s.paths(domain)
	if err := writeAtomic(crt, crtPEM, 0o644); err != nil {
		return CertInfo{}, err
	}
	if err := writeAtomic(key, keyPEM, 0o600); err != nil {
		return CertInfo{}, err
	}
	if len(cabPEM) > 0 {
		if err := writeAtomic(cab, cabPEM, 0o644); err != nil {
			return CertInfo{}, err
		}
	}
	return info, nil
}

func matchDomainCert(crtPEM []byte, domain string) bool {
	block, _ := pem.Decode(crtPEM)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	return matchDomain(cert, domain)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Info returns the parsed certificate for a domain.
func (s *Store) Info(ctx context.Context, domain string) (CertInfo, error) {
	if err := ValidateDomain(domain); err != nil {
		return CertInfo{}, err
	}
	crt, _, _ := s.paths(domain)
	raw, err := os.ReadFile(crt)
	if errors.Is(err, os.ErrNotExist) {
		return CertInfo{}, fmt.Errorf("no certificate installed for %s", domain)
	}
	if err != nil {
		return CertInfo{}, err
	}
	return ParseInfo(domain, raw)
}

// KeyPair returns the PEM cert+key for serving a domain (used by the web
// surface when vhost TLS lands).
func (s *Store) KeyPair(ctx context.Context, domain string) (crtPEM, keyPEM []byte, err error) {
	if err := ValidateDomain(domain); err != nil {
		return nil, nil, err
	}
	crt, key, _ := s.paths(domain)
	crtPEM, err = os.ReadFile(crt)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = os.ReadFile(key)
	if err != nil {
		return nil, nil, err
	}
	return crtPEM, keyPEM, nil
}

// List returns all installed certificates.
func (s *Store) List(ctx context.Context) ([]CertInfo, error) {
	entries, err := os.ReadDir(s.Root)
	if errors.Is(err, os.ErrNotExist) {
		return []CertInfo{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []CertInfo{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".crt") {
			continue
		}
		domain := strings.TrimSuffix(e.Name(), ".crt")
		info, err := s.Info(ctx, domain)
		if err != nil {
			continue // skip unreadable entries rather than fail the listing
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out, nil
}

// Delete removes a domain's certificate set.
func (s *Store) Delete(ctx context.Context, domain string) error {
	if err := ValidateDomain(domain); err != nil {
		return err
	}
	crt, key, cab := s.paths(domain)
	removed := false
	for _, p := range []string{crt, key, cab} {
		if err := os.Remove(p); err == nil {
			removed = true
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if !removed {
		return fmt.Errorf("no certificate installed for %s", domain)
	}
	return nil
}
