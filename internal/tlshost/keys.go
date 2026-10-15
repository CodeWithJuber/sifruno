package tlshost

// tls.autossl batch 2: real key and CSR generation (SSL::generate_key /
// generate_csr / list_keys / list_csrs / delete_key / delete_csr).
// Keys are ECDSA P-256 (modern default; the reference offers RSA-2048 —
// documented delta). Storage: <root>/_keys/<account>/<id>.pem and
// <root>/_csrs/<account>/<id>.pem, 0600.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var accountRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$`)

// KeyInfo describes one stored private key.
type KeyInfo struct {
	ID      string `json:"id"`   // first 16 hex chars of the DER sha256
	Type    string `json:"type"` // "ECDSA P-256"
	Created int64  `json:"created"`
}

// CSRInfo describes one stored certificate signing request.
type CSRInfo struct {
	ID      string   `json:"id"`
	Domains []string `json:"domains"`
	Created int64    `json:"created"`
	KeyID   string   `json:"key_id"`
}

func (s *Store) keyDir(account string) string {
	return filepath.Join(s.Root, "_keys", account)
}
func (s *Store) csrDir(account string) string {
	return filepath.Join(s.Root, "_csrs", account)
}

func validateAccount(account string) error {
	if !accountRe.MatchString(account) {
		return errors.New("invalid account name")
	}
	return nil
}

// GenerateKey creates a new EC P-256 private key for the account and
// returns its identity. The PEM is stored 0600.
func (s *Store) GenerateKey(account string) (KeyInfo, error) {
	if err := validateAccount(account); err != nil {
		return KeyInfo{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return KeyInfo{}, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return KeyInfo{}, err
	}
	sum := sha256.Sum256(der)
	id := hex.EncodeToString(sum[:8])
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.MkdirAll(s.keyDir(account), 0o700); err != nil {
		return KeyInfo{}, err
	}
	path := filepath.Join(s.keyDir(account), id+".pem")
	if err := writeAtomic(path, pemBytes, 0o600); err != nil {
		return KeyInfo{}, err
	}
	fi, _ := os.Stat(path)
	return KeyInfo{ID: id, Type: "ECDSA P-256", Created: fi.ModTime().Unix()}, nil
}

// GenerateCSR creates a CSR for the domains using the account's key
// (keyID). Email is optional but validated when present.
func (s *Store) GenerateCSR(account, keyID string, domains []string, email string) (CSRInfo, error) {
	if err := validateAccount(account); err != nil {
		return CSRInfo{}, err
	}
	if len(domains) == 0 {
		return CSRInfo{}, errors.New("at least one domain is required")
	}
	clean := []string{}
	for _, d := range domains {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if err := ValidateDomain(strings.TrimPrefix(d, "*.")); err != nil && !strings.HasPrefix(d, "*.") {
			return CSRInfo{}, fmt.Errorf("invalid domain %q", d)
		}
		clean = append(clean, d)
	}
	if email != "" {
		if _, err := mail.ParseAddress(email); err != nil {
			return CSRInfo{}, fmt.Errorf("invalid email: %v", err)
		}
	}
	keyPath := filepath.Join(s.keyDir(account), keyID+".pem")
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return CSRInfo{}, fmt.Errorf("key not found: %s", keyID)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return CSRInfo{}, errors.New("stored key is not PEM")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return CSRInfo{}, err
	}
	tpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: clean[0]},
		DNSNames: clean,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tpl, key)
	if err != nil {
		return CSRInfo{}, err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return CSRInfo{}, err
	}
	if err := csr.CheckSignature(); err != nil {
		return CSRInfo{}, fmt.Errorf("CSR self-signature invalid: %w", err)
	}
	sum := sha256.Sum256(csrDER)
	id := hex.EncodeToString(sum[:8])
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	if err := os.MkdirAll(s.csrDir(account), 0o700); err != nil {
		return CSRInfo{}, err
	}
	if err := writeAtomic(filepath.Join(s.csrDir(account), id+".pem"), csrPEM, 0o600); err != nil {
		return CSRInfo{}, err
	}
	return CSRInfo{ID: id, Domains: clean, Created: csrPEMTime(s.csrDir(account), id), KeyID: keyID}, nil
}

func csrPEMTime(dir, id string) int64 {
	fi, err := os.Stat(filepath.Join(dir, id+".pem"))
	if err != nil {
		return 0
	}
	return fi.ModTime().Unix()
}

// ListKeys returns the account's stored keys.
func (s *Store) ListKeys(account string) ([]KeyInfo, error) {
	if err := validateAccount(account); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.keyDir(account))
	if errors.Is(err, os.ErrNotExist) {
		return []KeyInfo{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []KeyInfo{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".pem") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, KeyInfo{ID: strings.TrimSuffix(e.Name(), ".pem"), Type: "ECDSA P-256", Created: fi.ModTime().Unix()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ListCSRs returns the account's stored CSRs (domains parsed from PEM).
func (s *Store) ListCSRs(account string) ([]CSRInfo, error) {
	if err := validateAccount(account); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.csrDir(account))
	if errors.Is(err, os.ErrNotExist) {
		return []CSRInfo{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []CSRInfo{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".pem") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(s.csrDir(account), e.Name()))
		if err != nil {
			continue
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			continue
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			continue
		}
		fi, _ := e.Info()
		out = append(out, CSRInfo{
			ID:      strings.TrimSuffix(e.Name(), ".pem"),
			Domains: csr.DNSNames,
			Created: fi.ModTime().Unix(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// DeleteKey removes one of the account's keys.
func (s *Store) DeleteKey(account, id string) error {
	return s.deleteID(s.keyDir(account), account, id, "key")
}

// DeleteCSR removes one of the account's CSRs.
func (s *Store) DeleteCSR(account, id string) error {
	return s.deleteID(s.csrDir(account), account, id, "CSR")
}

var idRe = regexp.MustCompile(`^[0-9a-f]{16}$`)

func (s *Store) deleteID(dir, account, id, kind string) error {
	if err := validateAccount(account); err != nil {
		return err
	}
	if !idRe.MatchString(id) {
		return fmt.Errorf("invalid %s id", kind)
	}
	path := filepath.Join(dir, id+".pem")
	if err := os.Remove(path); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s not found: %s", kind, id)
	} else if err != nil {
		return err
	}
	return nil
}

// CSRPEM returns the raw PEM for a CSR (for submission to a CA).
func (s *Store) CSRPEM(account, id string) ([]byte, error) {
	if err := validateAccount(account); err != nil {
		return nil, err
	}
	if !idRe.MatchString(id) {
		return nil, errors.New("invalid CSR id")
	}
	return os.ReadFile(filepath.Join(s.csrDir(account), id+".pem"))
}

// PurgeAccount removes an account's key and CSR directories (removeacct hook).
func (s *Store) PurgeAccount(account string) error {
	if err := validateAccount(account); err != nil {
		return err
	}
	for _, d := range []string{s.keyDir(account), s.csrDir(account)} {
		if err := os.RemoveAll(d); err != nil {
			return err
		}
	}
	return nil
}
