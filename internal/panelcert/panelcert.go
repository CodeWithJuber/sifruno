// Package panelcert provides the certificate the panel serves over HTTPS: the
// operator's own files when given, otherwise a self-signed certificate kept in
// the private state directory, and, for the panel's public DNS names, one
// from Let's Encrypt that internal/acme gets and renews (letsencrypt.go).
package panelcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"sifruno/internal/securestate"
)

const (
	certFile    = "panel-cert.pem"
	keyFile     = "panel-key.pem"
	maxPEMBytes = 64 << 10
	lifetime    = 397 * 24 * time.Hour
	renewBefore = 30 * 24 * time.Hour
)

var dnsName = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidHost accepts a DNS name or an IP address the panel answers for.
func ValidHost(h string) bool {
	if net.ParseIP(h) != nil {
		return true
	}
	return len(h) <= 253 && h == strings.ToLower(h) && dnsName.MatchString(h)
}

// Result is the certificate to serve and what to tell the operator about it.
type Result struct {
	Certificate tls.Certificate
	Fingerprint string // SHA-256 of the certificate, as browsers show it
	SelfSigned  bool
	NotAfter    time.Time
}

// Load returns the operator's certificate when both files are given; it must
// cover every panel host. Otherwise it reuses or creates the self-signed one
// in stateDir/tls, replacing it when a host changed or expiry is near.
func Load(stateDir, operatorCert, operatorKey string, hosts []string, now time.Time) (Result, error) {
	if len(hosts) == 0 {
		return Result{}, errors.New("no panel host names")
	}
	for _, h := range hosts {
		if !ValidHost(h) {
			return Result{}, fmt.Errorf("invalid panel host name %q", h)
		}
	}
	if (operatorCert == "") != (operatorKey == "") {
		return Result{}, errors.New("give both --tls-cert and --tls-key, or neither")
	}
	if operatorCert != "" {
		cert, err := tls.LoadX509KeyPair(operatorCert, operatorKey)
		if err != nil {
			return Result{}, fmt.Errorf("TLS certificate or key unreadable: %w", err)
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return Result{}, errors.New("TLS certificate unreadable")
		}
		for _, h := range hosts {
			if leaf.VerifyHostname(h) != nil {
				return Result{}, fmt.Errorf("the TLS certificate does not cover panel host %s", h)
			}
		}
		if !now.Before(leaf.NotAfter) {
			return Result{}, errors.New("the TLS certificate has expired")
		}
		return Result{Certificate: cert, Fingerprint: fingerprint(leaf.Raw), NotAfter: leaf.NotAfter}, nil
	}
	dir, err := securestate.Dir(filepath.Join(stateDir, "tls"))
	if err != nil {
		return Result{}, errors.New("panel TLS state unavailable")
	}
	if r, ok := reuse(dir, hosts, now); ok {
		return r, nil
	}
	return create(dir, hosts, now)
}

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

func reuse(dir string, hosts []string, now time.Time) (Result, bool) {
	certPEM, err1 := readPrivate(filepath.Join(dir, certFile))
	keyPEM, err2 := readPrivate(filepath.Join(dir, keyFile))
	if err1 != nil || err2 != nil {
		return Result{}, false
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return Result{}, false
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	// Replace anything that is not exactly what create makes and still valid.
	if err != nil || now.Before(leaf.NotBefore) || now.Add(renewBefore).After(leaf.NotAfter) || !sameHosts(leaf, hosts) ||
		leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) != nil || leaf.IsCA {
		return Result{}, false
	}
	return Result{Certificate: cert, Fingerprint: fingerprint(leaf.Raw), SelfSigned: true, NotAfter: leaf.NotAfter}, true
}

// sameHosts requires exactly the configured names, so a removed host name is
// not left in the certificate.
func sameHosts(leaf *x509.Certificate, hosts []string) bool {
	want := map[string]bool{}
	for _, h := range hosts {
		want[h] = true
	}
	got := map[string]bool{}
	for _, n := range leaf.DNSNames {
		got[n] = true
	}
	for _, ip := range leaf.IPAddresses {
		got[ip.String()] = true
	}
	if len(got) != len(want) {
		return false
	}
	for h := range want {
		key := h
		if ip := net.ParseIP(h); ip != nil {
			key = ip.String()
		}
		if !got[key] {
			return false
		}
	}
	return true
}

func create(dir string, hosts []string, now time.Time) (Result, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Result{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return Result{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Sifruno panel", Organization: []string{"Sifruno self-signed"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(lifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return Result{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Result{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	// The key is written first: a crash between the two renames leaves a
	// pair that does not match, which the next start replaces.
	if err := writePrivate(dir, keyFile, keyPEM); err != nil {
		return Result{}, err
	}
	if err := writePrivate(dir, certFile, certPEM); err != nil {
		return Result{}, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return Result{}, err
	}
	return Result{Certificate: cert, Fingerprint: fingerprint(der), SelfSigned: true, NotAfter: tmpl.NotAfter}, nil
}

func readPrivate(path string) ([]byte, error) {
	if err := securestate.CheckPath(path); err != nil {
		return nil, err
	}
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxPEMBytes || (runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0) {
		return nil, errors.New("invalid private TLS file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(st, opened) {
		return nil, errors.New("private TLS file changed")
	}
	return io.ReadAll(io.LimitReader(f, maxPEMBytes+1))
}

func writePrivate(dir, name string, data []byte) error {
	path := filepath.Join(dir, name)
	if err := securestate.CheckPath(path); err != nil {
		return err
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	tmp := filepath.Join(dir, fmt.Sprintf("%s.tmp-%x", name, suffix))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}
