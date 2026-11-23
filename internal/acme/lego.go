package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	legoacme "github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/lego"
	legolog "github.com/go-acme/lego/v5/log"
	"github.com/go-acme/lego/v5/registration"
)

const (
	accountKeyFile  = "account.key"
	accountFile     = "account.json"
	accountVersion  = 1
	maxAccountBytes = 64 << 10
	maxCAFileBytes  = 1 << 20
	httpTimeout     = time.Minute
	userAgent       = "sifruno-panel"
)

// Config is the panel's ACME setup, from its command-line flags.
type Config struct {
	Email        string // the account's contact; required
	Directory    string // the ACME directory URL; LetsEncrypt when empty
	CAFile       string // optional PEM bundle trusted for the ACME server only
	StateDir     string // the panel's private <state>/acme
	ChallengeDir string // ChallengeDir when empty; tests use their own
}

// New sets up the lego client from cfg and returns a Manager over it. It
// checks the settings and loads or makes the account key (ECDSA P-256, 0600
// in StateDir) now; it reaches the ACME server only when the first
// certificate is needed, so the panel starts while that server is down.
// Registering accepts the certificate authority's terms of service.
func New(cfg Config, installer Installer, sites Sites) (*Manager, error) {
	issuer, err := newLegoIssuer(cfg)
	if err != nil {
		return nil, err
	}
	return NewManager(issuer, installer, sites, cfg.StateDir)
}

// accountUser is the ACME account as lego wants it.
type accountUser struct {
	email   string
	key     crypto.Signer
	account *legoacme.ExtendedAccount
}

func (u *accountUser) GetEmail() string                           { return u.email }
func (u *accountUser) GetRegistration() *legoacme.ExtendedAccount { return u.account }
func (u *accountUser) GetPrivateKey() crypto.Signer               { return u.key }

// savedAccount is account.json: where the account key is registered.
type savedAccount struct {
	Version   int    `json:"version"`
	Email     string `json:"email"`
	Directory string `json:"directory"`
	Location  string `json:"location"`
}

type legoIssuer struct {
	cfg  Config
	http *http.Client
	user *accountUser

	mu     sync.Mutex
	client *lego.Client // made, and the account registered, on first use
}

func newLegoIssuer(cfg Config) (*legoIssuer, error) {
	if cfg.Directory == "" {
		cfg.Directory = LetsEncrypt
	}
	if cfg.ChallengeDir == "" {
		cfg.ChallengeDir = ChallengeDir
	}
	if a, err := mail.ParseAddress(cfg.Email); err != nil || a.Address != cfg.Email || a.Name != "" {
		return nil, errors.New("acme: --acme-email must be a plain email address such as admin@example.com")
	}
	if u, err := url.Parse(cfg.Directory); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, errors.New("acme: --acme-directory must be an https:// URL")
	}
	if !filepath.IsAbs(cfg.ChallengeDir) {
		return nil, errors.New("acme: the challenge directory must be an absolute path")
	}
	client, err := acmeHTTPClient(cfg.CAFile)
	if err != nil {
		return nil, err
	}
	dir, err := privateDir(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	cfg.StateDir = dir
	key, err := loadOrCreateKey(filepath.Join(dir, accountKeyFile))
	if err != nil {
		return nil, err
	}
	// lego's own progress lines would add several lines per attempt; the
	// Manager logs one line with the outcome instead.
	legolog.SetDefault(slog.New(slog.DiscardHandler))
	return &legoIssuer{cfg: cfg, http: client, user: &accountUser{email: cfg.Email, key: key}}, nil
}

// acmeHTTPClient trusts the system roots, or only the CA file when one is
// given. It is used for the ACME server alone.
func acmeHTTPClient(caFile string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		f, err := os.Open(caFile)
		if err != nil {
			return nil, fmt.Errorf("acme: --acme-ca-file: %w", err)
		}
		raw, err := io.ReadAll(io.LimitReader(f, maxCAFileBytes+1))
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("acme: --acme-ca-file: %w", err)
		}
		if len(raw) > maxCAFileBytes {
			return nil, fmt.Errorf("acme: --acme-ca-file %s is larger than %d bytes", caFile, maxCAFileBytes)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return nil, fmt.Errorf("acme: --acme-ca-file %s holds no PEM certificate", caFile)
		}
		transport.TLSClientConfig.RootCAs = pool
	}
	return &http.Client{Timeout: httpTimeout, Transport: transport}, nil
}

// loadOrCreateKey reads the account key, or makes an ECDSA P-256 key and
// saves it 0600. A key file others can read is refused, not repaired.
func loadOrCreateKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := readPrivate(path, maxAccountBytes)
	if errors.Is(err, os.ErrNotExist) {
		key, gerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if gerr != nil {
			return nil, gerr
		}
		der, merr := x509.MarshalECPrivateKey(key)
		if merr != nil {
			return nil, merr
		}
		if werr := writePrivate(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})); werr != nil {
			return nil, fmt.Errorf("acme: saving the account key: %w", werr)
		}
		return key, nil
	}
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "EC PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("acme: %s is not one EC private key", path)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("acme: %s is not an ECDSA P-256 key", path)
	}
	return key, nil
}

// Issue gets a certificate for domain over HTTP-01 with a new ECDSA P-256
// key, and answers the full chain, leaf first.
func (l *legoIssuer) Issue(ctx context.Context, domain string) (Certificate, error) {
	res, err := l.obtain(ctx, domain)
	if accountUnknown(err) {
		// The certificate authority no longer knows the saved account (a
		// test CA such as Pebble forgets it on restart): register the key
		// again and try once more.
		if ferr := l.forgetAccount(); ferr != nil {
			return Certificate{}, ferr
		}
		res, err = l.obtain(ctx, domain)
	}
	if err != nil {
		return Certificate{}, classify(err)
	}
	if res == nil || len(res.Certificate) == 0 || len(res.PrivateKey) == 0 {
		return Certificate{}, fmt.Errorf("%w: the answer held no certificate", ErrAuthority)
	}
	return Certificate{ChainPEM: res.Certificate, KeyPEM: res.PrivateKey}, nil
}

func (l *legoIssuer) obtain(ctx context.Context, domain string) (*certificate.Resource, error) {
	client, err := l.ready(ctx)
	if err != nil {
		return nil, err
	}
	return client.Certificate.Obtain(ctx, certificate.ObtainRequest{Domains: []string{domain}, KeyType: certcrypto.EC256, Bundle: true})
}

func accountUnknown(err error) bool {
	var problem *legoacme.ProblemDetails
	return errors.As(err, &problem) && problem.Type == legoacme.AccountDoesNotExistErrorType
}

// forgetAccount drops the saved registration, so the next use registers the
// account key again. The key itself is kept.
func (l *legoIssuer) forgetAccount() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.client, l.user.account = nil, nil
	if err := os.Remove(filepath.Join(l.cfg.StateDir, accountFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("acme: removing the account record: %w", err)
	}
	return nil
}

// ready makes the lego client on first use and registers the account key,
// or reuses the registration saved for this directory.
func (l *legoIssuer) ready(ctx context.Context) (*lego.Client, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.client != nil {
		return l.client, nil
	}
	path := filepath.Join(l.cfg.StateDir, accountFile)
	var saved savedAccount
	raw, err := readPrivate(path, maxAccountBytes)
	switch {
	case err == nil:
		if json.Unmarshal(raw, &saved) != nil || saved.Version != accountVersion {
			return nil, fmt.Errorf("acme: %s is not a version 1 account record", path)
		}
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	}
	known := saved.Directory == l.cfg.Directory && saved.Location != ""
	if known {
		l.user.account = &legoacme.ExtendedAccount{Location: saved.Location}
	}
	config := lego.NewConfig(l.user)
	config.CADirURL = l.cfg.Directory
	config.HTTPClient = l.http
	config.UserAgent = userAgent
	// lego reads the directory here, so an unreachable server fails now.
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, classify(err)
	}
	if err = client.Challenge.SetHTTP01Provider(challengeFiles{dir: l.cfg.ChallengeDir}); err != nil {
		return nil, err
	}
	var account *legoacme.ExtendedAccount
	switch {
	case !known:
		account, err = client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
	case saved.Email != l.cfg.Email:
		account, err = client.Registration.UpdateRegistration(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
	}
	if err != nil {
		return nil, classify(err)
	}
	if account != nil {
		if account.Location == "" {
			return nil, fmt.Errorf("%w: the account registration answered no account URL", ErrAuthority)
		}
		l.user.account = account
		data, _ := json.Marshal(savedAccount{Version: accountVersion, Email: l.cfg.Email, Directory: l.cfg.Directory, Location: account.Location})
		if err = writePrivate(path, append(data, '\n')); err != nil {
			return nil, fmt.Errorf("acme: saving the account record: %w", err)
		}
	}
	l.client = client
	return client, nil
}

// classify sorts lego's errors into the kinds the wizard explains. An error
// already of one of these kinds is kept as it is.
func classify(err error) error {
	for _, kind := range []error{ErrValidation, ErrRateLimited, ErrAuthority, ErrInstall} {
		if errors.Is(err, kind) {
			return err
		}
	}
	var limited *legoacme.RateLimitedError
	if errors.As(err, &limited) {
		return fmt.Errorf("%w: %w", ErrRateLimited, err)
	}
	var problem *legoacme.ProblemDetails
	if errors.As(err, &problem) {
		switch problem.Type {
		case legoacme.RateLimitedErrorType:
			return fmt.Errorf("%w: %w", ErrRateLimited, err)
		case legoacme.ConnectionErrorType, legoacme.DNSErrorType, legoacme.UnauthorizedErrorType, legoacme.IncorrectResponseErrorType, legoacme.TLSErrorType:
			return fmt.Errorf("%w: %w", ErrValidation, err)
		}
	}
	return fmt.Errorf("%w: %w", ErrAuthority, err)
}
