package tlshost

// tls.autossl batch 3: minimal ACME v2 (RFC 8555) client, DNS-01 only.
// Self-contained on purpose: no external ACME dependency enters the tree.
// The client talks JWS (ES256) to a configurable directory — production
// Let's Encrypt, staging, or a test CA (Pebble) for qualification rigs.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var b64 = base64.RawURLEncoding

// ChallengePublisher publishes and removes the DNS-01 TXT value for a
// domain. The WHM layer implements this over dnshost (BIND master files).
type ChallengePublisher interface {
	Publish(ctx context.Context, domain, txtValue string) error
	Cleanup(ctx context.Context, domain, txtValue string) error
}

// ACMEClient is a DNS-01-only ACME v2 client.
type ACMEClient struct {
	DirectoryURL string
	Email        string
	// HTTPClient overrides the transport (test rigs point at a Pebble CA
	// with InsecureSkipVerify). Nil = http.DefaultClient.
	HTTPClient *http.Client
	// PollInterval/OrderTimeout bound the validation waits.
	PollInterval time.Duration
	OrderTimeout time.Duration

	dir      *acmeDirectory
	key      *ecdsa.PrivateKey
	kid      string
	nonces   []string
	http     *http.Client
	stateDir string // account key persistence
}

type acmeDirectory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
}

type acmeErr struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

func (e *acmeErr) Error() string { return fmt.Sprintf("acme: %s: %s", e.Type, e.Detail) }

// NewACMEClient loads or creates the account key under stateDir.
func NewACMEClient(directoryURL, email, stateDir string) *ACMEClient {
	return &ACMEClient{
		DirectoryURL: directoryURL,
		Email:        email,
		PollInterval: time.Second,
		OrderTimeout: 60 * time.Second,
		stateDir:     stateDir,
	}
}

func (c *ACMEClient) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	if c.http == nil {
		c.http = &http.Client{Timeout: 30 * time.Second}
	}
	return c.http
}

func (c *ACMEClient) loadOrCreateKey() (*ecdsa.PrivateKey, error) {
	if c.key != nil {
		return c.key, nil
	}
	p := filepath.Join(c.stateDir, "account.key.pem")
	if raw, err := os.ReadFile(p); err == nil {
		blk, _ := pem.Decode(raw)
		if blk == nil {
			return nil, errors.New("acme account key: bad PEM")
		}
		k, err := x509.ParseECPrivateKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		c.key = k
		return k, nil
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(c.stateDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	c.key = k
	return k, nil
}

// jwkThumbprint is the RFC 7638 SHA-256 thumbprint of the account JWK,
// base64url — the ACME key-authorization suffix.
func jwkThumbprint(k *ecdsa.PrivateKey) string {
	x := b64.EncodeToString(k.PublicKey.X.Bytes())
	y := b64.EncodeToString(k.PublicKey.Y.Bytes())
	// RFC 7638: lexicographic member order, no whitespace.
	j := `{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`
	sum := sha256.Sum256([]byte(j))
	return b64.EncodeToString(sum[:])
}

func (c *ACMEClient) jws(url, payload string, withJWK bool) ([]byte, error) {
	if len(c.nonces) == 0 {
		if err := c.fetchNonce(); err != nil {
			return nil, err
		}
	}
	nonce := c.nonces[len(c.nonces)-1]
	c.nonces = c.nonces[:len(c.nonces)-1]

	protected := map[string]string{"alg": "ES256", "nonce": nonce, "url": url}
	if withJWK {
		x := b64.EncodeToString(c.key.PublicKey.X.Bytes())
		y := b64.EncodeToString(c.key.PublicKey.Y.Bytes())
		protected["jwk"] = `{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`
	} else {
		protected["kid"] = c.kid
	}
	// Build protected JSON manually so the jwk member stays verbatim.
	var pj string
	if withJWK {
		pj = fmt.Sprintf(`{"alg":"ES256","jwk":%s,"nonce":"%s","url":"%s"}`,
			protected["jwk"], nonce, url)
	} else {
		pj = fmt.Sprintf(`{"alg":"ES256","kid":"%s","nonce":"%s","url":"%s"}`,
			c.kid, nonce, url)
	}
	signing := b64.EncodeToString([]byte(pj)) + "." + b64.EncodeToString([]byte(payload))
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, c.key, digest[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	rb, sb := r.Bytes(), s.Bytes()
	copy(sig[32-len(rb):32], rb)
	copy(sig[64-len(sb):], sb)
	body := map[string]string{
		"protected": b64.EncodeToString([]byte(pj)),
		"payload":   b64.EncodeToString([]byte(payload)),
		"signature": b64.EncodeToString(sig),
	}
	return json.Marshal(body)
}

func (c *ACMEClient) fetchNonce() error {
	// GET, not HEAD: Pebble's nonce handler answers both, but some
	// proxies strip headers from HEAD responses.
	req, _ := http.NewRequest("GET", c.dir.NewNonce, nil)
	resp, err := c.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	n := resp.Header.Get("Replay-Nonce")
	if n == "" {
		return errors.New("acme: no Replay-Nonce from newNonce")
	}
	c.nonces = append(c.nonces, n)
	if acmeDebug() {
		fmt.Fprintf(os.Stderr, "acme: fetched nonce %s (stack %d)\n", n, len(c.nonces))
	}
	return nil
}

func acmeDebug() bool { return os.Getenv("ACME_DEBUG") != "" }

// post signs and posts one ACME request, keeping the replay nonce. A
// badNonce rejection (stale cached nonce across runs/processes) triggers
// one retry with a fresh nonce, per RFC 8555 §6.5.
func (c *ACMEClient) post(url, payload string, withJWK bool) (*http.Response, []byte, error) {
	resp, raw, err := c.postOnce(url, payload, withJWK)
	if err != nil {
		var pe *acmeErr
		if errors.As(err, &pe) && strings.HasSuffix(pe.Type, "badNonce") {
			if ferr := c.fetchNonce(); ferr == nil {
				return c.postOnce(url, payload, withJWK)
			}
		}
	}
	return resp, raw, err
}

func (c *ACMEClient) postOnce(url, payload string, withJWK bool) (*http.Response, []byte, error) {
	body, err := c.jws(url, payload, withJWK)
	if err != nil {
		return nil, nil, err
	}
	resp, err := c.client().Post(url, "application/jose+json", strings.NewReader(string(body)))
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if n := resp.Header.Get("Replay-Nonce"); n != "" {
		c.nonces = append(c.nonces, n)
	}
	if acmeDebug() {
		fmt.Fprintf(os.Stderr, "acme: POST %s -> %d (stack %d)\n", url, resp.StatusCode, len(c.nonces))
	}
	if resp.StatusCode >= 400 {
		pe := &acmeErr{}
		if json.Unmarshal(raw, pe) == nil && pe.Detail != "" {
			return resp, raw, pe
		}
		return resp, raw, fmt.Errorf("acme: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return resp, raw, nil
}

func (c *ACMEClient) postAsGET(url string) ([]byte, http.Header, error) {
	_, raw, err := c.post(url, "", false)
	if err != nil {
		return nil, nil, err
	}
	return raw, nil, err
}

func (c *ACMEClient) ensureDirectory() error {
	if c.dir != nil {
		return nil
	}
	resp, err := c.client().Get(c.DirectoryURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return fmt.Errorf("acme: directory HTTP %d", resp.StatusCode)
	}
	d := acmeDirectory{}
	if err := json.Unmarshal(raw, &d); err != nil {
		return err
	}
	if d.NewNonce == "" || d.NewAccount == "" || d.NewOrder == "" {
		return errors.New("acme: directory missing endpoints")
	}
	c.dir = &d
	return nil
}

func (c *ACMEClient) ensureAccount() error {
	if _, err := c.loadOrCreateKey(); err != nil {
		return err
	}
	if c.kid != "" {
		return nil
	}
	if err := c.ensureDirectory(); err != nil {
		return err
	}
	contact := "[]"
	if c.Email != "" {
		contact = `["mailto:` + c.Email + `"]`
	}
	payload := `{"termsOfServiceAgreed":true,"contact":` + contact + `}`
	resp, _, err := c.post(c.dir.NewAccount, payload, true)
	if err != nil {
		return err
	}
	kid := resp.Header.Get("Location")
	if kid == "" {
		return errors.New("acme: account registration returned no Location")
	}
	c.kid = kid
	return nil
}

type acmeAuthz struct {
	Status     string `json:"status"`
	Identifier struct {
		Value string `json:"value"`
	} `json:"identifier"`
	Challenges []struct {
		Type   string   `json:"type"`
		URL    string   `json:"url"`
		Token  string   `json:"token"`
		Status string   `json:"status"`
		Error  *acmeErr `json:"error"`
	} `json:"challenges"`
}

type acmeOrder struct {
	Status      string `json:"status"`
	Identifiers []struct {
		Value string `json:"value"`
	} `json:"identifiers"`
	AuthorizationURLs []string `json:"authorizations"`
	Finalize          string   `json:"finalize"`
	Certificate       string   `json:"certificate"`
	Error             *acmeErr `json:"error"`
}

// Issue runs one full ACME order for domains (DNS-01 per identifier) and
// returns the leaf PEM, the generated private key PEM, and the chain PEM
// (intermediates). The publisher must make the TXT visible at
// _acme-challenge.<domain> before returning.
func (c *ACMEClient) Issue(ctx context.Context, domains []string, pub ChallengePublisher) (leafPEM, keyPEM, chainPEM []byte, err error) {
	if len(domains) == 0 {
		return nil, nil, nil, errors.New("no domains")
	}
	if err := c.ensureAccount(); err != nil {
		return nil, nil, nil, err
	}

	ids := make([]string, 0, len(domains))
	for _, d := range domains {
		ids = append(ids, `{"type":"dns","value":"`+d+`"}`)
	}
	resp, raw, err := c.post(c.dir.NewOrder, `{"identifiers":[`+strings.Join(ids, ",")+`]}`, false)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("newOrder: %w", err)
	}
	orderURL := resp.Header.Get("Location")
	order := acmeOrder{}
	if err := json.Unmarshal(raw, &order); err != nil {
		return nil, nil, nil, err
	}

	// DNS-01 per authorization.
	type cleanupItem struct{ domain, txt string }
	cleanups := []cleanupItem{}
	defer func() {
		for _, cu := range cleanups {
			_ = pub.Cleanup(context.Background(), cu.domain, cu.txt)
		}
	}()

	for _, au := range order.AuthorizationURLs {
		raw, _, err := c.postAsGET(au)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("authz fetch: %w", err)
		}
		az := acmeAuthz{}
		if err := json.Unmarshal(raw, &az); err != nil {
			return nil, nil, nil, err
		}
		domain := az.Identifier.Value
		var chURL, token string
		for _, ch := range az.Challenges {
			if ch.Type == "dns-01" {
				chURL, token = ch.URL, ch.Token
			}
		}
		if chURL == "" {
			return nil, nil, nil, fmt.Errorf("authz %s: no dns-01 challenge offered", domain)
		}
		// RFC 8555 §8.4: TXT value = base64url(SHA-256(key authorization)).
		sum := sha256.Sum256([]byte(token + "." + jwkThumbprint(c.key)))
		txt := b64.EncodeToString(sum[:])
		if az.Status != "valid" {
			// Register cleanup BEFORE Publish: when Publish fails after
			// writing the TXT row (e.g. propagation timeout), the row
			// must still be swept instead of orphaned in the zone.
			cleanups = append(cleanups, cleanupItem{domain, txt})
			if err := pub.Publish(ctx, domain, txt); err != nil {
				return nil, nil, nil, fmt.Errorf("publish _acme-challenge.%s: %w", domain, err)
			}
			if _, _, err := c.post(chURL, "{}", false); err != nil {
				return nil, nil, nil, fmt.Errorf("challenge trigger %s: %w", domain, err)
			}
			if err := c.waitStatus(ctx, au, "valid"); err != nil {
				return nil, nil, nil, fmt.Errorf("challenge %s: %w", domain, err)
			}
		}
	}

	// Key + CSR for the order.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	tpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: domains[0]}, DNSNames: domains}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tpl, key)
	if err != nil {
		return nil, nil, nil, err
	}
	if _, _, err := c.post(order.Finalize, `{"csr":"`+b64.EncodeToString(csrDER)+`"}`, false); err != nil {
		return nil, nil, nil, fmt.Errorf("finalize: %w", err)
	}

	deadline := time.Now().Add(c.OrderTimeout)
	certURL := ""
	for time.Now().Before(deadline) {
		raw, _, err := c.postAsGET(orderURL)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("order poll: %w", err)
		}
		o := acmeOrder{}
		if err := json.Unmarshal(raw, &o); err != nil {
			return nil, nil, nil, err
		}
		switch o.Status {
		case "valid":
			certURL = o.Certificate
		case "invalid":
			if o.Error != nil {
				return nil, nil, nil, o.Error
			}
			return nil, nil, nil, errors.New("order invalid")
		}
		if certURL != "" {
			break
		}
		select {
		case <-ctx.Done():
			return nil, nil, nil, ctx.Err()
		case <-time.After(c.PollInterval):
		}
	}
	if certURL == "" {
		return nil, nil, nil, errors.New("order did not reach valid before timeout")
	}

	raw, _, err = c.postAsGET(certURL)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("certificate fetch: %w", err)
	}
	// Chain: first PEM block is the leaf, the rest is the cabundle.
	leaf, rest := pem.Decode(raw)
	if leaf == nil {
		return nil, nil, nil, errors.New("certificate response: no PEM")
	}
	leafBytes := pem.EncodeToMemory(leaf)
	var chainBytes []byte
	for len(rest) > 0 {
		blk, r2 := pem.Decode(rest)
		if blk == nil {
			break
		}
		chainBytes = append(chainBytes, pem.EncodeToMemory(blk)...)
		rest = r2
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	return leafBytes, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), chainBytes, nil
}

// waitStatus polls an authz URL until status becomes target or fails.
func (c *ACMEClient) waitStatus(ctx context.Context, url, target string) error {
	deadline := time.Now().Add(c.OrderTimeout)
	for time.Now().Before(deadline) {
		raw, _, err := c.postAsGET(url)
		if err != nil {
			return err
		}
		az := acmeAuthz{}
		if err := json.Unmarshal(raw, &az); err != nil {
			return err
		}
		if az.Status == target {
			return nil
		}
		if az.Status == "invalid" {
			for _, ch := range az.Challenges {
				if ch.Error != nil {
					return ch.Error
				}
			}
			return errors.New("authorization invalid")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(c.PollInterval):
		}
	}
	return errors.New("timed out waiting for " + target)
}
