package tlshost

// ACME client unit tests against a mock RFC 8555 server: directory,
// nonce, account, order, authz, challenge, finalize, certificate — all
// over httptest, with a fake publisher capturing the TXT value.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakePublisher struct {
	txts     map[string]string
	failOn   string
	publCnt  int
	cleanCnt int
}

func (f *fakePublisher) Publish(ctx context.Context, domain, txt string) error {
	f.publCnt++
	if f.failOn == domain {
		return context.DeadlineExceeded
	}
	f.txts[domain] = txt
	return nil
}

func (f *fakePublisher) Cleanup(ctx context.Context, domain, txt string) error {
	f.cleanCnt++
	delete(f.txts, domain)
	return nil
}

// mockACME is a minimal but honest ACME server: real JWS POSTs arrive,
// challenges flip to valid only after the TXT publisher ran, and the
// final certificate is a real x509 chain signed by a test CA.
type mockACME struct {
	t                *testing.T
	srv              *httptest.Server
	caKey            *ecdsa.PrivateKey
	caCert           *x509.Certificate
	pub              *fakePublisher
	rejectFirstOrder atomic.Bool
	kid              atomic.Int32
	nonces           atomic.Int32
	sawCSR           chan *x509.CertificateRequest
	csr              *x509.CertificateRequest
	chalURL          map[string]string
}

func newMockACME(t *testing.T, pub *fakePublisher) *mockACME {
	m := &mockACME{t: t, pub: pub, sawCSR: make(chan *x509.CertificateRequest, 1), chalURL: map[string]string{}}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	m.caKey = k
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mock test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	m.caCert, _ = x509.ParseCertificate(der)

	mux := http.NewServeMux()
	mux.HandleFunc("/dir", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   m.srv.URL + "/nonce",
			"newAccount": m.srv.URL + "/acct",
			"newOrder":   m.srv.URL + "/order",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", m.nonce())
	})
	mux.HandleFunc("/acct", m.handleAcct)
	mux.HandleFunc("/order", m.handleOrder)
	mux.HandleFunc("/authz/", m.handleAuthz)
	mux.HandleFunc("/chal/", m.handleChal)
	mux.HandleFunc("/finalize/", m.handleFinalize)
	mux.HandleFunc("/cert/", m.handleCert)
	m.srv = httptest.NewServer(mux)
	return m
}

func (m *mockACME) nonce() string {
	return "nonce-" + strings.Repeat("x", 8) + string(rune('a'+m.nonces.Add(1)%26))
}

func (m *mockACME) handleAcct(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", m.nonce())
	id := m.kid.Add(1)
	w.Header().Set("Location", m.srv.URL+"/acct/"+string(rune('0'+id)))
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
}

func (m *mockACME) handleOrder(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", m.nonce())
	if m.rejectFirstOrder.Swap(false) {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]any{
			"type":   "urn:ietf:params:acme:error:badNonce",
			"detail": "JWS has an invalid anti-replay nonce",
			"status": 400,
		})
		return
	}
	w.Header().Set("Location", m.srv.URL+"/order/1")
	w.WriteHeader(201)
	json.NewEncoder(w).Encode(map[string]any{
		"status":         "pending",
		"identifiers":    []map[string]string{{"type": "dns", "value": "unit.test"}},
		"authorizations": []string{m.srv.URL + "/authz/1"},
		"finalize":       m.srv.URL + "/finalize/1",
	})
}

func (m *mockACME) handleAuthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", m.nonce())
	status := "pending"
	if _, ok := m.pub.txts["unit.test"]; ok {
		// TXT published and challenge triggered → validator succeeds
		if m.chalURL["1"] == "triggered" {
			status = "valid"
		}
	}
	json.NewEncoder(w).Encode(map[string]any{
		"status":     status,
		"identifier": map[string]string{"type": "dns", "value": "unit.test"},
		"challenges": []map[string]string{{
			"type": "dns-01", "url": m.srv.URL + "/chal/1", "token": "tok123", "status": status,
		}},
	})
}

func (m *mockACME) handleChal(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", m.nonce())
	m.chalURL["1"] = "triggered"
	json.NewEncoder(w).Encode(map[string]string{"type": "dns-01", "status": "processing"})
}

func (m *mockACME) handleFinalize(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", m.nonce())
	var body struct {
		Payload string `json:"payload"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	payloadJSON, _ := b64.DecodeString(body.Payload)
	var fin struct {
		CSR string `json:"csr"`
	}
	json.Unmarshal(payloadJSON, &fin)
	csrDER, _ := b64.DecodeString(fin.CSR)
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err == nil {
		m.csr = csr
		m.sawCSR <- csr
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "processing"})
}

func (m *mockACME) handleCert(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", m.nonce())
	// Sign a leaf with the CSR's own public key so the issued certificate
	// matches the client's generated key (Store.Install verifies this).
	if m.csr == nil {
		w.WriteHeader(400)
		return
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "unit.test"},
		DNSNames:     []string{"unit.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, m.caCert, m.csr.PublicKey, m.caKey)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.caCert.Raw})
	w.Write(append(leafPEM, caPEM...))
}

// orderPoll needs the order URL handler to flip to valid after finalize.
func (m *mockACME) installOrderPoll() {
	// re-register with valid status
	m.srv.Config.Handler.(*http.ServeMux).HandleFunc("/order/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", m.nonce())
		json.NewEncoder(w).Encode(map[string]any{
			"status":      "valid",
			"certificate": m.srv.URL + "/cert/1",
			"finalize":    m.srv.URL + "/finalize/1",
		})
	})
}

func TestACMEIssueFlow(t *testing.T) {
	pub := &fakePublisher{txts: map[string]string{}}
	m := newMockACME(t, pub)
	m.installOrderPoll()
	defer m.srv.Close()

	c := NewACMEClient(m.srv.URL+"/dir", "ops@unit.test", t.TempDir())
	c.PollInterval = 10 * time.Millisecond
	c.OrderTimeout = 10 * time.Second

	leaf, key, chain, err := c.Issue(context.Background(), []string{"unit.test"}, pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf) == 0 || len(key) == 0 || len(chain) == 0 {
		t.Fatalf("expected leaf+key+chain, got %d/%d/%d bytes", len(leaf), len(key), len(chain))
	}
	if pub.publCnt != 1 || pub.cleanCnt != 1 {
		t.Fatalf("publish/cleanup counts: %d/%d", pub.publCnt, pub.cleanCnt)
	}
	select {
	case csr := <-m.sawCSR:
		if csr.Subject.CommonName != "unit.test" || len(csr.DNSNames) != 1 {
			t.Fatalf("bad CSR: %+v", csr)
		}
	default:
		t.Fatal("finalize never carried a CSR")
	}
	// Leaf parses and chains to the mock CA.
	blk, _ := pem.Decode(leaf)
	leafCert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(m.caCert)
	if _, err := leafCert.Verify(x509.VerifyOptions{DNSName: "unit.test", Roots: pool}); err != nil {
		t.Fatalf("leaf does not verify: %v", err)
	}
}

func TestACMEBadNonceRetry(t *testing.T) {
	pub := &fakePublisher{txts: map[string]string{}}
	m := newMockACME(t, pub)
	m.installOrderPoll()
	defer m.srv.Close()

	// First newOrder POST gets a badNonce rejection; the client must
	// refetch a nonce and retry once (RFC 8555 §6.5).
	m.rejectFirstOrder.Store(true)

	c := NewACMEClient(m.srv.URL+"/dir", "", t.TempDir())
	c.PollInterval = 10 * time.Millisecond
	c.OrderTimeout = 10 * time.Second
	leaf, _, _, err := c.Issue(context.Background(), []string{"unit.test"}, pub)
	if err != nil {
		t.Fatalf("badNonce retry should recover: %v", err)
	}
	if len(leaf) == 0 {
		t.Fatal("no leaf")
	}
}

func TestACMEPublishFailure(t *testing.T) {
	pub := &fakePublisher{txts: map[string]string{}, failOn: "unit.test"}
	m := newMockACME(t, pub)
	defer m.srv.Close()

	c := NewACMEClient(m.srv.URL+"/dir", "", t.TempDir())
	c.PollInterval = 10 * time.Millisecond
	_, _, _, err := c.Issue(context.Background(), []string{"unit.test"}, pub)
	if err == nil || !strings.Contains(err.Error(), "publish") {
		t.Fatalf("expected publish failure, got %v", err)
	}
}

func TestAutoSSLRunner(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	st := &Store{Root: root}

	pub := &fakePublisher{txts: map[string]string{}}
	m := newMockACME(t, pub)
	m.installOrderPoll()
	defer m.srv.Close()

	client := NewACMEClient(m.srv.URL+"/dir", "ops@unit.test", t.TempDir())
	client.PollInterval = 10 * time.Millisecond
	client.OrderTimeout = 10 * time.Second

	runner := &Runner{Store: st, ACME: client, Publisher: pub}

	// no cert yet → issued
	results, err := runner.RunCheck(ctx, "acct1", []string{"unit.test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Status != "issued" {
		t.Fatalf("results: %+v", results)
	}
	info, err := st.Info(ctx, "unit.test")
	if err != nil {
		t.Fatalf("installed cert not in store: %v", err)
	}
	if info.DaysRemaining < 80 {
		t.Fatalf("days remaining: %d", info.DaysRemaining)
	}

	// fresh cert → covered, no new order
	results, err = runner.RunCheck(ctx, "acct1", []string{"unit.test"})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Status != "covered" || results[0].DaysRemaining < 80 {
		t.Fatalf("results: %+v", results)
	}

	// state persisted + in-progress cleared
	st2, ok := runner.State("acct1")
	if !ok || len(st2.Results) != 1 {
		t.Fatalf("state: %+v ok=%v", st2, ok)
	}
	if runner.InProgress("acct1") {
		t.Fatal("in-progress flag stuck")
	}
}
