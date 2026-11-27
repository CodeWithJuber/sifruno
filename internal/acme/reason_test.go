package acme

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v5/acme"
)

func TestReasonOfNamesTheRealRefusal(t *testing.T) {
	problem := func(kind string) error {
		return fmt.Errorf("%w: invalid challenge: %w", ErrValidation, &legoacme.ProblemDetails{Type: kind, Detail: "detail", HTTPStatus: 403})
	}
	refused := &url.Error{Op: "Get", URL: LetsEncrypt, Err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}}
	for _, tc := range []struct {
		err  error
		want Reason
	}{
		{nil, ""},
		{problem(legoacme.InvalidContactErrorType), ReasonContact},
		{problem(legoacme.UnsupportedContactErrorType), ReasonContact},
		{problem(legoacme.RateLimitedErrorType), ReasonRateLimit},
		{&legoacme.RateLimitedError{ProblemDetails: &legoacme.ProblemDetails{Type: legoacme.RateLimitedErrorType}}, ReasonRateLimit},
		{problem(legoacme.RejectedIdentifierErrorType), ReasonName},
		{problem(legoacme.UnsupportedIdentifierErrorType), ReasonName},
		{problem(legoacme.CaaErrorType), ReasonCAA},
		{problem(legoacme.DNSErrorType), ReasonDNS},
		{problem(legoacme.ConnectionErrorType), ReasonConnection},
		{problem(legoacme.TLSErrorType), ReasonConnection},
		{problem(legoacme.UnauthorizedErrorType), ReasonElsewhere},
		{problem(legoacme.IncorrectResponseErrorType), ReasonElsewhere},
		{problem(legoacme.ServerInternalErrorType), ReasonRefused},
		// A refused order for several names says which, in its subproblems.
		{&legoacme.ProblemDetails{Type: legoacme.CompoundErrorType, SubProblems: []legoacme.SubProblem{{Type: legoacme.CaaErrorType}, {Type: legoacme.DNSErrorType}}}, ReasonCAA},
		{&legoacme.ProblemDetails{Type: legoacme.MalformedErrorType, SubProblems: []legoacme.SubProblem{{Type: legoacme.RejectedIdentifierErrorType}}}, ReasonName},
		{errors.Join(errors.New("other domain"), problem(legoacme.DNSErrorType)), ReasonDNS},
		{fmt.Errorf("%w: get directory: %w", ErrAuthority, refused), ReasonNoAnswer},
		{fmt.Errorf("%w: %w", ErrAuthority, context.DeadlineExceeded), ReasonNoAnswer},
		{fmt.Errorf("%w: disk full", ErrInstall), ReasonInstall},
		{ErrTooSoon, ReasonTooSoon},
		{fmt.Errorf("%w: too many", ErrRateLimited), ReasonRateLimit},
		{fmt.Errorf("%w: refused", ErrValidation), ReasonConnection},
		{errors.New("acme: error presenting token: permission denied"), ReasonOther},
	} {
		if got := ReasonOf(tc.err); got != tc.want {
			t.Errorf("%v: %q, want %q", tc.err, got, tc.want)
		}
	}
}

// fakeAuthority is the start of an ACME server: its directory, nonces, and
// an account registration it refuses with problem.
func fakeAuthority(t *testing.T, problem string) (*httptest.Server, string) {
	t.Helper()
	nonce := 0
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce++
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", nonce))
		switch r.URL.Path {
		case "/dir":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"newNonce": srv.URL + "/nonce", "newAccount": srv.URL + "/account", "newOrder": srv.URL + "/order", "revokeCert": srv.URL + "/revoke", "keyChange": srv.URL + "/key"})
		case "/nonce":
			w.WriteHeader(http.StatusOK)
		case "/account":
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(problem))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return srv, ca
}

// The audit's case through lego itself: Let's Encrypt refuses the contact
// address when the account registers, before any order, and the panel
// names that, not the network.
func TestIssueNamesARefusedContactAddress(t *testing.T) {
	srv, ca := fakeAuthority(t, `{"type":"urn:ietf:params:acme:error:invalidContact","detail":"Error validating contact(s) :: contact email has forbidden domain \"example.com\"","status":400}`)
	issuer, err := newLegoIssuer(Config{Email: "admin@example.com", Directory: srv.URL + "/dir", CAFile: ca, StateDir: t.TempDir(), ChallengeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err = issuer.Issue(ctx, []string{"shop.example.net"})
	if !errors.Is(err, ErrAuthority) || ReasonOf(err) != ReasonContact || !strings.Contains(err.Error(), "forbidden domain") {
		t.Fatalf("error %v, reason %q", err, ReasonOf(err))
	}

	// An authority that cannot be reached at all is no answer.
	closed := httptest.NewTLSServer(http.NotFoundHandler())
	address := closed.URL
	closed.Close()
	issuer, err = newLegoIssuer(Config{Email: "admin@shop.example.net", Directory: address + "/dir", CAFile: ca, StateDir: t.TempDir(), ChallengeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = issuer.Issue(ctx, []string{"shop.example.net"})
	if ReasonOf(err) != ReasonNoAnswer {
		t.Fatalf("error %v, reason %q", err, ReasonOf(err))
	}
}
