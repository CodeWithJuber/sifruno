package whmapi

// tls.autossl batch 3: AutoSSL endpoints. Function names match the
// licensed 138 reference capture: WHM start_autossl_check_for_one_user
// (root) plus UAPI SSL::start_autossl_check / get_autossl_problems /
// get_autossl_renewal_status / is_autossl_check_in_progress
// (account-scoped). DNS-01 challenges publish through the dnshost store
// (BIND master files + reload hook), so issuance only works for zones
// actually hosted here — honest failure otherwise.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"sifruno/internal/dnshost"
	"sifruno/internal/tlshost"
)

// SetAutoSSL wires the AutoSSL runner. Nil = AutoSSL surface fail-closed.
func (s *Server) SetAutoSSL(r *tlshost.Runner) { s.autossl = r }

// DNSChallengePublisher publishes _acme-challenge TXT rows into the
// account's real BIND zone via dnshost and waits for the local resolver
// to serve them before returning (ACME validators query authoritative
// DNS; publishing without propagation would fail validation).
type DNSChallengePublisher struct {
	DNS *dnshost.Store
	// ResolverAddr checks propagation, e.g. "127.0.0.1:53". Empty skips
	// the wait (unit tests).
	ResolverAddr string
	Timeout      time.Duration
}

func (p DNSChallengePublisher) Publish(ctx context.Context, domain, txt string) error {
	if p.DNS == nil {
		return errors.New("DNS store unavailable")
	}
	z, err := p.DNS.Load(domain)
	if err != nil {
		return fmt.Errorf("no local DNS zone for %s — DNS-01 requires the zone hosted on this server", domain)
	}
	// Sweep stale challenge rows first (orphans from earlier failed
	// attempts); empty value in RemoveRecord matches any stored value.
	z.RemoveRecord("_acme-challenge", "TXT", "")
	rec := dnshost.Record{Name: "_acme-challenge", Type: "TXT", Value: `"` + txt + `"`}
	if err := z.AddRecord(rec); err != nil {
		return err
	}
	if err := p.DNS.Save(z); err != nil {
		return err
	}
	return p.waitPropagation(ctx, domain, txt)
}

func (p DNSChallengePublisher) Cleanup(ctx context.Context, domain, txt string) error {
	if p.DNS == nil {
		return nil
	}
	z, err := p.DNS.Load(domain)
	if err != nil {
		return nil
	}
	if z.RemoveRecord("_acme-challenge", "TXT", `"`+txt+`"`) > 0 {
		return p.DNS.Save(z)
	}
	return nil
}

func (p DNSChallengePublisher) waitPropagation(ctx context.Context, domain, txt string) error {
	if p.ResolverAddr == "" {
		return nil
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{Timeout: 2 * time.Second}
		return d.DialContext(ctx, "udp", p.ResolverAddr)
	}}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		vals, err := resolver.LookupTXT(ctx, "_acme-challenge."+domain)
		if err == nil {
			for _, v := range vals {
				if v == txt {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("_acme-challenge.%s TXT did not propagate to %s within %s", domain, p.ResolverAddr, timeout)
}

// accountDomains resolves the domains a check should cover. Batch 3
// covers the account's main domain; addon/subdomain coverage lands with
// the domain-management surface.
func (s *Server) accountDomains(username string) ([]string, error) {
	for _, a := range s.backend.ListAccounts() {
		if a.User == username {
			if a.Domain == "" {
				return nil, errors.New("account has no domain")
			}
			return []string{a.Domain}, nil
		}
	}
	return nil, errors.New("account not found")
}

// --- WHM API 1 ---

func (s *Server) handleStartAutoSSLCheckForOneUser(w http.ResponseWriter, r *http.Request) {
	if s.autossl == nil {
		writeError(w, "start_autossl_check_for_one_user", "AutoSSL is not configured on this server")
		return
	}
	username := r.URL.Query().Get("username")
	if username == "" {
		writeError(w, "start_autossl_check_for_one_user", "The username parameter is required.")
		return
	}
	domains, err := s.accountDomains(username)
	if err != nil {
		writeError(w, "start_autossl_check_for_one_user", err.Error())
		return
	}
	results, err := s.autossl.RunCheck(r.Context(), username, domains)
	if err != nil {
		writeError(w, "start_autossl_check_for_one_user", err.Error())
		return
	}
	writeSuccess(w, "start_autossl_check_for_one_user", map[string]any{"results": results}, "")
}

// --- UAPI SSL module ---

func (s *Server) uapiSSLStartAutoSSLCheck(w http.ResponseWriter, r *http.Request, acct Account, _ string) {
	if s.autossl == nil {
		writeUAPIError(w, "SSL", "start_autossl_check", []string{"AutoSSL is not configured on this server"})
		return
	}
	results, err := s.autossl.RunCheck(r.Context(), acct.User, []string{acct.Domain})
	if err != nil {
		writeUAPIError(w, "SSL", "start_autossl_check", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "SSL", "start_autossl_check", map[string]any{"results": results})
}

func (s *Server) uapiSSLGetAutoSSLProblems(w http.ResponseWriter, r *http.Request, acct Account, _ string) {
	if s.autossl == nil {
		writeUAPIError(w, "SSL", "get_autossl_problems", []string{"AutoSSL is not configured on this server"})
		return
	}
	problems := []map[string]string{}
	if st, ok := s.autossl.State(acct.User); ok {
		for _, res := range st.Results {
			if res.Status == "failed" {
				problems = append(problems, map[string]string{"domain": res.Domain, "problem": res.Problem})
			}
		}
	}
	writeUAPISuccess(w, "SSL", "get_autossl_problems", problems)
}

func (s *Server) uapiSSLGetAutoSSLRenewalStatus(w http.ResponseWriter, r *http.Request, acct Account, _ string) {
	if s.autossl == nil {
		writeUAPIError(w, "SSL", "get_autossl_renewal_status", []string{"AutoSSL is not configured on this server"})
		return
	}
	if st, ok := s.autossl.State(acct.User); ok {
		writeUAPISuccess(w, "SSL", "get_autossl_renewal_status", map[string]any{
			"last_run": st.LastRun.Format(time.RFC3339),
			"results":  st.Results,
		})
		return
	}
	writeUAPISuccess(w, "SSL", "get_autossl_renewal_status", map[string]any{"last_run": nil, "results": []any{}})
}

func (s *Server) uapiSSLIsAutoSSLCheckInProgress(w http.ResponseWriter, r *http.Request, acct Account, _ string) {
	inProgress := false
	if s.autossl != nil {
		inProgress = s.autossl.InProgress(acct.User)
	}
	writeUAPISuccess(w, "SSL", "is_autossl_check_in_progress", inProgress)
}
