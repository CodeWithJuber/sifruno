package tlshost

// tls.autossl batch 3: the AutoSSL runner. RunCheck walks an account's
// domains, skips certificates still valid beyond RenewBeforeDays, issues
// the rest over ACME DNS-01, installs them via Store.Install, and records
// per-domain outcomes in <root>/_acme/autossl-state.json — the truth
// behind get_autossl_problems / get_autossl_renewal_status.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RenewalState is one domain's outcome from the last check.
type RenewalState struct {
	Domain        string `json:"domain"`
	Status        string `json:"status"` // covered | issued | failed
	Problem       string `json:"problem,omitempty"`
	DaysRemaining int    `json:"days_remaining,omitempty"`
}

// AccountState is the persisted per-account AutoSSL record.
type AccountState struct {
	LastRun time.Time      `json:"last_run"`
	Results []RenewalState `json:"results"`
}

// Runner executes AutoSSL checks against a Store + ACMEClient.
type Runner struct {
	Store     *Store
	ACME      *ACMEClient
	Publisher ChallengePublisher
	// RenewBeforeDays: certificates expiring within this window (or
	// missing) are re-issued. cPanel AutoSSL renews at ~30 days.
	RenewBeforeDays int

	mu         sync.Mutex
	inProgress map[string]bool
}

func (r *Runner) renewBefore() int {
	if r.RenewBeforeDays <= 0 {
		return 30
	}
	return r.RenewBeforeDays
}

func (r *Runner) statePath() string {
	return filepath.Join(r.Store.Root, "_acme", "autossl-state.json")
}

// InProgress reports whether a check is running for the account.
func (r *Runner) InProgress(account string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inProgress[account]
}

// State returns the persisted last-check record for an account.
func (r *Runner) State(account string) (AccountState, bool) {
	raw, err := os.ReadFile(r.statePath())
	if errors.Is(err, os.ErrNotExist) {
		return AccountState{}, false
	}
	if err != nil {
		return AccountState{}, false
	}
	m := map[string]AccountState{}
	if json.Unmarshal(raw, &m) != nil {
		return AccountState{}, false
	}
	st, ok := m[account]
	return st, ok
}

// PurgeAccount drops an account's AutoSSL state entry (removeacct hook),
// keeping the zero-residue guarantee for the _acme state directory.
func (r *Runner) PurgeAccount(account string) error {
	raw, err := os.ReadFile(r.statePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	m := map[string]AccountState{}
	if json.Unmarshal(raw, &m) != nil {
		return nil // unreadable state: leave it, purge must not fail removeacct
	}
	if _, ok := m[account]; !ok {
		return nil
	}
	delete(m, account)
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.statePath() + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.statePath())
}

func (r *Runner) saveState(account string, st AccountState) error {
	if err := os.MkdirAll(filepath.Dir(r.statePath()), 0o700); err != nil {
		return err
	}
	m := map[string]AccountState{}
	if raw, err := os.ReadFile(r.statePath()); err == nil {
		_ = json.Unmarshal(raw, &m)
	}
	m[account] = st
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.statePath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.statePath())
}

// RunCheck issues/renews certificates for the account's domains and
// persists the outcome. Synchronous and bounded by ACME.OrderTimeout per
// domain; is_autossl_check_in_progress reflects the in-flight run.
func (r *Runner) RunCheck(ctx context.Context, account string, domains []string) ([]RenewalState, error) {
	if r.ACME == nil || r.Publisher == nil {
		return nil, errors.New("autossl is not configured (no ACME client/publisher)")
	}
	r.mu.Lock()
	if r.inProgress == nil {
		r.inProgress = map[string]bool{}
	}
	if r.inProgress[account] {
		r.mu.Unlock()
		return nil, errors.New("an AutoSSL check is already in progress for this account")
	}
	r.inProgress[account] = true
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.inProgress, account)
		r.mu.Unlock()
	}()

	results := []RenewalState{}
	for _, domain := range domains {
		st := RenewalState{Domain: domain, Status: "covered"}
		info, err := r.Store.Info(ctx, domain)
		switch {
		case err == nil && info.DaysRemaining > r.renewBefore():
			st.DaysRemaining = info.DaysRemaining
		default:
			leaf, key, chain, ierr := r.ACME.Issue(ctx, []string{domain}, r.Publisher)
			if ierr != nil {
				st.Status = "failed"
				st.Problem = ierr.Error()
			} else if _, ierr := r.Store.Install(ctx, domain, leaf, key, chain); ierr != nil {
				st.Status = "failed"
				st.Problem = "install: " + ierr.Error()
			} else {
				st.Status = "issued"
				if info2, err := r.Store.Info(ctx, domain); err == nil {
					st.DaysRemaining = info2.DaysRemaining
				}
			}
		}
		results = append(results, st)
	}
	if err := r.saveState(account, AccountState{LastRun: time.Now().UTC(), Results: results}); err != nil {
		return results, err
	}
	return results, nil
}
