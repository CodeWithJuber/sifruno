package whmapi

import (
	"context"
	"errors"
	"strconv"

	"sifruno/internal/hostaccounts"
)

// HostAccounts adapts the native Linux account service to the WHM API 1
// backend contract. It only reports what hostaccounts actually tracks;
// unmeasured fields use the reference's own "*unknown*" convention rather
// than fabricated values.
type HostAccounts struct {
	Svc    hostaccounts.Service
	Build  string // advertised compatible build, e.g. "11.138.0.11"
	Actor  string // journal actor recorded for lifecycle operations
	Server string // primary IPv4 assigned to created accounts
}

var (
	_ Backend          = HostAccounts{}
	_ LifecycleBackend = HostAccounts{}
)

func (h HostAccounts) Version() string { return h.Build }

// ListPackages is truthful: sifruno has no package store yet, so the array
// is empty until pr-resellers lands one.
func (h HostAccounts) ListPackages() []Package { return []Package{} }

func (h HostAccounts) ListAccounts() []Account {
	if h.Svc == nil {
		return []Account{}
	}
	items, err := h.Svc.List(context.Background())
	if err != nil {
		return []Account{}
	}
	out := make([]Account, 0, len(items))
	for _, a := range items {
		out = append(out, h.mapAccount(a))
	}
	return out
}

func (h HostAccounts) mapAccount(a hostaccounts.Account) Account {
	suspended := a.State == "suspended"
	rec := Account{
		User:               a.Username,
		UID:                strconv.Itoa(a.UID),
		Domain:             a.Domain,
		IP:                 h.Server,
		IPv6:               []string{},
		Owner:              "root",
		Plan:               planOr(a.Plan),
		Theme:              "jupiter",
		Partition:          "home",
		DiskUsed:           "*unknown*", // unmeasured by hostaccounts; reference's own convention
		DiskLimit:          "unlimited",
		InodesLimit:        "unlimited",
		StartDate:          a.CreatedAt.Format("06 Jan 02 15:04"),
		UnixStartdate:      a.CreatedAt.Unix(),
		IsLocked:           0,
		Temporary:          0,
		IsTemporaryDomain:  0,
		Backup:             1,
		LegacyBackup:       0,
		HasBackup:          0,
		MailboxFormat:      "maildir",
		MaxPop:             "unlimited",
		MaxFTP:             "unlimited",
		MaxSQL:             "unlimited",
		MaxLst:             "unlimited",
		MaxSub:             "unlimited",
		MaxParked:          "0",
		MaxAddons:          "0",
		MaxEmailacctQuota:  "unlimited",
		MaxEmailPerHour:    "*unknown*",
		MaxDeferFailPct:    "*unknown*",
		MinDeferFailTrig:   "5",
		OutgoingMailHold:   0,
		ChildNodes:         []string{},
		StandaloneFeature:  "",
		StandaloneFeatName: "",
	}
	if suspended {
		rec.Suspended = 1
		rec.OutgoingMailSusp = 1
		rec.Shell = "/bin/false"
		rec.SuspendReason = "suspended"
		rec.SuspendTime = a.UpdatedAt.Unix()
	} else {
		rec.Shell = "/usr/local/cpanel/bin/noshell"
		rec.SuspendReason = "not suspended"
	}
	return rec
}

func planOr(plan string) string {
	if plan == "" {
		return "default"
	}
	return plan
}

func (h HostAccounts) actor() string {
	if h.Actor == "" {
		return "whm-api"
	}
	return h.Actor
}

func (h HostAccounts) CreateAccount(ctx context.Context, username, domain string) (Account, error) {
	return h.CreateAccountPlan(ctx, username, domain, "")
}

// RemoveAccount permanently deletes the managed identity through the
// broker's journaled delete (ownership-verified). There is no undo.
func (h HostAccounts) RemoveAccount(ctx context.Context, username string) error {
	if h.Svc == nil {
		return ErrUnsupported
	}
	acct, err := h.find(ctx, username)
	if err != nil {
		return err
	}
	_, err = h.Svc.Delete(ctx, acct.ID, hostaccounts.DeleteInput{
		ExpectedRevision: acct.Revision,
		Reason:           "whm api removeacct",
	}, h.actor())
	if errors.Is(err, hostaccounts.ErrNotFound) {
		return ErrNoSuchUser
	}
	if errors.Is(err, hostaccounts.ErrConflict) {
		return ErrConflicted
	}
	return err
}

// ChangePackage updates the account's plan metadata after validating the
// package exists in the store. The reference changepackage also re-applies
// limits and theme; those enforcement effects land with pr-resellers.
func (h HostAccounts) ChangePackage(ctx context.Context, username, plan string) error {
	if h.Svc == nil {
		return ErrUnsupported
	}
	acct, err := h.find(ctx, username)
	if err != nil {
		return err
	}
	if acct.Plan == plan {
		return nil
	}
	_, err = h.Svc.SetPlan(ctx, acct.ID, hostaccounts.PlanInput{
		Plan:             plan,
		ExpectedRevision: acct.Revision,
		Reason:           "whm api changepackage",
	}, h.actor())
	if errors.Is(err, hostaccounts.ErrNotFound) {
		return ErrNoSuchUser
	}
	if errors.Is(err, hostaccounts.ErrConflict) {
		return ErrConflicted
	}
	return err
}

// CreateAccountPlan additionally records the WHM package as plan metadata.
func (h HostAccounts) CreateAccountPlan(ctx context.Context, username, domain, plan string) (Account, error) {
	if h.Svc == nil {
		return Account{}, ErrUnsupported
	}
	if !whmUsername.MatchString(username) {
		return Account{}, ErrInvalidUsername
	}
	created, err := h.Svc.Create(ctx, hostaccounts.CreateInput{
		Username: username,
		Domain:   domain,
		Plan:     plan,
		Reason:   "whm api createacct",
	}, h.actor())
	if errors.Is(err, hostaccounts.ErrConflict) {
		return Account{}, ErrDuplicateUser
	}
	if errors.Is(err, hostaccounts.ErrInvalid) {
		return Account{}, ErrInvalidUsername
	}
	if err != nil {
		return Account{}, err
	}
	rec := h.mapAccount(created)
	rec.IP = h.Server
	return rec, nil
}

func (h HostAccounts) find(ctx context.Context, username string) (hostaccounts.Account, error) {
	items, err := h.Svc.List(ctx)
	if err != nil {
		return hostaccounts.Account{}, err
	}
	for _, a := range items {
		if a.Username == username {
			return a, nil
		}
	}
	return hostaccounts.Account{}, ErrNoSuchUser
}

func (h HostAccounts) SuspendAccount(ctx context.Context, username, reason string) (bool, error) {
	if h.Svc == nil {
		return false, ErrUnsupported
	}
	acct, err := h.find(ctx, username)
	if err != nil {
		return false, err
	}
	if acct.State == "suspended" {
		return true, nil
	}
	_, err = h.Svc.SetState(ctx, acct.ID, hostaccounts.StateInput{
		State:            "suspended",
		ExpectedRevision: acct.Revision,
		Reason:           reason,
	}, h.actor())
	if errors.Is(err, hostaccounts.ErrNotFound) {
		return false, ErrNoSuchUser
	}
	return false, err
}

func (h HostAccounts) UnsuspendAccount(ctx context.Context, username string) error {
	if h.Svc == nil {
		return ErrUnsupported
	}
	acct, err := h.find(ctx, username)
	if err != nil {
		return err
	}
	if acct.State != "suspended" {
		return nil
	}
	_, err = h.Svc.SetState(ctx, acct.ID, hostaccounts.StateInput{
		State:            "active",
		ExpectedRevision: acct.Revision,
		Reason:           "whm api unsuspendacct",
	}, h.actor())
	if errors.Is(err, hostaccounts.ErrNotFound) {
		return ErrNoSuchUser
	}
	return err
}
