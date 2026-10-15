package mailhost

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrUnavailable is returned when the mailbox store is not reachable.
var ErrUnavailable = errors.New("mail store unavailable")

// Mailbox is one account-owned mailbox (cPanel layout: localpart@domain,
// Maildir at <homes>/<account>/mail/<domain>/<localpart>).
type Mailbox struct {
	Email     string `json:"email"`   // localpart@domain
	Account   string `json:"account"` // owning panel account
	Domain    string `json:"domain"`  // mailbox domain
	Localpart string `json:"localpart"`
	QuotaMiB  int    `json:"quota_mib"` // 0 = account default
}

// Localpart policy: cPanel permits dot/underscore/dash/plus; reject the rest.
var localpartRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,63}$`)

func ValidateLocalpart(lp string) error {
	if !localpartRe.MatchString(lp) {
		return fmt.Errorf("mailbox name %q contains invalid characters", lp)
	}
	if strings.Contains(lp, "..") {
		return fmt.Errorf("mailbox name %q contains consecutive dots", lp)
	}
	return nil
}

// Service is the mailbox lifecycle contract.
type Service interface {
	CreateMailbox(ctx context.Context, account, domain, localpart, password string, quotaMiB int) (Mailbox, error)
	DeleteMailbox(ctx context.Context, account, email string) error
	SetPassword(ctx context.Context, account, email, password string) error
	SetQuota(ctx context.Context, account, email string, quotaMiB int) error
	Quota(ctx context.Context, account, email string) (int, error)
	ListMailboxes(ctx context.Context, account string) ([]Mailbox, error)
	CountMailboxes(ctx context.Context, account string) (int, error)
	VerifyPassword(ctx context.Context, account, email, password string) (bool, error)

	// Forwarders (valiases store)
	AddForwarder(ctx context.Context, account, domain, localpart, dest string) error
	DeleteForwarder(ctx context.Context, account, domain, localpart, dest string) error
	ListForwarders(ctx context.Context, account, domain string) ([]Forwarder, error)
	CountForwarders(ctx context.Context, account, domain string) (int, error)
	AddDomainForwarder(ctx context.Context, account, srcDomain, destDomain string) error
	DeleteDomainForwarder(ctx context.Context, account, domain string) error
	ListDomainForwarders(ctx context.Context, account string) (map[string]string, error)
	SetDefaultAddress(ctx context.Context, account, domain, dest string) error
	ListDefaultAddress(ctx context.Context, account, domain string) (string, error)

	// PurgeAccount removes a terminated account's mailboxes and mail root.
	PurgeAccount(ctx context.Context, account string, domains []string) (purged int, errs []string)
}
