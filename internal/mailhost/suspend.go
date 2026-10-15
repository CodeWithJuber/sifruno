package mailhost

// mail.lifecycle batch 3: per-mailbox suspend flags (incoming / outgoing /
// login), mirroring the reference's UAPI Email::suspend_* surface. Truth is
// stored in the mailmap registry AND as flag files under the account's etc
// directory, like the reference's on-disk hold flags.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// SuspendFlag names one mailbox suspension class.
type SuspendFlag string

const (
	SuspendIncoming SuspendFlag = "incoming"
	SuspendOutgoing SuspendFlag = "outgoing"
	SuspendLogin    SuspendFlag = "login"
)

// ErrLoginSuspended is reported by the verify_password surface when the
// mailbox login is suspended (the reference rejects authentication then).
var ErrLoginSuspended = errors.New("login is suspended for this mailbox")

func (s *LocalService) flagPath(m Mailbox, flag SuspendFlag) string {
	return filepath.Join(s.Homes, m.Account, "etc", m.Domain,
		fmt.Sprintf("%s.suspended_%s", m.Localpart, flag))
}

// SetSuspend sets or clears one suspend flag on a mailbox owned by the
// account, writing both the registry and the on-disk flag file.
func (s *LocalService) SetSuspend(ctx context.Context, account, email string, flag SuspendFlag, on bool) error {
	switch flag {
	case SuspendIncoming, SuspendOutgoing, SuspendLogin:
	default:
		return errors.New("unknown suspend flag: " + string(flag))
	}
	if err := s.load(); err != nil {
		return err
	}
	s.mu.Lock()
	m, ok := s.mailboxes[email]
	if !ok || m.Account != account {
		s.mu.Unlock()
		return errors.New("mailbox not found: " + email)
	}
	switch flag {
	case SuspendIncoming:
		m.SuspendedIncoming = on
	case SuspendOutgoing:
		m.SuspendedOutgoing = on
	case SuspendLogin:
		m.SuspendedLogin = on
	}
	s.mailboxes[email] = m
	err := s.flush()
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if err := s.writeDovecotAggregate(); err != nil {
		return err
	}
	fp := s.flagPath(m, flag)
	if on {
		if err := os.MkdirAll(filepath.Dir(fp), 0o700); err != nil {
			return err
		}
		return os.WriteFile(fp, []byte("1\n"), 0o600)
	}
	if err := os.Remove(fp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Suspensions reports the current flag set for a mailbox.
func (s *LocalService) Suspensions(ctx context.Context, account, email string) (incoming, outgoing, login bool, err error) {
	if err := s.load(); err != nil {
		return false, false, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.mailboxes[email]
	if !ok || m.Account != account {
		return false, false, false, errors.New("mailbox not found: " + email)
	}
	return m.SuspendedIncoming, m.SuspendedOutgoing, m.SuspendedLogin, nil
}
