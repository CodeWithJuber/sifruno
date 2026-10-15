package mailhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// LocalService implements the mailbox lifecycle against the host layout the
// reference uses: per-domain passwd+shadow files under the account's etc
// dir and Maildirs under mail/. Passwords are SHA512-CRYPT via doveadm
// (openssl -6 fallback). The registry (mailmap.json) is the query source;
// passwd files are the auth truth Dovecot reads.
type LocalService struct {
	Homes   string // /srv/sfn-homes
	State   string // panel state dir (mailmap.json)
	Doveadm string // doveadm path; default "doveadm"

	mu        sync.Mutex
	mailboxes map[string]Mailbox
	loaded    bool
}

func (s *LocalService) mapPath() string { return filepath.Join(s.State, "mailmap.json") }

func (s *LocalService) load() error {
	if s.loaded {
		return nil
	}
	s.mailboxes = map[string]Mailbox{}
	raw, err := os.ReadFile(s.mapPath())
	if errors.Is(err, os.ErrNotExist) {
		s.loaded = true
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &s.mailboxes); err != nil {
		return err
	}
	s.loaded = true
	return nil
}

func (s *LocalService) flush() error {
	if err := os.MkdirAll(s.State, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s.mailboxes, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.mapPath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.mapPath())
}

func (s *LocalService) etcDir(m Mailbox) string {
	return filepath.Join(s.Homes, m.Account, "etc", m.Domain)
}

func (s *LocalService) maildir(m Mailbox) string {
	return filepath.Join(s.Homes, m.Account, "mail", m.Domain, m.Localpart)
}

// hashPassword returns a {SHA512-CRYPT} hash via doveadm, falling back to
// openssl passwd -6 when doveadm is absent (same underlying crypt).
func (s *LocalService) hashPassword(password string) (string, error) {
	bin := s.Doveadm
	if bin == "" {
		bin = "doveadm"
	}
	if _, err := exec.LookPath(bin); err == nil {
		out, err := exec.Command(bin, "pw", "-s", "SHA512-CRYPT", "-p", password).Output()
		if err == nil {
			return strings.TrimSpace(string(out)), nil
		}
	}
	out, err := exec.Command("openssl", "passwd", "-6", password).Output()
	if err != nil {
		return "", fmt.Errorf("no password hasher available (doveadm/openssl)")
	}
	return "{SHA512-CRYPT}" + strings.TrimSpace(string(out)), nil
}

// passwdLine is the dovecot passwd-file row cPanel writes.
func passwdLine(m Mailbox, hash string) string {
	return fmt.Sprintf("%s:%s:%d:%d::%s::userdb_quota_rule=*:bytes=%dM",
		m.Email, hash, 1000, 1000, filepath.Join("mail", m.Domain, m.Localpart), m.QuotaMiB)
}

// writeAuth rewrites the domain passwd+shadow files from the registry.
// The directory is derived from account+domain so an emptied domain still
// gets its stale auth rows rewritten away.
func (s *LocalService) writeAuth(account, domain string) error {
	dir := filepath.Join(s.Homes, account, "etc", domain)
	lines := []string{}
	shadow := []string{}
	for _, m := range s.mailboxes {
		if m.Domain != domain {
			continue
		}
		h, ok := s.shadowHash(m.Email)
		if !ok {
			continue
		}
		lines = append(lines, passwdLine(m, h))
		shadow = append(shadow, m.Email+":"+h)
	}
	if err := os.MkdirAll(dir, 0o770); err != nil {
		return err
	}
	sort.Strings(lines)
	sort.Strings(shadow)
	if err := os.WriteFile(filepath.Join(dir, "passwd"), []byte(strings.Join(lines, "\n")+"\n"), 0o660); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "shadow"), []byte(strings.Join(shadow, "\n")+"\n"), 0o600)
}

// shadow store: separate map so hashes never land in the query registry JSON.
func (s *LocalService) shadowPath() string { return filepath.Join(s.State, "mailshadow.json") }

func (s *LocalService) loadShadow() (map[string]string, error) {
	out := map[string]string{}
	raw, err := os.ReadFile(s.shadowPath())
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	return out, json.Unmarshal(raw, &out)
}

func (s *LocalService) shadowHash(email string) (string, bool) {
	m, err := s.loadShadow()
	if err != nil {
		return "", false
	}
	h, ok := m[email]
	return h, ok
}

func (s *LocalService) putShadow(email, hash string) error {
	if err := os.MkdirAll(s.State, 0o700); err != nil {
		return err
	}
	m, err := s.loadShadow()
	if err != nil {
		return err
	}
	m[email] = hash
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp := s.shadowPath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.shadowPath())
}

func (s *LocalService) dropShadow(email string) error {
	if err := os.MkdirAll(s.State, 0o700); err != nil {
		return err
	}
	m, err := s.loadShadow()
	if err != nil {
		return err
	}
	delete(m, email)
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp := s.shadowPath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.shadowPath())
}

func (s *LocalService) CreateMailbox(ctx context.Context, account, domain, localpart, password string, quotaMiB int) (Mailbox, error) {
	if err := s.load(); err != nil {
		return Mailbox{}, err
	}
	if err := ValidateLocalpart(localpart); err != nil {
		return Mailbox{}, err
	}
	if strings.ContainsAny(password, "\x00\n\r") {
		return Mailbox{}, errors.New("password contains control characters")
	}
	if quotaMiB < 0 {
		return Mailbox{}, errors.New("quota cannot be negative")
	}
	m := Mailbox{Email: localpart + "@" + domain, Account: account, Domain: domain, Localpart: localpart, QuotaMiB: quotaMiB}
	s.mu.Lock()
	if _, exists := s.mailboxes[m.Email]; exists {
		s.mu.Unlock()
		return Mailbox{}, fmt.Errorf("The email account “%s” already exists.", m.Email)
	}
	s.mu.Unlock()
	hash, err := s.hashPassword(password)
	if err != nil {
		return Mailbox{}, err
	}
	// Maildir: maildir-style skeleton (cur new tmp)
	for _, sub := range []string{"cur", "new", "tmp"} {
		if err := os.MkdirAll(filepath.Join(s.maildir(m), sub), 0o700); err != nil {
			return Mailbox{}, err
		}
	}
	if err := s.putShadow(m.Email, hash); err != nil {
		return Mailbox{}, err
	}
	s.mu.Lock()
	s.mailboxes[m.Email] = m
	err = s.flush()
	s.mu.Unlock()
	if err != nil {
		return Mailbox{}, err
	}
	return m, s.writeAuth(account, domain)
}

func (s *LocalService) DeleteMailbox(ctx context.Context, account, email string) error {
	if err := s.load(); err != nil {
		return err
	}
	s.mu.Lock()
	m, ok := s.mailboxes[email]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("The email account “%s” does not exist.", email)
	}
	if m.Account != account {
		s.mu.Unlock()
		return errors.New("access denied: mailbox belongs to another account")
	}
	delete(s.mailboxes, email)
	err := s.flush()
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if err := s.dropShadow(email); err != nil {
		return err
	}
	if err := os.RemoveAll(s.maildir(m)); err != nil {
		return err
	}
	return s.writeAuth(account, m.Domain)
}

func (s *LocalService) SetPassword(ctx context.Context, account, email, password string) error {
	if err := s.load(); err != nil {
		return err
	}
	s.mu.Lock()
	m, ok := s.mailboxes[email]
	s.mu.Unlock()
	if !ok {
		return fmt.Errorf("The email account “%s” does not exist.", email)
	}
	if m.Account != account {
		return errors.New("access denied: mailbox belongs to another account")
	}
	if strings.ContainsAny(password, "\x00\n\r") {
		return errors.New("password contains control characters")
	}
	hash, err := s.hashPassword(password)
	if err != nil {
		return err
	}
	if err := s.putShadow(email, hash); err != nil {
		return err
	}
	return s.writeAuth(account, m.Domain)
}

func (s *LocalService) SetQuota(ctx context.Context, account, email string, quotaMiB int) error {
	if quotaMiB < 0 {
		return errors.New("quota cannot be negative")
	}
	if err := s.load(); err != nil {
		return err
	}
	s.mu.Lock()
	m, ok := s.mailboxes[email]
	if ok && m.Account == account {
		m.QuotaMiB = quotaMiB
		s.mailboxes[email] = m
		err := s.flush()
		s.mu.Unlock()
		if err != nil {
			return err
		}
		return s.writeAuth(account, m.Domain)
	}
	s.mu.Unlock()
	if !ok {
		return fmt.Errorf("The email account “%s” does not exist.", email)
	}
	return errors.New("access denied: mailbox belongs to another account")
}

func (s *LocalService) Quota(ctx context.Context, account, email string) (int, error) {
	if err := s.load(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.mailboxes[email]
	if !ok {
		return 0, fmt.Errorf("The email account “%s” does not exist.", email)
	}
	if m.Account != account {
		return 0, errors.New("access denied: mailbox belongs to another account")
	}
	return m.QuotaMiB, nil
}

func (s *LocalService) ListMailboxes(ctx context.Context, account string) ([]Mailbox, error) {
	if err := s.load(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Mailbox{}
	for _, m := range s.mailboxes {
		if account == "" || m.Account == account {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out, nil
}

func (s *LocalService) CountMailboxes(ctx context.Context, account string) (int, error) {
	l, err := s.ListMailboxes(ctx, account)
	return len(l), err
}

// VerifyPassword checks against the domain shadow truth with doveadm when
// present (real auth path), else crypt-compare via openssl.
func (s *LocalService) VerifyPassword(ctx context.Context, account, email, password string) (bool, error) {
	if err := s.load(); err != nil {
		return false, err
	}
	s.mu.Lock()
	m, ok := s.mailboxes[email]
	s.mu.Unlock()
	if !ok || m.Account != account {
		return false, fmt.Errorf("The email account “%s” does not exist.", email)
	}
	stored, ok := s.shadowHash(email)
	if !ok {
		return false, ErrUnavailable
	}
	stored = strings.TrimPrefix(stored, "{SHA512-CRYPT}")
	bin := s.Doveadm
	if bin == "" {
		bin = "doveadm"
	}
	if _, err := exec.LookPath(bin); err == nil {
		cmd := exec.CommandContext(ctx, bin, "pw", "-s", "SHA512-CRYPT", "-p", password, "-t", "{SHA512-CRYPT}"+stored)
		err = cmd.Run()
		if err == nil {
			return true, nil
		}
		if _, isExit := err.(*exec.ExitError); isExit {
			if ee := err.(*exec.ExitError); ee.ExitCode() == 1 {
				return false, nil // doveadm's clean mismatch
			}
		}
		// doveadm unusable (broken local config, exit 89 etc.) — fall
		// through to the openssl crypt compare.
	}
	out, err := exec.Command("openssl", "passwd", "-6", "-salt", saltOf(stored), password).Output()
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(out)) == stored, nil
}

// saltOf extracts the $6$salt$ portion for verification.
func saltOf(crypt string) string {
	parts := strings.Split(crypt, "$")
	if len(parts) >= 3 {
		return parts[2]
	}
	return ""
}
