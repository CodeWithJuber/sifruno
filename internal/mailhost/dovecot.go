package mailhost

// mail.lifecycle batch 4: aggregate Dovecot passwd-file. The per-domain
// etc/<domain>/passwd files keep the reference's cPanel layout; Dovecot
// authenticates against one aggregate file with absolute home paths at
// <Homes>/dovecot/users (passdb+userdb combined). Login-suspended
// mailboxes get a "!" password prefix so authentication always fails.
// Password hashes never enter the query registry — they come from the
// 0600 shadow store.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// dovecotLine renders one aggregate passwd-file row with an absolute home.
func (s *LocalService) dovecotLine(m Mailbox, hash string) string {
	if m.SuspendedLogin {
		hash = "!" + hash
	}
	home := filepath.Join(s.Homes, m.Account, "mail", m.Domain, m.Localpart)
	return strings.Join([]string{
		m.Email, hash, "2000", "2000", "", home, "",
		"userdb_quota_rule=*:bytes=" + itoa(m.QuotaMiB) + "M",
	}, ":")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for v := n; v > 0; v /= 10 {
		digits = append([]byte{byte('0' + v%10)}, digits...)
	}
	return string(digits)
}

// writeDovecotAggregate rewrites the aggregate auth file from the
// registry + shadow store. Called on every auth-affecting mutation.
func (s *LocalService) writeDovecotAggregate() error {
	dir := filepath.Join(s.Homes, "dovecot")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	lines := []string{}
	for _, m := range s.mailboxes {
		h, ok := s.shadowHash(m.Email)
		if !ok {
			continue
		}
		lines = append(lines, s.dovecotLine(m, h))
	}
	sort.Strings(lines)
	tmp := filepath.Join(dir, "users.tmp")
	if err := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "users"))
}
