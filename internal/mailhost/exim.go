package mailhost

// mail.lifecycle batch 5: Exim-facing routing export. Exim runs as its own
// uid and cannot traverse the 0700 mail-homes root, so — mirroring the
// reference's /etc/localdomains + /etc/valiases pattern — routing truth is
// exported to a root-level directory Exim can read:
//
//	<EximRoot>/localdomains         one domain per line (lsearch key set)
//	<EximRoot>/mailboxes            "email: /abs/maildir" rows (lsearch)
//	<EximRoot>/aliases              "lp@domain: dest" rows flattened from
//	                                valiases (lsearch*; catch-all "*@domain:")
//	<EximRoot>/suspended_incoming   "email: 1" rows denied at RCPT time
//	<EximRoot>/suspended_outgoing   "email: 1" rows denied at MAIL FROM
//
// Files are 0644, dirs 0755 — no secrets cross this boundary (password
// hashes stay in the shadow store and the Dovecot aggregate).

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// eximRoot resolves the export root; empty EximRoot derives a sibling of
// Homes (<srv>/sfn-exim when Homes is <srv>/sfn-mail).
func (s *LocalService) eximRoot() string {
	if s.EximRoot != "" {
		return s.EximRoot
	}
	return filepath.Join(filepath.Dir(s.Homes), "sfn-exim")
}

// writeEximFile writes one export atomically (tmp+rename), 0644 so the
// Exim uid can read it.
func writeEximFile(path, body string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func joinRows(rows []string) string {
	if len(rows) == 0 {
		return ""
	}
	sort.Strings(rows)
	return strings.Join(rows, "\n") + "\n"
}

// writeEximData regenerates the whole export from the registry plus the
// valiases dir. Idempotent; stale valiases exports (terminated domains)
// are removed first. Called on every mail-routing mutation.
func (s *LocalService) writeEximData() error {
	// forwarder mutations come through writeValiases, which never touches
	// the mailbox registry — load it here so the export is complete.
	if err := s.load(); err != nil {
		return err
	}
	root := s.eximRoot()

	s.mu.Lock()
	boxes := make([]Mailbox, 0, len(s.mailboxes))
	for _, m := range s.mailboxes {
		boxes = append(boxes, m)
	}
	s.mu.Unlock()

	domains := map[string]bool{}
	mbRows, incRows, outRows := []string{}, []string{}, []string{}
	for _, m := range boxes {
		domains[m.Domain] = true
		mbRows = append(mbRows, m.Email+": "+s.maildir(m))
		if m.SuspendedIncoming {
			incRows = append(incRows, m.Email+": 1")
		}
		if m.SuspendedOutgoing {
			outRows = append(outRows, m.Email+": 1")
		}
	}

	// Flatten every valiases domain file into one static-path lsearch*
	// file. A single file sidesteps Exim's taint rule (a $domain-derived
	// lookup path is rejected); keys become "lp@domain", the catch-all
	// "*: dest" row becomes "*@domain: dest". Domain forwarders
	// (*domainfwd* rows) are a redirect-with-rewrite feature of a later
	// batch and are skipped here.
	srcV := filepath.Join(s.Homes, "valiases")
	entries, err := os.ReadDir(srcV)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	aliasRows := []string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		domains[e.Name()] = true
		lines, err := s.readValiases(e.Name())
		if err != nil {
			return err
		}
		for _, l := range lines {
			lp, dest, ok := parseFwd(l)
			if !ok || lp == "*domainfwd*" {
				continue
			}
			aliasRows = append(aliasRows, lp+"@"+e.Name()+": "+dest)
		}
	}

	dl := make([]string, 0, len(domains))
	for d := range domains {
		dl = append(dl, d)
	}
	if err := writeEximFile(filepath.Join(root, "localdomains"), joinRows(dl)); err != nil {
		return err
	}
	if err := writeEximFile(filepath.Join(root, "mailboxes"), joinRows(mbRows)); err != nil {
		return err
	}
	if err := writeEximFile(filepath.Join(root, "aliases"), joinRows(aliasRows)); err != nil {
		return err
	}
	if err := writeEximFile(filepath.Join(root, "suspended_incoming"), joinRows(incRows)); err != nil {
		return err
	}
	return writeEximFile(filepath.Join(root, "suspended_outgoing"), joinRows(outRows))
}
