package mailhost

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Forwarders use the reference's valiases format: one "localpart: dest"
// line per domain file at <mail-homes>/valiases/<domain>. Domain forwarders
// are the same file with a catchall-domain entry; the default address is
// the "*: ..." row (:fail:, :blackhole:, or a real destination).

// Forwarder is one source localpart → destination row.
type Forwarder struct {
	Domain    string `json:"domain"`
	Localpart string `json:"localpart"`
	Dest      string `json:"dest"`
}

func (s *LocalService) valiasesPath(domain string) string {
	return filepath.Join(s.Homes, "valiases", domain)
}

func (s *LocalService) readValiases(domain string) ([]string, error) {
	raw, err := os.ReadFile(s.valiasesPath(domain))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, nil
}

func (s *LocalService) writeValiases(domain string, lines []string) error {
	dir := filepath.Join(s.Homes, "valiases")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	sort.Strings(lines)
	body := ""
	if len(lines) > 0 {
		body = strings.Join(lines, "\n") + "\n"
	}
	tmp := s.valiasesPath(domain) + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.valiasesPath(domain)); err != nil {
		return err
	}
	return s.writeEximData()
}

// parseFwd splits "localpart: dest"; destinations may contain colons only
// for the special :fail:/:blackhole: forms which are handled before this.
func parseFwd(line string) (string, string, bool) {
	i := strings.Index(line, ":")
	if i <= 0 {
		return "", "", false
	}
	return line[:i], strings.TrimSpace(line[i+1:]), true
}

// validDest rejects shell-shaped destinations; pipe destinations are a
// later batch (they execute, so they get their own policy).
func validDest(dest string) bool {
	if dest == ":fail:" || dest == ":blackhole:" {
		return true
	}
	if strings.HasPrefix(dest, "|") {
		return false
	}
	if strings.ContainsAny(dest, "\x00\n\r;&|<>$`") {
		return false
	}
	return strings.Contains(dest, "@")
}

func (s *LocalService) AddForwarder(ctx context.Context, account, domain, localpart, dest string) error {
	if err := ValidateLocalpart(localpart); err != nil {
		return err
	}
	if !validDest(dest) {
		return fmt.Errorf("destination %q is not a valid forward target", dest)
	}
	lines, err := s.readValiases(domain)
	if err != nil {
		return err
	}
	row := localpart + ": " + dest
	for _, l := range lines {
		lp, _, ok := parseFwd(l)
		if ok && lp == localpart {
			return fmt.Errorf("A forwarder for “%s@%s” already exists.", localpart, domain)
		}
	}
	return s.writeValiases(domain, append(lines, row))
}

func (s *LocalService) DeleteForwarder(ctx context.Context, account, domain, localpart, dest string) error {
	lines, err := s.readValiases(domain)
	if err != nil {
		return err
	}
	row := localpart + ": " + dest
	out := []string{}
	found := false
	for _, l := range lines {
		if l == row {
			found = true
			continue
		}
		out = append(out, l)
	}
	if !found {
		return fmt.Errorf("The forwarder “%s@%s” → “%s” does not exist.", localpart, domain, dest)
	}
	return s.writeValiases(domain, out)
}

func (s *LocalService) ListForwarders(ctx context.Context, account, domain string) ([]Forwarder, error) {
	lines, err := s.readValiases(domain)
	if err != nil {
		return nil, err
	}
	out := []Forwarder{}
	for _, l := range lines {
		lp, dest, ok := parseFwd(l)
		if ok && lp != "*" {
			out = append(out, Forwarder{Domain: domain, Localpart: lp, Dest: dest})
		}
	}
	return out, nil
}

func (s *LocalService) CountForwarders(ctx context.Context, account, domain string) (int, error) {
	f, err := s.ListForwarders(ctx, account, domain)
	return len(f), err
}

// AddDomainForwarder forwards every address of srcDomain to the same
// localpart at destDomain (the reference's domain forwarder row).
func (s *LocalService) AddDomainForwarder(ctx context.Context, account, srcDomain, destDomain string) error {
	if !strings.Contains(destDomain, ".") {
		return fmt.Errorf("destination domain %q is invalid", destDomain)
	}
	lines, err := s.readValiases(srcDomain)
	if err != nil {
		return err
	}
	row := "*domainfwd*: " + destDomain
	for _, l := range lines {
		if strings.HasPrefix(l, "*domainfwd*:") {
			return fmt.Errorf("A domain forwarder for “%s” already exists.", srcDomain)
		}
	}
	return s.writeValiases(srcDomain, append(lines, row))
}

func (s *LocalService) DeleteDomainForwarder(ctx context.Context, account, domain string) error {
	lines, err := s.readValiases(domain)
	if err != nil {
		return err
	}
	out := []string{}
	found := false
	for _, l := range lines {
		if strings.HasPrefix(l, "*domainfwd*:") {
			found = true
			continue
		}
		out = append(out, l)
	}
	if !found {
		return fmt.Errorf("No domain forwarder exists for “%s”.", domain)
	}
	return s.writeValiases(domain, out)
}

func (s *LocalService) ListDomainForwarders(ctx context.Context, account string) (map[string]string, error) {
	out := map[string]string{}
	dir := filepath.Join(s.Homes, "valiases")
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		lines, err := s.readValiases(e.Name())
		if err != nil {
			continue
		}
		for _, l := range lines {
			if strings.HasPrefix(l, "*domainfwd*:") {
				_, dest, _ := parseFwd(l)
				out[e.Name()] = dest
			}
		}
	}
	return out, nil
}

// SetDefaultAddress sets the catch-all row ("*: dest").
func (s *LocalService) SetDefaultAddress(ctx context.Context, account, domain, dest string) error {
	if !validDest(dest) && !strings.HasPrefix(dest, ":fail") {
		return fmt.Errorf("destination %q is not a valid default address target", dest)
	}
	lines, err := s.readValiases(domain)
	if err != nil {
		return err
	}
	out := []string{}
	for _, l := range lines {
		if lp, _, ok := parseFwd(l); ok && lp == "*" {
			continue
		}
		out = append(out, l)
	}
	return s.writeValiases(domain, append(out, "*: "+dest))
}

func (s *LocalService) ListDefaultAddress(ctx context.Context, account, domain string) (string, error) {
	lines, err := s.readValiases(domain)
	if err != nil {
		return "", err
	}
	for _, l := range lines {
		if lp, dest, ok := parseFwd(l); ok && lp == "*" {
			return dest, nil
		}
	}
	return "", nil
}
