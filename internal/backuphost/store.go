// Package backuphost builds and manages per-account backup archives —
// the backup.archive obligation. Batch 1 archives the panel-owned truth
// (mail auth/forwarders/flags, DNS zones, MySQL dumps, account metadata)
// into a gzip tarball under <root>/<account>/. Account home directories
// are owned by the account uid and require broker assistance; that lands
// in batch 2 and is documented as a delta against the reference, which
// includes homedir content.
package backuphost

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Store manages backup archives.
type Store struct {
	Root string // <state>/backups

	// Inputs describing what to include. All optional; absent inputs are
	// skipped and recorded in the archive metadata.
	MailHomes string // mail surface root (etc/, valiases/)
	DNSRoot   string // zone store root
	DumpBin   string // mariadb-dump/mysqldump binary
	DumpOpts  []string
	// Databases lists the account's database names for dumping.
	Databases func(ctx context.Context, account string) ([]string, error)
	// AccountInfo returns domain list for the account.
	AccountDomains func(account string) []string
	PanelVersion   string
}

// Info describes one stored archive.
type Info struct {
	File    string `json:"file"`
	Size    int64  `json:"size"`
	Created int64  `json:"created"`
	Account string `json:"account"`
}

var acctRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$`)
var fileRe = regexp.MustCompile(`^backup-[0-9TZ.-]+_[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}\.tar\.gz$`)

// ValidateAccount rejects anything but a plain account name.
func ValidateAccount(account string) error {
	if !acctRe.MatchString(account) {
		return errors.New("invalid account name")
	}
	return nil
}

// ValidateFile rejects archive names that are not panel-generated files.
func ValidateFile(name string) error {
	if !fileRe.MatchString(name) {
		return errors.New("invalid backup file name")
	}
	return nil
}

type tarWriter struct {
	gz  *gzip.Writer
	tw  *tar.Writer
	n   int
	err error
}

func (t *tarWriter) addBytes(name string, data []byte, mode int64) {
	if t.err != nil {
		return
	}
	if err := t.tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(data)), ModTime: time.Now()}); err != nil {
		t.err = err
		return
	}
	if _, err := t.tw.Write(data); err != nil {
		t.err = err
		return
	}
	t.n++
}

func (t *tarWriter) addFile(name, src string) {
	if t.err != nil {
		return
	}
	data, err := os.ReadFile(src)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		t.err = err
		return
	}
	t.addBytes(name, data, 0o600)
}

func (t *tarWriter) addTree(prefix, root string) {
	if t.err != nil {
		return
	}
	if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
		return
	}
	t.err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		t.addFile(filepath.ToSlash(filepath.Join(prefix, rel)), path)
		return t.err
	})
}

// dumpDatabase shells out to mariadb-dump/mysqldump for one database.
func (s *Store) dumpDatabase(ctx context.Context, db string) ([]byte, error) {
	bin := s.DumpBin
	if bin == "" {
		bin = "mariadb-dump"
	}
	args := append(append([]string{}, s.DumpOpts...), "--databases", db)
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("dump %s: %v", db, err)
	}
	return out, nil
}

// Create builds the account archive and returns its info.
func (s *Store) Create(ctx context.Context, account string) (Info, error) {
	if err := ValidateAccount(account); err != nil {
		return Info{}, err
	}
	stamp := time.Now().UTC().Format("2006-01-02T15-04-05Z")
	name := fmt.Sprintf("backup-%s_%s.tar.gz", stamp, account)
	dir := filepath.Join(s.Root, account)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Info{}, err
	}
	final := filepath.Join(dir, name)
	tmp := final + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return Info{}, err
	}
	gz := gzip.NewWriter(f)
	tw := &tarWriter{gz: gz, tw: tar.NewWriter(gz)}

	base := "cp/" + account
	meta := map[string]any{
		"account":  account,
		"created":  time.Now().UTC().Format(time.RFC3339),
		"panel":    s.PanelVersion,
		"contents": []string{},
	}
	contents := []string{}

	domains := []string{}
	if s.AccountDomains != nil {
		domains = s.AccountDomains(account)
	}

	// mail: etc/ auth trees + valiases for account domains
	if s.MailHomes != "" {
		for _, d := range domains {
			tw.addTree(filepath.Join(base, "mail/etc", d), filepath.Join(s.MailHomes, account, "etc", d))
			tw.addFile(filepath.Join(base, "mail/valiases", d), filepath.Join(s.MailHomes, "valiases", d))
		}
		contents = append(contents, "mail")
	}
	// dns zones
	if s.DNSRoot != "" {
		for _, d := range domains {
			tw.addFile(filepath.Join(base, "dns", d+".db"), filepath.Join(s.DNSRoot, d+".db"))
			tw.addFile(filepath.Join(base, "dns", d+".json"), filepath.Join(s.DNSRoot, d+".json"))
		}
		contents = append(contents, "dns")
	}
	// mysql dumps
	if s.Databases != nil {
		dbs, err := s.Databases(ctx, account)
		if err != nil {
			f.Close()
			os.Remove(tmp)
			return Info{}, err
		}
		for _, db := range dbs {
			dump, err := s.dumpDatabase(ctx, db)
			if err != nil {
				f.Close()
				os.Remove(tmp)
				return Info{}, err
			}
			tw.addBytes(filepath.Join(base, "mysql", db+".sql"), dump, 0o600)
		}
		contents = append(contents, "mysql")
	}

	meta["contents"] = contents
	metaRaw, _ := json.MarshalIndent(meta, "", "  ")
	tw.addBytes(base+"/meta.json", metaRaw, 0o600)

	if tw.err != nil {
		f.Close()
		os.Remove(tmp)
		return Info{}, tw.err
	}
	if err := tw.tw.Close(); err != nil {
		f.Close()
		os.Remove(tmp)
		return Info{}, err
	}
	if err := gz.Close(); err != nil {
		f.Close()
		os.Remove(tmp)
		return Info{}, err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return Info{}, err
	}
	if err := os.Rename(tmp, final); err != nil {
		return Info{}, err
	}
	fi, err := os.Stat(final)
	if err != nil {
		return Info{}, err
	}
	return Info{File: name, Size: fi.Size(), Created: fi.ModTime().Unix(), Account: account}, nil
}

// List returns the account's archives, newest first.
func (s *Store) List(ctx context.Context, account string) ([]Info, error) {
	if err := ValidateAccount(account); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(s.Root, account))
	if errors.Is(err, os.ErrNotExist) {
		return []Info{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []Info{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".tar.gz") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, Info{File: e.Name(), Size: fi.Size(), Created: fi.ModTime().Unix(), Account: account})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created > out[j].Created })
	return out, nil
}

// Path returns the archive path after validating account and file name.
func (s *Store) Path(account, name string) (string, error) {
	if err := ValidateAccount(account); err != nil {
		return "", err
	}
	if err := ValidateFile(name); err != nil {
		return "", err
	}
	p := filepath.Join(s.Root, account, name)
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("backup not found: %s", name)
	}
	return p, nil
}

// Delete removes one archive.
func (s *Store) Delete(ctx context.Context, account, name string) error {
	p, err := s.Path(account, name)
	if err != nil {
		return err
	}
	return os.Remove(p)
}

// Purge removes all archives of a terminated account.
func (s *Store) Purge(ctx context.Context, account string) (int, error) {
	if err := ValidateAccount(account); err != nil {
		return 0, err
	}
	dir := filepath.Join(s.Root, account)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if err := os.RemoveAll(dir); err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tar.gz") {
			n++
		}
	}
	return n, nil
}
