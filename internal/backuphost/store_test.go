package backuphost

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newBackupStore(t *testing.T) (*Store, string) {
	t.Helper()
	root := t.TempDir()
	homes := filepath.Join(root, "mail")
	dns := filepath.Join(root, "dns")
	// seed mail + dns truth
	os.MkdirAll(filepath.Join(homes, "acct1", "etc", "example.com"), 0o700)
	os.WriteFile(filepath.Join(homes, "acct1", "etc", "example.com", "passwd"), []byte("info@example.com:hash\n"), 0o600)
	os.MkdirAll(filepath.Join(homes, "valiases"), 0o700)
	os.WriteFile(filepath.Join(homes, "valiases", "example.com"), []byte("info: dest@x.test\n"), 0o644)
	os.MkdirAll(dns, 0o755)
	os.WriteFile(filepath.Join(dns, "example.com.db"), []byte("$TTL 14400\n"), 0o644)

	st := &Store{
		Root:      filepath.Join(root, "backups"),
		MailHomes: homes,
		DNSRoot:   dns,
		Databases: func(ctx context.Context, account string) ([]string, error) {
			return []string{}, nil // dump skipped without a server
		},
		AccountDomains: func(account string) []string { return []string{"example.com"} },
		PanelVersion:   "11.138.0.11",
	}
	return st, root
}

func tarList(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	names := []string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
	}
	return names
}

func TestCreateListDelete(t *testing.T) {
	ctx := context.Background()
	st, _ := newBackupStore(t)
	info, err := st.Create(ctx, "acct1")
	if err != nil {
		t.Fatal(err)
	}
	if info.Size <= 0 || !strings.HasPrefix(info.File, "backup-") {
		t.Fatalf("info: %+v", info)
	}
	p, err := st.Path("acct1", info.File)
	if err != nil {
		t.Fatal(err)
	}
	names := tarList(t, p)
	joined := strings.Join(names, "\n")
	for _, want := range []string{
		"cp/acct1/meta.json",
		"cp/acct1/mail/etc/example.com/passwd",
		"cp/acct1/mail/valiases/example.com",
		"cp/acct1/dns/example.com.db",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("archive missing %s:\n%s", want, joined)
		}
	}
	list, err := st.List(ctx, "acct1")
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %v", list, err)
	}
	if err := st.Delete(ctx, "acct1", info.File); err != nil {
		t.Fatal(err)
	}
	if list, _ := st.List(ctx, "acct1"); len(list) != 0 {
		t.Fatal("list after delete")
	}
}

func TestBackupValidation(t *testing.T) {
	ctx := context.Background()
	st, _ := newBackupStore(t)
	if _, err := st.Create(ctx, "../evil"); err == nil {
		t.Fatal("traversal account accepted")
	}
	if _, err := st.Create(ctx, "acct1"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Path("acct1", "../../etc/passwd"); err == nil {
		t.Fatal("traversal file accepted")
	}
	if _, err := st.Path("acct1", "backup-2099-01-01T00-00-00Z_acct1.tar.gz"); err == nil {
		t.Fatal("nonexistent backup reported found")
	}
	if _, err := st.List(ctx, "nosuchacct"); err != nil {
		t.Fatalf("list for empty account should be empty, got %v", err)
	}
}

func TestPurge(t *testing.T) {
	ctx := context.Background()
	st, _ := newBackupStore(t)
	if _, err := st.Create(ctx, "acct1"); err != nil {
		t.Fatal(err)
	}
	n, err := st.Purge(ctx, "acct1")
	if err != nil || n != 1 {
		t.Fatalf("purge: %d %v", n, err)
	}
	if _, err := os.Stat(filepath.Join(st.Root, "acct1")); !os.IsNotExist(err) {
		t.Fatal("account backup dir not removed")
	}
}
