//go:build linux

package hostaccounts

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"sifruno/internal/sitesource"
)

func TestServerCopyRunsAsTheFoldersOwner(t *testing.T) {
	src := serverSource{site: sitesource.ServerSite{Server: "nginx", DocRoot: "/var/www/blog"}, owner: sitesource.Owner{Name: "www-data", UID: 33}}
	args, ok := serverFetchArgs("/usr/bin/ssh -p 22", "source.example.test", src, "/stage/files/public_html", 1234)
	if !ok {
		t.Fatal("refused")
	}
	for _, want := range []string{"--rsync-path=/usr/sbin/runuser -u www-data -- /usr/bin/rsync", "--groupmap=nobody:1234,apache:1234,www-data:1234,nginx:1234,*:0", "--exclude=.htaccess", "--chmod=ug-s", "--one-file-system"} {
		if !slices.Contains(args, want) {
			t.Errorf("args lack %q: %v", want, args)
		}
	}
	if args[len(args)-2] != "source.example.test:/var/www/blog/" || args[len(args)-3] != "--" {
		t.Fatalf("source = %v", args)
	}
	src.site.Server = "apache"
	if args, _ = serverFetchArgs("/usr/bin/ssh", "h.example.test", src, "/d", 1); slices.Contains(args, "--exclude=.htaccess") {
		t.Fatal("an Apache site's .htaccess files are left out")
	}
	root := serverSource{site: src.site, owner: sitesource.Owner{Name: "root", UID: 0}}
	if sender, ok := serverSender(root.owner); !ok || sender != "/usr/bin/rsync" {
		t.Fatalf("root's own folder: %q %v", sender, ok)
	}
	for _, bad := range []sitesource.Owner{{Name: "root", UID: 5}, {Name: "x y", UID: 1000}, {Name: "toor", UID: 0}} {
		if _, ok := serverSender(bad); ok {
			t.Errorf("%+v is a sender", bad)
		}
	}
	bad := serverSource{site: sitesource.ServerSite{DocRoot: "/etc"}, owner: src.owner}
	if _, ok := serverFetchArgs("/usr/bin/ssh", "h.example.test", bad, "/d", 1); ok {
		t.Fatal("/etc is copied")
	}
	if home := (serverSource{site: sitesource.ServerSite{DocRoot: "/home/shop/public_html"}}).stagedHome(); home != "/home/shop" {
		t.Fatalf("home = %q", home)
	}
}

func TestServerRulesAndWPConfigAreWrittenIntoTheStagedCopy(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "shop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "wp-config.php"), []byte("<?php\ndefine('DB_NAME', 'wordpress');\ndefine('DB_USER', 'wpuser');\ndefine('DB_PASSWORD', 'x');\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	public, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer public.Close()
	files := map[string]string{"": "# Moved\nRewriteEngine On\n", "private/inner": "# Moved\nRequire all denied\n", "shop": "# Moved\nRequire all denied\n"}
	if err := writeConverted(public, files); err != nil {
		t.Fatal(err)
	}
	for folder, text := range files {
		got, err := os.ReadFile(filepath.Join(dir, folder, ".htaccess"))
		if err != nil || string(got) != text {
			t.Fatalf("%s: %q %v", folder, got, err)
		}
	}
	// A file already there is never overwritten.
	var failed *MigrationError
	if err := writeConverted(public, map[string]string{"shop": "x"}); !errors.As(err, &failed) || failed.Step != "copy" {
		t.Fatalf("a second write: %v", err)
	}
	if err := rewriteStagedWPConfig(public, "shop_wordpress", "shop_wpuser"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "wp-config.php"))
	info, _ := os.Stat(filepath.Join(dir, "wp-config.php"))
	if !strings.Contains(string(got), "define('DB_NAME', 'shop_wordpress');") || !strings.Contains(string(got), "define('DB_USER', 'shop_wpuser');") || !strings.Contains(string(got), "'DB_PASSWORD', 'x'") || info.Mode().Perm() != 0o640 {
		t.Fatalf("wp-config.php = %s %v", got, info.Mode())
	}
	// A link is never followed.
	if err := os.Remove(filepath.Join(dir, "wp-config.php")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "wp-config.php")); err != nil {
		t.Fatal(err)
	}
	if err := rewriteStagedWPConfig(public, "a", "b"); !errors.As(err, &failed) || failed.Step != "copy" {
		t.Fatalf("a link: %v", err)
	}
	if err := os.Symlink("/tmp", filepath.Join(dir, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := writeConverted(public, map[string]string{"linked": "x"}); !errors.As(err, &failed) {
		t.Fatalf("a linked folder: %v", err)
	}
}
