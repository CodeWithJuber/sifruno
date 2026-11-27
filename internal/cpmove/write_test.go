package cpmove

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sifruno/internal/cpsource"
)

// exportHome makes a Sifruno home on disk: public_html with a link, an
// .ssh folder that stays, and a file the export's Owned check refuses.
func exportHome(t *testing.T) *os.Root {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"public_html/index.php":     "<?php echo 'shop';\n",
		"public_html/.htaccess":     "RewriteEngine On\n",
		"public_html/wp-config.php": "<?php define('DB_NAME', 'shop_wp');\n",
		".ssh/authorized_keys":      "this server's keys\n",
		"public_html/not-mine.txt":  "someone else's\n",
	} {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("index.php", filepath.Join(dir, "public_html", "home.php")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

func shopExport(t *testing.T) Export {
	cert, key := testCertificate(t)
	dump := "CREATE TABLE `wp_options` (id int);\n"
	return Export{User: "shop", Domain: "example.com", Aliases: []string{"example.net"}, PHP: "8.2", Home: exportHome(t).FS(),
		Owned:          func(name string, _ fs.FileInfo) bool { return !strings.HasSuffix(name, "not-mine.txt") },
		Databases:      []ExportDatabase{{Name: "shop_wp", Size: int64(len(dump)), Dump: strings.NewReader(dump)}},
		Users:          []cpsource.DatabaseUser{{Name: "shop_wp", Hash: testHash2, Grants: []cpsource.Grant{{Database: "shop_wp", Privileges: []string{"ALL PRIVILEGES"}}}}},
		Cron:           []cpsource.CronLine{{Schedule: "*/5 * * * *", Command: "php ~/public_html/wp-cron.php"}},
		CertificatePEM: []byte(cert), KeyPEM: []byte(key), Now: time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)}
}

// The way back: what Write makes, Read reads as the same website.
func TestExportReadsBackAsTheSameWebsite(t *testing.T) {
	var out bytes.Buffer
	if err := Write(context.Background(), &out, shopExport(t)); err != nil {
		t.Fatal(err)
	}
	a, sink, err := readShop(t, out.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	s := a.Site
	if s.Account != "shop" || s.Domain != "example.com" || strings.Join(s.Aliases, ",") != "example.net" || !s.WWW || s.PHP.Version != "8.2" || !s.PHP.Exact || s.DocRoot != "public_html" || s.Home != "/home/shop" {
		t.Fatalf("site = %+v", s)
	}
	if len(a.Users) != 1 || a.Users[0].Hash != testHash2 || a.Users[0].Grants[0].Database != "shop_wp" || len(s.Cron) != 1 || s.Certificate == nil || !s.Certificate.HasKey {
		t.Fatalf("users %+v cron %+v cert %+v", a.Users, s.Cron, s.Certificate)
	}
	if sink.files["mysql/shop_wp.sql"] != "CREATE TABLE `wp_options` (id int);\n" || sink.files["home/public_html/index.php"] != "<?php echo 'shop';\n" || sink.links["home/public_html/home.php"] != "index.php" {
		t.Fatalf("files %v links %v", sink.files, sink.links)
	}
	for name := range sink.files {
		if strings.Contains(name, ".ssh") || strings.Contains(name, "not-mine") {
			t.Fatalf("%s was exported", name)
		}
	}
	if len(s.NotCarried) != 0 {
		t.Fatalf("an export reads back with things that do not move: %+v", s.NotCarried)
	}
}

func TestExportRefusesWhatItCannotWrite(t *testing.T) {
	for name, change := range map[string]func(*Export){
		"account":    func(e *Export) { e.User = "Shop" },
		"php":        func(e *Export) { e.PHP = "7.4" },
		"other db":   func(e *Export) { e.Databases[0].Name = "other_wp" },
		"key alone":  func(e *Export) { e.CertificatePEM = nil },
		"short dump": func(e *Export) { e.Databases[0].Size += 10 },
		"no home":    func(e *Export) { e.Home = nil },
	} {
		e := shopExport(t)
		change(&e)
		if err := Write(context.Background(), &bytes.Buffer{}, e); !errors.Is(err, ErrExport) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Without a key the certificate stays out too.
	e := shopExport(t)
	e.CertificatePEM, e.KeyPEM = nil, nil
	var out bytes.Buffer
	if err := Write(context.Background(), &out, e); err != nil {
		t.Fatal(err)
	}
	if a, _, err := readShop(t, out.Bytes()); err != nil || a.Site.Certificate != nil {
		t.Fatalf("without a key: %+v %v", a, err)
	}
	if ExportName("shop") != "cpmove-shop.tar.gz" {
		t.Fatal(ExportName("shop"))
	}
}
