package cpmove

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"sifruno/internal/sitemodel"
)

// memSink keeps what Read extracts, and refuses a name that is not a clean
// relative path, so a test fails if Read ever hands one over.
type memSink struct {
	t     testing.TB
	dirs  map[string]fs.FileMode
	files map[string]string
	modes map[string]fs.FileMode
	links map[string]string
}

func newMemSink(t testing.TB) *memSink {
	return &memSink{t: t, dirs: map[string]fs.FileMode{}, files: map[string]string{}, modes: map[string]fs.FileMode{}, links: map[string]string{}}
}

func (m *memSink) check(name string) {
	if name == "" || strings.HasPrefix(name, "/") || filepath.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") || strings.Contains(name, "/../") {
		m.t.Fatalf("Read handed the sink an unsafe name %q", name)
	}
}
func (m *memSink) Dir(name string, mode fs.FileMode) error {
	m.check(name)
	m.dirs[name] = mode
	return nil
}
func (m *memSink) File(name string, mode fs.FileMode, r io.Reader) error {
	m.check(name)
	b, err := io.ReadAll(r)
	m.files[name], m.modes[name] = string(b), mode
	return err
}
func (m *memSink) Symlink(name, target string) error {
	m.check(name)
	m.links[name] = target
	return nil
}

const (
	testHash  = "*ABABABABABABABABABABABABABABABABABABABAB"
	testHash2 = "*CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD"
)

// tarOf and gzipOf are syntheticTar and syntheticGzip for fuzz targets too.
func tarOf(t testing.TB, entries ...syntheticEntry) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range entries {
		h := e.h
		if h.Typeflag == 0 {
			h.Typeflag = tar.TypeReg
		}
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(e.payload))
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.payload)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func gzipOf(t testing.TB, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	z := gzip.NewWriter(&out)
	if _, err := z.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func dir(name string) syntheticEntry {
	return syntheticEntry{h: tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0755}}
}
func file(name, payload string) syntheticEntry {
	return syntheticEntry{h: tar.Header{Name: name, Mode: 0644}, payload: payload}
}
func link(name, target string) syntheticEntry {
	return syntheticEntry{h: tar.Header{Name: name, Typeflag: tar.TypeSymlink, Linkname: target, Mode: 0777}}
}

// testCertificate makes a certificate and key for example.com at test
// time, so no key lives in the repository.
func testCertificate(t testing.TB) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "example.com"}, Issuer: pkix.Name{CommonName: "Test CA"},
		DNSNames: []string{"example.com", "www.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	k, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k}))
}

// shopArchive is a synthetic cpmove-shop.tar.gz in the layout cPanel's
// "Backup Tarball Contents" page describes; extra entries go at the end.
func shopArchive(t testing.TB, extra ...syntheticEntry) []byte {
	t.Helper()
	cert, key := testCertificate(t)
	p := "cpmove-shop/"
	entries := []syntheticEntry{
		dir(p),
		file(p+"version", "pkgacct version: 10\narchive version: 4\n"),
		dir(p + "cp/"),
		file(p+"cp/shop", "DNS=example.com\nDNS1=example.net\nPLAN=default\nUSER=shop\nSTARTDATE=1700000000\n"),
		dir(p + "userdata/"),
		file(p+"userdata/main", "---\naddon_domains: {}\nmain_domain: example.com\nparked_domains:\n  - example.net\nsub_domains:\n  - blog.example.com\n"),
		file(p+"userdata/example.com", "---\ndocumentroot: /home/shop/public_html\ngroup: shop\nhomedir: /home/shop\nip: 192.0.2.10\nphpversion: ea-php82\nserveralias: mail.example.com www.example.com\nservername: example.com\nuser: shop\n"),
		file(p+"userdata/blog.example.com", "---\ndocumentroot: /home/shop/blog\nservername: blog.example.com\nuser: shop\n"),
		dir(p + "cron/"),
		file(p+"cron/shop", "MAILTO=\"\"\n*/5 * * * * /usr/local/bin/php -q /home/shop/public_html/wp-cron.php\n"),
		file(p+"mysql.sql", "GRANT USAGE ON *.* TO 'shop'@'localhost' IDENTIFIED BY PASSWORD '"+testHash+"';\n"+
			"GRANT ALL PRIVILEGES ON `shop\\_%`.* TO 'shop'@'localhost';\n"+
			"GRANT USAGE ON *.* TO 'shop_wp'@'localhost' IDENTIFIED BY PASSWORD '"+testHash2+"';\n"+
			"GRANT ALL PRIVILEGES ON `shop\\_wp`.* TO 'shop_wp'@'localhost';\n"+
			"GRANT SELECT, INSERT ON `shop\\_wp`.* TO 'shop_wp'@'%';\n"),
		dir(p + "mysql/"),
		file(p+"mysql/shop_wp.create", "CREATE DATABASE `shop_wp`;\n"),
		file(p+"mysql/shop_wp.sql", "CREATE TABLE `wp_options` (id int);\nINSERT INTO `wp_options` VALUES (1);\n"),
		dir(p + "apache_tls/"),
		file(p+"apache_tls/example.com", key+cert),
		dir(p + "dnszones/"),
		file(p+"dnszones/example.com.db", "$ORIGIN example.com.\n"),
		file(p+"shadow", "not read\n"),
		dir(p + "homedir/"),
		dir(p + "homedir/public_html/"),
		file(p+"homedir/public_html/index.php", "<?php echo 'shop';\n"),
		file(p+"homedir/public_html/.htaccess", "php_value memory_limit 256M\nRewriteEngine On\n"),
		{h: tar.Header{Name: p + "homedir/public_html/run.sh", Mode: 0o4755}, payload: "#!/bin/sh\n"},
		link(p+"homedir/www", "public_html"),
		link(p+"homedir/public_html/home.php", "index.php"),
		dir(p + "homedir/mail/"),
		file(p+"homedir/mail/inbox", "mail stays\n"),
		dir(p + "homedir/.ssh/"),
		file(p+"homedir/.ssh/authorized_keys", "old keys stay\n"),
	}
	return gzipOf(t, tarOf(t, append(entries, extra...)...))
}

func readShop(t testing.TB, b []byte) (*Archive, *memSink, error) {
	t.Helper()
	sink := newMemSink(t)
	a, err := Read(context.Background(), bytes.NewReader(b), DefaultLimits(), sink)
	return a, sink, err
}

func TestReadCPanelBackup(t *testing.T) {
	a, sink, err := readShop(t, shopArchive(t))
	if err != nil {
		t.Fatal(err)
	}
	s := a.Site
	if err := s.Check(); err != nil {
		t.Fatal(err)
	}
	if s.Source != sitemodel.SourceArchive || s.Account != "shop" || s.Domain != "example.com" || !s.WWW || s.DocRoot != "public_html" {
		t.Fatalf("site = %+v", s)
	}
	if strings.Join(s.Aliases, ",") != "example.net" || s.PHP.Source != "ea-php82" || s.PHP.Version != "8.2" || !s.PHP.Exact {
		t.Fatalf("aliases %v php %+v", s.Aliases, s.PHP)
	}
	if len(s.Databases) != 1 || s.Databases[0].Name != "shop_wp" || s.Databases[0].Dump != "mysql/shop_wp.sql" {
		t.Fatalf("databases = %+v", s.Databases)
	}
	if len(a.Users) != 1 || a.Users[0].Name != "shop_wp" || a.Users[0].Hash != testHash2 || len(a.Users[0].Grants) != 1 || a.Users[0].Grants[0].Privileges[0] != "ALL PRIVILEGES" {
		t.Fatalf("users = %+v", a.Users)
	}
	if len(s.Users) != 1 || !s.Users[0].HasHash {
		t.Fatalf("model users = %+v", s.Users)
	}
	if len(s.Cron) != 1 || s.Cron[0].Schedule != "*/5 * * * *" {
		t.Fatalf("cron = %+v", s.Cron)
	}
	if len(s.PHP.Settings) != 1 || s.PHP.Settings[0].Name != "memory_limit" {
		t.Fatalf("php settings = %+v", s.PHP.Settings)
	}
	if s.Certificate == nil || !s.Certificate.HasKey || strings.Join(s.Certificate.Domains, ",") != "example.com,www.example.com" || len(a.CertificatePEM) == 0 || len(a.KeyPEM) == 0 {
		t.Fatalf("certificate = %+v", s.Certificate)
	}
	// What the sink got: the home's site files and the dump; mail and
	// .ssh stay; www is a link inside the home; setuid is dropped.
	var names []string
	for n := range sink.files {
		names = append(names, n)
	}
	sort.Strings(names)
	if got := strings.Join(names, " "); got != "home/public_html/.htaccess home/public_html/index.php home/public_html/run.sh mysql/shop_wp.sql" {
		t.Fatalf("files = %s", got)
	}
	if sink.modes["home/public_html/run.sh"] != 0o755 {
		t.Fatalf("run.sh mode = %o", sink.modes["home/public_html/run.sh"])
	}
	if sink.links["home/public_html/home.php"] != "index.php" || len(sink.links) != 1 {
		t.Fatalf("links = %v", sink.links)
	}
	// The model says what does not move.
	var texts []string
	for _, item := range s.NotCarried {
		texts = append(texts, item.Part+": "+item.Text)
	}
	joined := strings.Join(texts, "\n")
	for _, want := range []string{"mail: ", "dns: ", "domain: The sub-domain or addon domain blog.example.com", "database: The database user shop is the cPanel account's own", "database: A grant of shop_wp from hosts other than localhost", "cron: A scheduled-job line was not copied: a variable line"} {
		if !strings.Contains(joined, want) {
			t.Errorf("not carried lacks %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, testHash) || strings.Contains(joined, "not read") {
		t.Fatal("the model quotes a hash or the shadow file")
	}
}

func TestReadRefusesUnsafeArchives(t *testing.T) {
	p := "cpmove-shop/"
	cases := map[string]struct {
		archive []byte
		want    error
	}{
		"traversal":         {shopArchive(t, file(p+"homedir/../../../etc/cron.d/x", "x")), ErrArchive},
		"absolute":          {shopArchive(t, file("/etc/passwd", "x")), ErrArchive},
		"other top folder":  {shopArchive(t, file("cpmove-other/homedir/x", "x")), ErrArchive},
		"duplicate":         {shopArchive(t, file(p+"homedir/public_html/index.php", "again")), ErrArchive},
		"metadata too big":  {shopArchive(t, file(p+"userdata/huge.example.com", strings.Repeat("a", maxMetadataFile+1))), ErrLimit},
		"not a cpmove file": {gzipOf(t, tarOf(t, dir("site/"), file("site/index.php", "x"))), ErrNotCPMove},
		"no cp file":        {gzipOf(t, tarOf(t, dir("cpmove-shop/"), file("cpmove-shop/version", "pkgacct version: 10\n"))), ErrNotCPMove},
		"cp user differs":   {gzipOf(t, tarOf(t, file("cpmove-shop/cp/other", "DNS=example.com\n"))), ErrNotCPMove},
		"bad account name":  {gzipOf(t, tarOf(t, file("cpmove-Shop/cp/Shop", "DNS=example.com\n"))), ErrNotCPMove},
	}
	for name, c := range cases {
		if _, _, err := readShop(t, c.archive); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
	}
}

func TestReadLeavesOutLinksAndSpecialFiles(t *testing.T) {
	p := "cpmove-shop/homedir/"
	a, sink, err := readShop(t, shopArchive(t,
		link(p+"public_html/passwd", "../../../../etc/passwd"),
		link(p+"public_html/abs", "/etc/shadow"),
		link(p+"up", ".."),
		syntheticEntry{h: tar.Header{Name: p + "public_html/hard", Typeflag: tar.TypeLink, Linkname: "cpmove-shop/homedir/public_html/index.php"}},
		syntheticEntry{h: tar.Header{Name: p + "fifo", Typeflag: tar.TypeFifo, Mode: 0644}},
		syntheticEntry{h: tar.Header{Name: p + "dev", Typeflag: tar.TypeChar, Mode: 0644, Devmajor: 1, Devminor: 3}},
		link(p+"public_html/up", "../public_html"),
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(sink.links) != 2 || sink.links["home/public_html/up"] != "../public_html" {
		t.Fatalf("links = %v", sink.links)
	}
	var texts []string
	for _, item := range a.Site.NotCarried {
		if item.Part == "file" {
			texts = append(texts, item.Where+": "+item.Text)
		}
	}
	joined := strings.Join(texts, "\n")
	for _, want := range []string{"public_html/passwd: ", "public_html/abs: ", "up: ", "public_html/hard: ", "fifo: ", "dev: "} {
		if !strings.Contains(joined, want) {
			t.Errorf("not carried lacks %q:\n%s", want, joined)
		}
	}
}

func TestReadBounds(t *testing.T) {
	small := DefaultLimits()
	small.MaxFileBytes = 1 << 10
	big := shopArchive(t, file("cpmove-shop/homedir/public_html/big.bin", strings.Repeat("z", 2<<10)))
	if _, err := Read(context.Background(), bytes.NewReader(big), small, newMemSink(t)); !errors.Is(err, ErrLimit) {
		t.Fatalf("member over the limit: %v", err)
	}
	// A bomb: a small gzip that expands past the limit.
	bomb := DefaultLimits()
	bomb.MaxExpandedBytes = 64 << 10
	zeros := shopArchive(t, file("cpmove-shop/homedir/public_html/zeros", strings.Repeat("\x00", 256<<10)))
	if len(zeros) > 64<<10 {
		t.Fatalf("the bomb is not small: %d", len(zeros))
	}
	if _, err := Read(context.Background(), bytes.NewReader(zeros), bomb, newMemSink(t)); !errors.Is(err, ErrLimit) {
		t.Fatalf("expanded past the limit: %v", err)
	}
	entries := DefaultLimits()
	entries.MaxEntries = 10
	if _, err := Read(context.Background(), bytes.NewReader(shopArchive(t)), entries, newMemSink(t)); !errors.Is(err, ErrLimit) {
		t.Fatalf("entries past the limit: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Read(ctx, bytes.NewReader(shopArchive(t)), DefaultLimits(), newMemSink(t)); !errors.Is(err, ErrCanceled) {
		t.Fatalf("canceled: %v", err)
	}
}

func TestRootSinkStaysInside(t *testing.T) {
	top := t.TempDir()
	if err := os.Mkdir(filepath.Join(top, "stage"), 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(filepath.Join(top, "stage"))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	sink := RootSink{Root: root}
	_, err = Read(context.Background(), bytes.NewReader(shopArchive(t,
		link("cpmove-shop/homedir/public_html/inner", "../public_html"),
		file("cpmove-shop/homedir/public_html/inner/through.txt", "x"),
	)), DefaultLimits(), sink)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(top, "stage", "home", "public_html", "index.php"))
	if err != nil || string(b) != "<?php echo 'shop';\n" {
		t.Fatalf("index.php = %q, %v", b, err)
	}
	info, err := os.Lstat(filepath.Join(top, "stage", "home", "public_html", "run.sh"))
	if err != nil || info.Mode().Perm() != 0o755 || info.Mode()&fs.ModeSetuid != 0 {
		t.Fatalf("run.sh = %v, %v", info.Mode(), err)
	}
	if target, err := os.Readlink(filepath.Join(top, "stage", "home", "public_html", "home.php")); err != nil || target != "index.php" {
		t.Fatalf("home.php = %q, %v", target, err)
	}
	// Nothing was written beside the stage.
	entries, err := os.ReadDir(top)
	if err != nil || len(entries) != 1 {
		t.Fatalf("top holds %v", entries)
	}
}
