package cpmove

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"
	"time"

	"sifruno/internal/cpsource"
)

// Write is the way back (docs/migration-design.md, Export): a Sifruno
// website as a cPanel account backup, cpmove-USER.tar.gz, in the layout
// cPanel's public "Backup Tarball Contents" page describes and with a name
// its restorepkg page lists. It holds the home (homedir/), each database's
// dump (mysql/DB.sql, mysql/DB.create) and its users' grants with their
// mysql_native_password hashes (mysql.sql), the domain and PHP version
// (cp/USER, userdata/main, userdata/DOMAIN), cron (cron/USER) and, only
// when the caller passes the key, the certificate with its key
// (apache_tls/DOMAIN). cPanel says the layout can change; a restore into a
// real cPanel server is not certified here. Read reads everything Write
// makes.

// Export is one website to write.
type Export struct {
	User    string
	Domain  string
	Aliases []string
	// PHP is this server's version, "8.3"; it becomes ea-php83.
	PHP string
	// Home is the account's home. Links are written as links, never
	// followed; Owned says whether an entry may be written (the caller
	// checks it belongs to the account). Nil Owned writes everything.
	Home  fs.FS
	Owned func(name string, info fs.FileInfo) bool
	// Databases are the dumps, each with its exact size.
	Databases []ExportDatabase
	Users     []cpsource.DatabaseUser
	Cron      []cpsource.CronLine
	// CertificatePEM and KeyPEM go out together, or not at all.
	CertificatePEM, KeyPEM []byte
	Now                    time.Time
}

// ExportDatabase is one database's dump.
type ExportDatabase struct {
	Name string
	Size int64
	Dump io.Reader
}

// ErrExport means the website cannot be written as asked.
var ErrExport = errors.New("the website cannot be exported as asked")

// homeSkips are the parts of a Sifruno home a cPanel account does not
// take: the account's SFTP keys are this server's.
var homeSkips = map[string]bool{".ssh": true}

// Write writes e as a gzip-compressed TAR to w.
func Write(ctx context.Context, w io.Writer, e Export) error {
	if ctx == nil || w == nil || !cpsource.UserPattern.MatchString(e.User) || !cpsource.ValidDomain(e.Domain) || e.Home == nil || (len(e.KeyPEM) > 0) != (len(e.CertificatePEM) > 0) {
		return ErrExport
	}
	php, ok := eaPHP(e.PHP)
	if !ok {
		return ErrExport
	}
	for _, d := range e.Databases {
		if !owned(e.User, d.Name) || d.Size < 0 || d.Dump == nil {
			return ErrExport
		}
	}
	now := e.Now
	if now.IsZero() {
		now = time.Now()
	}
	z := gzip.NewWriter(w)
	t := &tarWriter{tw: tar.NewWriter(z), top: "cpmove-" + e.User + "/", now: now.UTC().Truncate(time.Second)}
	err := t.write(ctx, e, php)
	if err == nil {
		err = t.tw.Close()
	}
	if cerr := z.Close(); err == nil {
		err = cerr
	}
	return err
}

type tarWriter struct {
	tw  *tar.Writer
	top string
	now time.Time
}

func (t *tarWriter) dir(name string, mode int64) error {
	return t.tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: t.top + name + "/", Mode: mode, ModTime: t.now, Format: tar.FormatPAX})
}

func (t *tarWriter) text(name, body string) error {
	if err := t.tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: t.top + name, Mode: 0600, Size: int64(len(body)), ModTime: t.now, Format: tar.FormatPAX}); err != nil {
		return err
	}
	_, err := io.WriteString(t.tw, body)
	return err
}

func (t *tarWriter) write(ctx context.Context, e Export, php string) error {
	home := "/home/" + e.User
	if err := t.tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: t.top, Mode: 0700, ModTime: t.now, Format: tar.FormatPAX}); err != nil {
		return err
	}
	parts := []struct{ name, body string }{
		{"version", "pkgacct version: 10\narchive version: 4\n"},
		{"homedir_paths", home + "\n"},
		{"cp/" + e.User, fmt.Sprintf("DNS=%s\nUSER=%s\nPLAN=default\nSTARTDATE=%d\n", e.Domain, e.User, t.now.Unix())},
		{"userdata/main", mainUserdata(e)},
		{"userdata/" + e.Domain, fmt.Sprintf("---\ndocumentroot: %s/public_html\ngroup: %s\nhomedir: %s\nphpversion: %s\nserveralias: %s\nservername: %s\nuser: %s\n",
			home, e.User, home, php, "www."+e.Domain, e.Domain, e.User)},
		{"cron/" + e.User, cronFile(e.Cron)},
		{"mysql.sql", grantsFile(e.User, e.Users)},
	}
	for _, d := range []string{"cp", "userdata", "cron", "mysql", "homedir"} {
		if err := t.dir(d, 0700); err != nil {
			return err
		}
	}
	for _, p := range parts {
		if err := t.text(p.name, p.body); err != nil {
			return err
		}
	}
	if len(e.KeyPEM) > 0 {
		if err := t.dir("apache_tls", 0700); err != nil {
			return err
		}
		if err := t.text("apache_tls/"+e.Domain, string(e.KeyPEM)+string(e.CertificatePEM)); err != nil {
			return err
		}
	}
	for _, d := range e.Databases {
		if err := t.text("mysql/"+d.Name+".create", "CREATE DATABASE `"+d.Name+"`;\n"); err != nil {
			return err
		}
		if err := t.tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: t.top + "mysql/" + d.Name + ".sql", Mode: 0600, Size: d.Size, ModTime: t.now, Format: tar.FormatPAX}); err != nil {
			return err
		}
		if n, err := io.Copy(t.tw, &contextReader{ctx: ctx, r: io.LimitReader(d.Dump, d.Size)}); err != nil || n != d.Size {
			return ErrExport
		}
	}
	return t.home(ctx, e)
}

// home writes the account's home under homedir/, in name order.
func (t *tarWriter) home(ctx context.Context, e Export) error {
	return fs.WalkDir(e.Home, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ErrCanceled
		}
		if name == "." {
			return nil
		}
		if first, _, _ := strings.Cut(name, "/"); homeSkips[first] {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		info, err := fs.Lstat(e.Home, name)
		if err != nil {
			return err
		}
		if e.Owned != nil && !e.Owned(name, info) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		h := &tar.Header{Name: t.top + "homedir/" + name, Mode: int64(info.Mode().Perm()), ModTime: info.ModTime().UTC().Truncate(time.Second), Format: tar.FormatPAX}
		switch {
		case info.IsDir():
			h.Typeflag, h.Name = tar.TypeDir, h.Name+"/"
			return t.tw.WriteHeader(h)
		case info.Mode()&fs.ModeSymlink != 0:
			target, err := fs.ReadLink(e.Home, name)
			if err != nil {
				return err
			}
			h.Typeflag, h.Linkname = tar.TypeSymlink, target
			return t.tw.WriteHeader(h)
		case info.Mode().IsRegular():
			f, err := e.Home.Open(name)
			if err != nil {
				return err
			}
			defer f.Close()
			opened, err := f.Stat()
			// The entry must still be the regular file walked to, of the
			// same size: a home that changes under the export stops it.
			if err != nil || !opened.Mode().IsRegular() || opened.Size() != info.Size() || (e.Owned != nil && !e.Owned(name, opened)) {
				return ErrExport
			}
			h.Typeflag, h.Size = tar.TypeReg, info.Size()
			if err := t.tw.WriteHeader(h); err != nil {
				return err
			}
			if n, err := io.Copy(t.tw, &contextReader{ctx: ctx, r: io.LimitReader(f, h.Size)}); err != nil || n != h.Size {
				return ErrExport
			}
			return nil
		}
		return nil // devices, sockets and pipes are not a website's
	})
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *contextReader) Read(p []byte) (int, error) {
	if c.ctx.Err() != nil {
		return 0, ErrCanceled
	}
	return c.r.Read(p)
}

// eaPHP is cPanel's EasyApache name for a PHP version.
func eaPHP(v string) (string, bool) {
	switch v {
	case "8.1", "8.2", "8.3", "8.4":
		return "ea-php" + strings.ReplaceAll(v, ".", ""), true
	}
	return "", false
}

func mainUserdata(e Export) string {
	var b strings.Builder
	b.WriteString("---\naddon_domains: {}\nmain_domain: " + e.Domain + "\n")
	aliases := append([]string{}, e.Aliases...)
	sort.Strings(aliases)
	if len(aliases) == 0 {
		b.WriteString("parked_domains: []\n")
	} else {
		b.WriteString("parked_domains:\n")
		for _, a := range aliases {
			if cpsource.ValidDomain(a) {
				b.WriteString("  - " + a + "\n")
			}
		}
	}
	b.WriteString("sub_domains: []\n")
	return b.String()
}

func cronFile(jobs []cpsource.CronLine) string {
	var b strings.Builder
	for _, j := range jobs {
		if !strings.ContainsAny(j.Schedule+j.Command, "\r\n\x00") {
			b.WriteString(j.Schedule + " " + j.Command + "\n")
		}
	}
	return b.String()
}

// grantsFile writes each user's grants as MariaDB's SHOW GRANTS prints them,
// at localhost, with _ and % in database names escaped.
func grantsFile(account string, users []cpsource.DatabaseUser) string {
	var b strings.Builder
	for _, u := range users {
		if !owned(account, u.Name) {
			continue
		}
		b.WriteString("GRANT USAGE ON *.* TO '" + u.Name + "'@'localhost'")
		if nativeHash.MatchString(u.Hash) {
			b.WriteString(" IDENTIFIED BY PASSWORD '" + u.Hash + "'")
		}
		b.WriteString(";\n")
		for _, g := range u.Grants {
			if !owned(account, g.Database) {
				continue
			}
			privs := make([]string, 0, len(g.Privileges))
			for _, p := range g.Privileges {
				if p == "ALL PRIVILEGES" || knownPrivileges[p] {
					privs = append(privs, p)
				}
			}
			if len(privs) == 0 {
				continue
			}
			db := strings.NewReplacer("_", `\_`, "%", `\%`).Replace(g.Database)
			b.WriteString("GRANT " + strings.Join(privs, ", ") + " ON `" + db + "`.* TO '" + u.Name + "'@'localhost';\n")
		}
	}
	return b.String()
}

// ExportName is the file name restorepkg finds an account's backup by.
func ExportName(user string) string { return "cpmove-" + user + ".tar.gz" }
