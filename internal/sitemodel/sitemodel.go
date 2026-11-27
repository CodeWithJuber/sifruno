// Package sitemodel is one website as Sifruno will host it, read from any
// source: a cPanel server, a cPanel backup file, another Linux server over
// SSH (docs/migration-design.md). Source adapters fill a Site; the panel
// shows what it holds and what cannot move before anything is created, and
// the broker's typed copy steps move what it names.
//
// A Site holds no password, password hash, private key or file contents.
// Those stay where the adapter found them until a broker step copies them.
package sitemodel

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"sifruno/internal/cpsource"
)

// The sources a Site can come from.
const (
	SourceCPanel  = "cpanel"
	SourceArchive = "cpanel-archive"
	SourceSSH     = "ssh"
)

// Bounds on what one Site may hold, so a hostile source cannot make the
// panel or the broker keep unbounded data.
const (
	MaxAliases    = 64
	MaxDatabases  = cpsource.MaxDatabases
	MaxUsers      = cpsource.MaxUsers
	MaxCron       = cpsource.MaxCronLines
	MaxSettings   = 64
	MaxNotCarried = 200
	MaxRewrites   = 400
	maxText       = 1024
)

// Site is one website read from a source.
type Site struct {
	Source string `json:"source"`
	// Account is the account name the site keeps here.
	Account string   `json:"account"`
	Domain  string   `json:"domain"`
	Aliases []string `json:"aliases"`
	// WWW says the source answered for www.<Domain> too.
	WWW          bool  `json:"www"`
	DiskUsedMiB  int64 `json:"disk_used_mib"`
	DiskLimitMiB int64 `json:"disk_limit_mib"`
	// Home is the site's home on the source (an absolute path there), and
	// DocRoot the document root relative to it ("public_html"). For a
	// backup file Home is empty: the archive's homedir/ is the home.
	Home      string              `json:"home"`
	DocRoot   string              `json:"doc_root"`
	Databases []Database          `json:"databases"`
	Users     []User              `json:"users"`
	Cron      []cpsource.CronLine `json:"cron"`
	PHP       PHP                 `json:"php"`
	// Certificate is the source's certificate for the domain, nil when it
	// has none. It never holds the key.
	Certificate *Certificate `json:"certificate,omitempty"`
	Rules       Rules        `json:"rules"`
	// NotCarried is everything the adapter saw and cannot carry, each in
	// plain words, so nothing is dropped without the person knowing.
	NotCarried []Item `json:"not_carried"`
}

// Database is one database as it is named here. SourceName is its name on
// the source when that differs (a plain server's "wordpress" becomes
// "account_wordpress"); Dump says where its dump comes from: "ssh" for a
// dump made on the source, or the archive member ("mysql/NAME.sql").
type Database struct {
	Name       string `json:"name"`
	SourceName string `json:"source_name,omitempty"`
	Dump       string `json:"dump"`
}

// User is one database user and its grants. HasHash says the source keeps
// a mysql_native_password hash for it, which the copy can reuse; the hash
// itself is never in the model.
type User struct {
	Name    string           `json:"name"`
	HasHash bool             `json:"has_hash"`
	Grants  []cpsource.Grant `json:"grants"`
}

// PHP is the source's PHP: its own version string, the version this server
// runs the copy with, and whether they are the same.
type PHP struct {
	Source   string    `json:"source"`
	Version  string    `json:"version"`
	Exact    bool      `json:"exact"`
	Settings []Setting `json:"settings"`
}

// Setting is one PHP setting the source gave the site, and where it came
// from ("public_html/.htaccess line 4").
type Setting struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	From  string `json:"from"`
}

// Certificate is what the source's certificate says about itself.
type Certificate struct {
	Domains  []string  `json:"domains"`
	Issuer   string    `json:"issuer"`
	NotAfter time.Time `json:"not_after"`
	// HasKey says the source holds the matching private key, so the
	// certificate can move.
	HasKey bool `json:"has_key"`
}

// Rules are the site's web server rules as they move: Native says
// OpenLiteSpeed acts on all of them as converted; Redirects and Folders
// go into the site's olsweb config; Rewrites are Apache rewrite lines for
// the document root's .htaccess, which OpenLiteSpeed reads.
type Rules struct {
	Native    bool       `json:"native"`
	Htaccess  int        `json:"htaccess_files"`
	Redirects []Redirect `json:"redirects"`
	Folders   []string   `json:"closed_folders"`
	Rewrites  []string   `json:"rewrites"`
}

// Redirect is a whole-path redirect: Path on every domain to Target.
type Redirect struct {
	Path   string `json:"path"`
	Target string `json:"target"`
	Status int    `json:"status"`
}

// Item is one thing that does not move: Part names which part of the site
// ("database", "cron", "domain", "rule", "php", "mail"), Text says in plain
// words what and why, and Where points at the file and line when there is
// one. Part "info" is what moves differently without anything lost (a
// database that takes the account's prefix, .htaccess files nginx never
// read): the summary shows it, and a move's job says it in its steps.
type Item struct {
	Part  string `json:"part"`
	Text  string `json:"text"`
	Where string `json:"where,omitempty"`
}

// Skip records something that does not move. Past MaxNotCarried items the
// last one says that more were left out, so the list stays bounded.
func (s *Site) Skip(part, text, where string) {
	switch {
	case len(s.NotCarried) < MaxNotCarried-1:
		s.NotCarried = append(s.NotCarried, Item{Part: part, Text: clip(text), Where: clip(where)})
	case len(s.NotCarried) == MaxNotCarried-1:
		s.NotCarried = append(s.NotCarried, Item{Part: "more", Text: "More things do not move than this list shows."})
	}
}

// ErrInvalid wraps every reason Check refuses a Site.
var ErrInvalid = errors.New("the website cannot be hosted here as read")

var (
	settingName = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)
	phpVersions = map[string]bool{"8.1": true, "8.2": true, "8.3": true, "8.4": true}
)

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, a...)...)
}

// Check refuses a Site that names something Sifruno cannot host: an
// account or domain outside the wizard's rules, a database or user that is
// not the account's own, a PHP version this server does not run, or more
// than the bounds allow.
func (s *Site) Check() error {
	switch {
	case s.Source != SourceCPanel && s.Source != SourceArchive && s.Source != SourceSSH:
		return invalid("unknown source")
	case !cpsource.UserPattern.MatchString(s.Account):
		return invalid("the account name must be 3 to 32 lowercase letters, digits or _, starting with a letter")
	case !cpsource.ValidDomain(s.Domain):
		return invalid("the domain is not a lowercase DNS name")
	case len(s.Aliases) > MaxAliases, len(s.Databases) > MaxDatabases, len(s.Users) > MaxUsers, len(s.Cron) > MaxCron,
		len(s.PHP.Settings) > MaxSettings, len(s.NotCarried) > MaxNotCarried, len(s.Rules.Rewrites) > MaxRewrites:
		return invalid("the website holds more than this server takes in one move")
	case !phpVersions[s.PHP.Version]:
		return invalid("PHP %q is not one this server runs", s.PHP.Version)
	case s.DiskUsedMiB < 0 || s.DiskLimitMiB < 0:
		return invalid("the disk figures are negative")
	}
	if s.DocRoot != "" && (path.IsAbs(s.DocRoot) || path.Clean(s.DocRoot) != s.DocRoot || s.DocRoot == ".." || strings.HasPrefix(s.DocRoot, "../")) {
		return invalid("the document root must lie inside the home")
	}
	for _, a := range s.Aliases {
		if !cpsource.ValidDomain(a) || a == s.Domain {
			return invalid("the alias %q is not a lowercase DNS name of its own", clip(a))
		}
	}
	names := map[string]bool{}
	for _, d := range s.Databases {
		if !owned(s.Account, d.Name) || names[d.Name] {
			return invalid("the database %q must be the account's own, named %s_ and a suffix, once", clip(d.Name), s.Account)
		}
		names[d.Name] = true
	}
	users := map[string]bool{}
	for _, u := range s.Users {
		if !owned(s.Account, u.Name) || users[u.Name] {
			return invalid("the database user %q must be the account's own, named %s_ and a suffix, once", clip(u.Name), s.Account)
		}
		users[u.Name] = true
		for _, g := range u.Grants {
			if !names[g.Database] {
				return invalid("the database user %q has a grant on a database the website does not have", u.Name)
			}
		}
	}
	for _, p := range s.PHP.Settings {
		if !settingName.MatchString(p.Name) || strings.ContainsAny(p.Value, "\x00\r\n") || len(p.Value) > maxText {
			return invalid("the PHP setting %q cannot be written as it is", clip(p.Name))
		}
	}
	for _, r := range s.Rules.Rewrites {
		if strings.ContainsAny(r, "\x00\r\n") || len(r) > maxText {
			return invalid("a rewrite line cannot be written as it is")
		}
	}
	return nil
}

// owned says name is one of the account's own database names: the account
// name, "_" and a suffix, as cPanel and Sifruno's database service name
// them.
func owned(account, name string) bool {
	return cpsource.DatabasePattern.MatchString(name) && strings.HasPrefix(name, account+"_") && len(name) > len(account)+1
}

// clip keeps text to one bounded line.
func clip(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > maxText {
		s = s[:maxText]
		for len(s) > 0 && s[len(s)-1]&0xc0 == 0x80 {
			s = s[:len(s)-1]
		}
		if len(s) > 0 && s[len(s)-1] >= 0xc0 {
			s = s[:len(s)-1]
		}
	}
	return s
}
