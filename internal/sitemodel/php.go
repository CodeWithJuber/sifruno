package sitemodel

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"sifruno/internal/htaccess"
)

// The model's PHP settings are what an adapter read. No copy applies them
// as a .user.ini: Sifruno's LSPHP reads no .user.ini, as a running server
// showed (docs/migration-design.md, "PHP settings"). A move from cPanel
// applies the root .htaccess's settings through the vhost's
// phpIniOverride instead, with internal/htaccess phpsettings.go's own
// list; UserINI below is not written by any copy.

// userSettings are the settings a site may set for itself in .user.ini, as
// php.net's ini list marks them (PHP_INI_PERDIR or PHP_INI_ALL). Settings
// that name a file path (auto_prepend_file, session.save_path, error_log)
// are left out: a path from the old server does not exist here.
var userSettings = map[string]bool{
	"memory_limit": true, "max_execution_time": true, "max_input_time": true, "max_input_vars": true,
	"max_input_nesting_level": true, "post_max_size": true, "upload_max_filesize": true, "max_file_uploads": true,
	"display_errors": true, "display_startup_errors": true, "error_reporting": true, "log_errors": true,
	"html_errors": true, "date.timezone": true, "default_charset": true, "output_buffering": true,
	"short_open_tag": true, "zlib.output_compression": true, "default_socket_timeout": true,
	"session.gc_maxlifetime": true, "session.cookie_lifetime": true, "session.cookie_secure": true,
	"session.cookie_httponly": true, "session.cookie_samesite": true, "session.use_strict_mode": true,
	"session.name": true, "precision": true, "serialize_precision": true, "arg_separator.output": true,
	"mbstring.language": true, "mbstring.internal_encoding": true, "pcre.backtrack_limit": true,
	"pcre.recursion_limit": true, "realpath_cache_size": true, "realpath_cache_ttl": true,
}

var (
	// plainValue is written as it is; quotedValue inside double quotes.
	// Nothing else is written: INI reads $, ", ', ;, = and \ specially.
	plainValue  = regexp.MustCompile(`^[A-Za-z0-9_.:/+\-]{1,200}$`)
	quotedValue = regexp.MustCompile(`^[A-Za-z0-9_.:/+\- ,]{0,200}$`)
	// reportingValue is error_reporting's constant expression, which INI
	// evaluates only unquoted.
	reportingValue = regexp.MustCompile(`^[A-Z_0-9 &~|^!()]{1,200}$`)
)

// HtaccessSettings reads php_value and php_flag lines from one .htaccess
// file, named where (for the item text, "public_html/.htaccess"). The
// admin forms are what only the server may set, so they do not move.
func (s *Site) HtaccessSettings(where string, data []byte) {
	f, err := htaccess.Parse(data)
	if err != nil {
		s.Skip("php", "The PHP settings in this .htaccess could not be read: it is larger than 1 MiB.", where)
		return
	}
	var walk func(nodes []*htaccess.Node)
	walk = func(nodes []*htaccess.Node) {
		for _, n := range nodes {
			if n.Kind == htaccess.KindSection {
				walk(n.Children)
				continue
			}
			if n.Kind != htaccess.KindDirective {
				continue
			}
			at := fmt.Sprintf("%s line %d", where, n.Line)
			switch name := strings.ToLower(n.Name); name {
			case "php_value", "php_flag":
				if len(n.Args) != 2 {
					s.Skip("php", "A "+name+" line does not have a name and one value, so it was not read.", at)
					continue
				}
				value := n.Args[1]
				if name == "php_flag" {
					switch strings.ToLower(value) {
					case "on", "1", "true", "yes":
						value = "On"
					case "off", "0", "false", "no":
						value = "Off"
					default:
						s.Skip("php", "The PHP flag "+clip(n.Args[0])+" is not on or off, so it was not carried.", at)
						continue
					}
				}
				s.addSetting(Setting{Name: strings.ToLower(n.Args[0]), Value: value, From: at})
			case "php_admin_value", "php_admin_flag":
				setting := "line"
				if len(n.Args) > 0 {
					setting = clip(n.Args[0])
				}
				s.Skip("php", "The PHP setting "+setting+" is one only the old server's administrator could set; it does not move to the website's own settings.", at)
			}
		}
	}
	walk(f.Nodes)
}

// AddSetting carries one PHP setting from the source, or records why not.
func (s *Site) AddSetting(name, value, from string) {
	s.addSetting(Setting{Name: strings.ToLower(name), Value: value, From: from})
}

func (s *Site) addSetting(p Setting) {
	switch {
	case !userSettings[p.Name]:
		s.Skip("php", "The PHP setting "+clip(p.Name)+" is not one a website sets for itself here, so it was not carried.", p.From)
	case !writable(p):
		s.Skip("php", "The value of the PHP setting "+p.Name+" has characters the website's PHP settings file cannot hold, so it was not carried.", p.From)
	case len(s.PHP.Settings) >= MaxSettings:
		s.Skip("php", "The website has more PHP settings than one move carries; "+p.Name+" was not carried.", p.From)
	default:
		for i, old := range s.PHP.Settings {
			if old.Name == p.Name {
				// The later line wins, as it does in Apache and in PHP.
				s.PHP.Settings[i] = p
				return
			}
		}
		s.PHP.Settings = append(s.PHP.Settings, p)
	}
}

func writable(p Setting) bool {
	if p.Name == "error_reporting" && reportingValue.MatchString(p.Value) {
		return true
	}
	return plainValue.MatchString(p.Value) || quotedValue.MatchString(p.Value)
}

// UserINI is the .user.ini for the site's carried PHP settings, sorted by
// name, or nil when there are none. Every value passed Check's and
// addSetting's rules.
func (p PHP) UserINI() []byte {
	if len(p.Settings) == 0 {
		return nil
	}
	settings := append([]Setting(nil), p.Settings...)
	sort.Slice(settings, func(i, j int) bool { return settings[i].Name < settings[j].Name })
	var b strings.Builder
	b.WriteString("; PHP settings carried from the old server by Sifruno's move.\n")
	for _, s := range settings {
		if !userSettings[s.Name] || !writable(s) {
			continue
		}
		value := s.Value
		if !plainValue.MatchString(value) && !(s.Name == "error_reporting" && reportingValue.MatchString(value)) {
			value = `"` + value + `"`
		}
		fmt.Fprintf(&b, "%s = %s\n", s.Name, value)
	}
	return []byte(b.String())
}
