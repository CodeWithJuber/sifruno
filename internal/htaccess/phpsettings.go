package htaccess

import (
	"regexp"
	"strconv"
	"strings"
)

// php_value and php_flag reach PHP only through Apache's PHP module
// (mod_php, CloudLinux's mod_lsapi) or LiteSpeed Enterprise. OpenLiteSpeed
// 1.9.4 takes PHP settings only from a virtual host's or context's
// phpIniOverride (doc.go), and Sifruno's LSPHP reads no .user.ini
// (docs/migration-design.md, "PHP settings", has the evidence from a
// running server). So the converter carries a root .htaccess's settings
// into the site's phpIniOverride, which the root broker writes (olsweb
// phpini.go), for a short list of settings with values of a checked shape:
//
//	shape     settings
//	size      memory_limit (or -1), upload_max_filesize, post_max_size
//	number    max_execution_time, max_input_time (or -1), max_input_vars,
//	          max_input_nesting_level, max_file_uploads,
//	          session.gc_maxlifetime, session.cookie_lifetime,
//	          default_socket_timeout, pcre.backtrack_limit,
//	          pcre.recursion_limit, error_reporting (or -1)
//	on/off    display_errors, display_startup_errors, log_errors,
//	          html_errors, short_open_tag, session.cookie_httponly,
//	          session.cookie_secure, session.use_strict_mode,
//	          session.use_only_cookies
//	on/off    output_buffering, zlib.output_compression
//	or number
//	time zone date.timezone (Area/Location)
//
// Every one is a setting PHP lets .htaccess change (PHP_INI_PERDIR or
// PHP_INI_ALL in php.net's list of ini settings), and none names a file,
// a folder or a program. Apache reads php_value and php_flag as two
// words (TAKE2), so a line with another count refuses. mod_php reads a
// php_flag value as on when it is "On" or "1" and off for anything else
// (sapi/apache2handler/apache_config.c, php_apache_flag_handler_ex), so
// only On, Off, 1 and 0 carry.
//
// A setting carries from the root .htaccess, at its top level or inside
// <IfModule> sections Apache reads (movable, as for redirects): in a
// folder's .htaccess or a <Files> section it applied to part of the site
// only, and the vhost's phpIniOverride applies to all of it. The later line
// for a setting wins, as in Apache.
//
// Everything else refuses, naming the line: settings that name a file,
// folder or program (auto_prepend_file, auto_append_file, include_path,
// open_basedir, sendmail_path, session.save_path, error_log ...), the
// settings only a server's administrator may set (disable_functions and
// every php_admin_value or php_admin_flag line), and any setting or value
// not in the list. Two lines do nothing here either way and so do not
// refuse:
//
//   - session.save_path set to cPanel's own session folder for a PHP
//     package (/var/cpanel/php/sessions/ea-php81), which cPanel's MultiPHP
//     INI Editor writes into the root .htaccess; this server's PHP keeps
//     sessions in its own folder (handled);
//   - an Off value for a setting PHP 5.4 removed (register_globals,
//     magic_quotes_gpc, safe_mode ...): it names no setting on the PHP
//     8.1 to 8.4 this server runs, so PHP ignores the line on both servers
//     (ignored).

// PHPSetting is one php_value or php_flag line of the root .htaccess that
// the vhost carries. Name is lower case. A flag's Value is "on" or "off".
type PHPSetting struct {
	Line  int    `json:"line"`
	Name  string `json:"name"`
	Value string `json:"value"`
	Flag  bool   `json:"flag,omitempty"`
}

// MaxSitePHPSettings bounds the settings one site carries; more refuse.
const MaxSitePHPSettings = 32

type phpShape int

const (
	phpSize phpShape = iota
	phpNumber
	phpOnOff
	phpOnOffOrNumber
	phpTimeZone
)

// phpSettings are the settings a root .htaccess carries, each with its
// value's shape and whether -1 (no limit) is a value it takes.
var phpSettings = map[string]struct {
	shape    phpShape
	minusOne bool
}{
	"memory_limit":             {phpSize, true},
	"upload_max_filesize":      {phpSize, false},
	"post_max_size":            {phpSize, false},
	"max_execution_time":       {phpNumber, false},
	"max_input_time":           {phpNumber, true},
	"max_input_vars":           {phpNumber, false},
	"max_input_nesting_level":  {phpNumber, false},
	"max_file_uploads":         {phpNumber, false},
	"session.gc_maxlifetime":   {phpNumber, false},
	"session.cookie_lifetime":  {phpNumber, false},
	"default_socket_timeout":   {phpNumber, true},
	"pcre.backtrack_limit":     {phpNumber, false},
	"pcre.recursion_limit":     {phpNumber, false},
	"error_reporting":          {phpNumber, true},
	"display_errors":           {phpOnOff, false},
	"display_startup_errors":   {phpOnOff, false},
	"log_errors":               {phpOnOff, false},
	"html_errors":              {phpOnOff, false},
	"short_open_tag":           {phpOnOff, false},
	"session.cookie_httponly":  {phpOnOff, false},
	"session.cookie_secure":    {phpOnOff, false},
	"session.use_strict_mode":  {phpOnOff, false},
	"session.use_only_cookies": {phpOnOff, false},
	"output_buffering":         {phpOnOffOrNumber, false},
	"zlib.output_compression":  {phpOnOffOrNumber, false},
	"date.timezone":            {phpTimeZone, false},
}

// removedPHPSettings were removed in PHP 5.4.0 (php.net, "Backward
// Incompatible Changes" of the 5.3 to 5.4 migration guide).
var removedPHPSettings = map[string]bool{
	"register_globals": true, "register_long_arrays": true, "magic_quotes_gpc": true,
	"magic_quotes_runtime": true, "magic_quotes_sybase": true, "safe_mode": true,
	"allow_call_time_pass_reference": true,
}

var (
	// phpSizeValue is a number of bytes, or of K, M or G (PHP's own
	// shorthand); phpNumberValue a whole number.
	phpSizeValue   = regexp.MustCompile(`^(?:[0-9]{1,12}|[0-9]{1,6}[KkMmGg])$`)
	phpNumberValue = regexp.MustCompile(`^[0-9]{1,10}$`)
	// phpTimeZoneValue is an IANA time zone name: UTC, or Area/Location
	// with an optional third part.
	phpTimeZoneValue = regexp.MustCompile(`^(?:UTC|[A-Z][A-Za-z_]{1,30}(?:/[A-Z][A-Za-z0-9_+-]{0,30}){1,2})$`)
	// cpanelSessions is the folder cPanel's MultiPHP INI Editor names for
	// a PHP package's sessions.
	cpanelSessions = regexp.MustCompile(`^/var/cpanel/php/sessions/(?:ea|alt)-php[0-9]{2}/?$`)
)

// CarriedPHPSetting reports whether this server carries a setting with
// this value into a site's phpIniOverride: the check the converter makes,
// for the broker to make again on what it records.
func CarriedPHPSetting(s PHPSetting) bool {
	rule, ok := phpSettings[s.Name]
	if !ok {
		return false
	}
	value, flag, ok := phpValue(rule.shape, rule.minusOne, s.Value, s.Flag)
	return ok && value == s.Value && flag == s.Flag
}

// phpValue checks a value against its shape and returns it as the vhost
// writes it: flags as on or off. fromFlag is a php_flag line.
func phpValue(shape phpShape, minusOne bool, v string, fromFlag bool) (string, bool, bool) {
	onOff := func() (string, bool, bool) {
		switch strings.ToLower(v) {
		case "on", "1":
			return "on", true, true
		case "off", "0":
			return "off", true, true
		}
		return "", false, false
	}
	if fromFlag || shape == phpOnOff {
		if shape != phpOnOff && shape != phpOnOffOrNumber {
			return "", false, false
		}
		return onOff()
	}
	if minusOne && v == "-1" {
		return v, false, true
	}
	switch shape {
	case phpSize:
		return v, false, phpSizeValue.MatchString(v)
	case phpNumber:
		return v, false, phpNumberValue.MatchString(v)
	case phpOnOffOrNumber:
		if value, flag, ok := onOff(); ok {
			return value, flag, ok
		}
		return v, false, phpNumberValue.MatchString(v)
	case phpTimeZone:
		return v, false, phpTimeZoneValue.MatchString(v)
	}
	return "", false, false
}

// convertPHP reads a php_value, php_flag, php_admin_value or
// php_admin_flag line OpenLiteSpeed ignores ("engine off" is access
// control and never gets here). It returns the setting the vhost carries,
// a handling class for the two lines that do nothing either way, or no
// handling and why not.
func (c *classifier) convertPHP(name string, args []string, sc scope) (Handling, string, *PHPSetting) {
	if name == "php_admin_value" || name == "php_admin_flag" {
		return "", "a PHP setting only the old server's administrator could set (" + name + "): this server does not take one from a website", nil
	}
	if len(args) != 2 {
		return "", "a " + name + " line without a setting name and one value, which Apache refuses", nil
	}
	setting, value := strings.ToLower(args[0]), args[1]
	if removedPHPSettings[setting] && isOff(value) {
		return HandlingIgnored, "a PHP setting PHP 5.4 removed: PHP 8.1 to 8.4, which this server runs, has no such setting, so the line does nothing", nil
	}
	if !c.root || !movable(sc) {
		return "", "a PHP setting in a folder's .htaccess or inside a section: on the old server it applied there only, and this server sets PHP options for the whole site", nil
	}
	if setting == "session.save_path" && name == "php_value" && cpanelSessions.MatchString(value) {
		return HandlingSifruno, "cPanel's own session folder for its PHP package: this server's PHP keeps the site's sessions in its own session folder", nil
	}
	rule, ok := phpSettings[setting]
	if !ok {
		return "", phpRefusal(setting, value), nil
	}
	v, flag, ok := phpValue(rule.shape, rule.minusOne, value, name == "php_flag")
	if !ok {
		return "", "a value for " + setting + " this server does not carry: " + phpShapeText(rule.shape, rule.minusOne), nil
	}
	return HandlingConverted, "PHP setting: OpenLiteSpeed does not read it from .htaccess, so this server writes it into the site's web server configuration, where the site's PHP reads it", &PHPSetting{Name: setting, Value: v, Flag: flag}
}

// phpRefusal says why a setting outside the list does not move.
func phpRefusal(setting, value string) string {
	switch setting {
	case "auto_prepend_file", "auto_append_file":
		when := "before"
		if setting == "auto_append_file" {
			when = "after"
		}
		return setting + " names a file PHP runs " + when + " every script, often a security plugin's firewall (such as Wordfence's extended protection). This server does not carry PHP settings that name files, so moving the site would turn that file off"
	case "open_basedir", "disable_functions", "disable_classes":
		return setting + " is a security setting this server keeps for itself; a website does not set it here"
	case "include_path", "sendmail_path", "session.save_path", "error_log", "upload_tmp_dir", "sys_temp_dir":
		return setting + " names a file, folder or program of the old server, and this server does not carry PHP settings that name them"
	}
	if strings.ContainsAny(value, "/\\") {
		return "a PHP setting whose value names a file or folder of the old server, which this server does not carry"
	}
	return "a PHP setting this server does not carry: only memory and upload sizes, time and input limits, error display and reporting, output buffering, session cookie settings and the time zone move"
}

func phpShapeText(shape phpShape, minusOne bool) string {
	var s string
	switch shape {
	case phpSize:
		s = "it must be a size such as 256M"
	case phpNumber:
		s = "it must be a whole number"
	case phpOnOff:
		s = "it must be On, Off, 1 or 0"
	case phpOnOffOrNumber:
		s = "it must be On, Off or a whole number"
	case phpTimeZone:
		s = "it must be a time zone name such as Europe/Berlin"
	}
	if minusOne {
		s += ", or -1"
	}
	return s
}

// sitePHPSettings collects a site's carried PHP settings from its root
// .htaccess, the later line for a setting winning, in the order the
// settings first appear.
func sitePHPSettings(files []FileResult) ([]PHPSetting, *FileRefusal) {
	var out []PHPSetting
	for _, f := range files {
		for _, g := range f.Findings {
			if g.PHPSetting == nil {
				continue
			}
			s := *g.PHPSetting
			s.Line = g.Line
			replaced := false
			for i := range out {
				if out[i].Name == s.Name {
					out[i], replaced = s, true
				}
			}
			if replaced {
				continue
			}
			if len(out) == MaxSitePHPSettings {
				return nil, &FileRefusal{File: f.Path, Line: g.Line, Directive: g.Label, Cause: CauseNotConverted, Reason: "more PHP settings than this server carries for one site (" + strconv.Itoa(MaxSitePHPSettings) + ")"}
			}
			out = append(out, s)
		}
	}
	return out, nil
}

// The document root's .user.ini. CGI and FastCGI PHP (PHP-FPM, as on
// cPanel) reads it per directory, and Wordfence's extended protection and
// other firewalls load through its auto_prepend_file there. This server's
// LSPHP reads no .user.ini (LSPHP_ENABLE_USER_INI is not in its
// environment; docs/migration-design.md), and the converter does not
// carry a file setting, so the copy runs without that file: a warning a
// person accepts before cutover. The scan reads the document root's file
// only (scan.go), which applies to every script of the site.

// userINIEmpty are the INI words PHP's parser reads as an empty value.
var userINIEmpty = map[string]bool{"": true, "none": true, "null": true, "off": true, "false": true, "no": true}

// UserINIWarnings reads a document root's .user.ini, named file, and
// warns about each auto_prepend_file or auto_append_file line with a
// value: the file PHP ran before or after every script on the old server.
func UserINIWarnings(file string, data []byte) []FileWarning {
	var out []FileWarning
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || line[0] == ';' || line[0] == '[' {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if key != "auto_prepend_file" && key != "auto_append_file" {
			continue
		}
		value = strings.TrimSpace(value)
		quoted := len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0]
		if quoted {
			value = value[1 : len(value)-1]
		} else {
			value, _, _ = strings.Cut(value, ";")
			value = strings.TrimSpace(value)
		}
		if value == "" || (!quoted && userINIEmpty[strings.ToLower(value)]) {
			continue
		}
		when := "before"
		if key == "auto_append_file" {
			when = "after"
		}
		out = append(out, FileWarning{File: file, Line: i + 1, Directive: key, Reason: "the old server's PHP ran a file " + when + " every script (" + key + "), often a security plugin's firewall such as Wordfence's extended protection. This server's PHP does not read .user.ini files, so after the move that file does not run and the firewall's extended protection is off, while the plugin itself still runs. Check the plugin's firewall settings on the copy before cutover."})
	}
	return out
}

// userINIUnread is the warning for a document root .user.ini the scan
// could not read.
func userINIUnread(file, why string) FileWarning {
	return FileWarning{File: file, Reason: "the document root's .user.ini was not read (" + why + "), so whether it makes PHP run a file before every script (such as a firewall) is not known. This server's PHP does not read .user.ini files. Check it on the old server before cutover."}
}
