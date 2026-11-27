package olsweb

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The PHP settings a migration carried from the site's root .htaccess
// (internal/htaccess phpsettings.go) are written into the site's
// vhconf.conf as OpenLiteSpeed's "php.ini Override" block:
//
//	phpIniOverride  {
//	php_value memory_limit 256M
//	php_flag display_errors off
//	}
//
// OpenLiteSpeed reads PHP settings only from there (dist/docs/
// Static_Context.html at v1.9.4, "php.ini Override"), never from
// .htaccess, and Sifruno's LSPHP reads no .user.ini. It hands them to the
// site's lsphp with every request, which applies php_value and php_flag
// at the stage Apache's .htaccess lines run at, so the site's code can
// still change them with ini_set, as on Apache. On a running server
// (docs/migration-design.md, "PHP settings") a vhost's block set every
// value it named, read back through PHP.
//
// Only the names a site may set from .htaccess here are written (the
// htaccess package's list), each once, sorted by name. A value is a word
// of letters, digits, '.' and '_', optionally after one '-', so it names
// no file, folder or program and cannot end the line or the block; a
// time zone (date.timezone) may hold '/' between its parts. A flag's
// value is on or off. memory_limit may not exceed the site's own memory
// limit (Limits.MemoryMiB, each lsphp process's address space): the
// broker writes the smaller of the two.

// PHPSetting is one line of a site's phpIniOverride: php_flag when Flag,
// else php_value.
type PHPSetting struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Flag  bool   `json:"flag,omitempty"`
}

// MaxPHPSettings bounds a site's PHP settings.
const MaxPHPSettings = 32

// phpIniNames are the settings a site's phpIniOverride may hold: the
// htaccess package's list of what a migration carries.
var phpIniNames = map[string]bool{
	"memory_limit": true, "upload_max_filesize": true, "post_max_size": true,
	"max_execution_time": true, "max_input_time": true, "max_input_vars": true,
	"max_input_nesting_level": true, "max_file_uploads": true, "session.gc_maxlifetime": true,
	"session.cookie_lifetime": true, "default_socket_timeout": true, "pcre.backtrack_limit": true,
	"pcre.recursion_limit": true, "error_reporting": true, "display_errors": true,
	"display_startup_errors": true, "log_errors": true, "html_errors": true, "short_open_tag": true,
	"session.cookie_httponly": true, "session.cookie_secure": true, "session.use_strict_mode": true,
	"session.use_only_cookies": true, "output_buffering": true, "zlib.output_compression": true,
	"date.timezone": true,
}

var (
	phpIniValue    = regexp.MustCompile(`^-?[A-Za-z0-9_.]{1,64}$`)
	phpIniTimeZone = regexp.MustCompile(`^(?:UTC|[A-Z][A-Za-z_]{1,30}(?:/[A-Z][A-Za-z0-9_+-]{0,30}){1,2})$`)
	phpIniSize     = regexp.MustCompile(`^([0-9]{1,12})([KkMmGg]?)$`)
)

// CheckPHPSettings validates a site's PHP settings exactly as Validate
// does for a site whose memory limit is memoryMiB (0: the default), so a
// caller can refuse them before it stores them. A FieldError names the
// field as site.php_settings[i]...
func CheckPHPSettings(settings []PHPSetting, memoryMiB int) error {
	if memoryMiB == 0 {
		memoryMiB = DefaultMemoryMiB
	}
	return checkPHPSettings("site", settings, memoryMiB)
}

func checkPHPSettings(field string, settings []PHPSetting, memoryMiB int) error {
	if len(settings) > MaxPHPSettings {
		return fieldErr(field+".php_settings", "at most %d settings", MaxPHPSettings)
	}
	for i, s := range settings {
		f := fmt.Sprintf("%s.php_settings[%d]", field, i)
		if !phpIniNames[s.Name] {
			return fieldErr(f+".name", "must be a setting a site may set from .htaccess here")
		}
		if i > 0 && settings[i-1].Name >= s.Name {
			return fieldErr(f+".name", "settings must be sorted by name, each once")
		}
		switch {
		case s.Flag:
			if s.Value != "on" && s.Value != "off" {
				return fieldErr(f+".value", "a flag must be on or off")
			}
		case s.Name == "date.timezone":
			if !phpIniTimeZone.MatchString(s.Value) {
				return fieldErr(f+".value", "must be a time zone name such as Europe/Berlin")
			}
		case !phpIniValue.MatchString(s.Value):
			return fieldErr(f+".value", "must be letters, digits, . and _, at most 64 bytes, optionally after one -")
		}
		if s.Name == "memory_limit" {
			if mib, ok := PHPSizeMiB(s.Value); !ok || mib > memoryMiB {
				return fieldErr(f+".value", "memory_limit must be a size of at most the site's %d MiB", memoryMiB)
			}
		}
	}
	return nil
}

// PHPSizeMiB reads a PHP size (bytes, or a number with K, M or G) and
// returns it in MiB, rounded up; ok is false for anything else, -1 (no
// limit) among it.
func PHPSizeMiB(v string) (int, bool) {
	m := phpIniSize.FindStringSubmatch(v)
	if m == nil {
		return 0, false
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, false
	}
	switch strings.ToLower(m[2]) {
	case "":
	case "k":
		n <<= 10
	case "m":
		n <<= 20
	case "g":
		n <<= 30
	}
	mib := (n + 1<<20 - 1) >> 20
	if mib > 1<<30 {
		return 0, false
	}
	return int(mib), true
}

// renderPHPIni writes an active site's phpIniOverride block.
func renderPHPIni(b *bytes.Buffer, settings []PHPSetting) {
	if len(settings) == 0 {
		return
	}
	b.WriteString("\nphpIniOverride  {\n")
	for _, s := range settings {
		directive := "php_value"
		if s.Flag {
			directive = "php_flag"
		}
		b.WriteString(directive + " " + s.Name + " " + s.Value + "\n")
	}
	b.WriteString("}\n")
}
