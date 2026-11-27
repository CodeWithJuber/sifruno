package sitesource

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
)

// WPConfig is what a WordPress site's wp-config.php names for its
// database. Password is a credential: the caller keeps it in memory for
// the copy only and never logs, stores or answers it.
type WPConfig struct {
	Name, User, Password, Host, Prefix string
}

// ErrWPConfig means wp-config.php does not name its database in a form
// this reads; the person then types the database's details.
var ErrWPConfig = errors.New("wp-config.php does not name its database plainly")

// maxWPConfig bounds the file read.
const maxWPConfig = 256 << 10

var (
	wpDefine = regexp.MustCompile(`(?m)^\s*define\s*\(\s*['"](DB_NAME|DB_USER|DB_PASSWORD|DB_HOST)['"]\s*,\s*('(?:[^'\\]|\\.)*'|"(?:[^"\\$]|\\.)*")\s*\)\s*;`)
	wpPrefix = regexp.MustCompile(`(?m)^\s*\$table_prefix\s*=\s*('(?:[^'\\]|\\.)*'|"(?:[^"\\$]|\\.)*")\s*;`)
)

// ParseWPConfig reads the four DB_ constants and the table prefix as plain
// PHP string literals. A value built from an expression, an environment
// variable or a constant is not read: ErrWPConfig. Each constant counts
// once, as PHP's define keeps the first.
func ParseWPConfig(data []byte) (WPConfig, error) {
	if len(data) > maxWPConfig {
		return WPConfig{}, ErrWPConfig
	}
	text := stripPHPComments(string(data))
	var c WPConfig
	seen := map[string]bool{}
	for _, m := range wpDefine.FindAllStringSubmatch(text, -1) {
		if seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		v := phpString(m[2])
		switch m[1] {
		case "DB_NAME":
			c.Name = v
		case "DB_USER":
			c.User = v
		case "DB_PASSWORD":
			c.Password = v
		case "DB_HOST":
			c.Host = v
		}
	}
	if m := wpPrefix.FindStringSubmatch(text); m != nil {
		c.Prefix = phpString(m[1])
	}
	if !seen["DB_NAME"] || !seen["DB_USER"] || !seen["DB_PASSWORD"] || c.Name == "" || c.User == "" {
		return WPConfig{}, ErrWPConfig
	}
	if !seen["DB_HOST"] {
		c.Host = "localhost"
	}
	return c, nil
}

// LocalDatabase says the site's database is on the same server, where the
// copy's dump runs: localhost, 127.0.0.1 or a local socket.
func (c WPConfig) LocalDatabase() bool {
	h := c.Host
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return h == "localhost" || h == "127.0.0.1" || h == "::1" || h == ""
}

// NativeHash is the mysql_native_password hash of the site's password,
// "*" and 40 upper-case hex digits (SHA1 of SHA1), so the user is made here
// with the same password without the password leaving the caller.
func (c WPConfig) NativeHash() string {
	first := sha1.Sum([]byte(c.Password))
	second := sha1.Sum(first[:])
	return "*" + strings.ToUpper(hex.EncodeToString(second[:]))
}

// phpString undoes a PHP literal's quoting: in single quotes only \' and
// \\; in double quotes the usual escapes (a $ was refused by the pattern).
func phpString(lit string) string {
	q, body := lit[0], lit[1:len(lit)-1]
	var b strings.Builder
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c != '\\' || i+1 == len(body) {
			b.WriteByte(c)
			continue
		}
		n := body[i+1]
		switch {
		case n == '\\' || n == byte(q):
			b.WriteByte(n)
			i++
		case q == '"' && n == 'n':
			b.WriteByte('\n')
			i++
		case q == '"' && n == 't':
			b.WriteByte('\t')
			i++
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// stripPHPComments removes // and # line comments and /* */ blocks outside
// string literals, so a commented-out define is not read.
func stripPHPComments(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' || c == '"':
			j := i + 1
			for j < len(s) && s[j] != c {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(s) {
				j = len(s) - 1
			}
			b.WriteString(s[i : j+1])
			i = j
		case c == '#' || (c == '/' && i+1 < len(s) && s[i+1] == '/'):
			for i < len(s) && s[i] != '\n' {
				i++
			}
			b.WriteByte('\n')
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				return b.String()
			}
			for _, r := range s[i : i+2+end+2] {
				if r == '\n' {
					b.WriteByte('\n')
				}
			}
			i += 2 + end + 1
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
