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
	text := blankPHPComments(string(data))
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

// blankPHPComments turns // and # line comments and /* */ blocks outside
// string literals into spaces, keeping every other byte where it is, so a
// commented-out define is not read and a match's offsets are the file's.
// An unclosed block blanks the rest of the file.
func blankPHPComments(s string) string {
	b := []byte(s)
	blank := func(from, to int) {
		for k := from; k < to; k++ {
			if b[k] != '\n' {
				b[k] = ' '
			}
		}
	}
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
			i = min(j, len(s)-1)
		case c == '#' || (c == '/' && i+1 < len(s) && s[i+1] == '/'):
			j := i
			for j < len(s) && s[j] != '\n' {
				j++
			}
			blank(i, j)
			i = j
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				blank(i, len(s))
				return string(b)
			}
			blank(i, i+2+end+2)
			i += 2 + end + 1
		}
	}
	return string(b)
}

// wpName is a database or user name this server writes into wp-config.php.
var wpName = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

// RewriteWPConfig points wp-config.php at the database here: the string
// literal of the first DB_NAME, DB_USER and DB_HOST define (the ones PHP
// keeps) becomes 'name', 'user' and 'localhost', and nothing else in the
// file changes. The password stays: the user here has the same one. A file
// ParseWPConfig does not read is ErrWPConfig and is not changed.
func RewriteWPConfig(data []byte, name, user string) ([]byte, error) {
	if !wpName.MatchString(name) || !wpName.MatchString(user) {
		return nil, ErrWPConfig
	}
	if _, err := ParseWPConfig(data); err != nil {
		return nil, err
	}
	text := blankPHPComments(string(data))
	values := map[string]string{"DB_NAME": name, "DB_USER": user, "DB_HOST": "localhost"}
	type change struct {
		from, to int
		value    string
	}
	var changes []change
	seen := map[string]bool{}
	for _, m := range wpDefine.FindAllStringSubmatchIndex(text, -1) {
		constant := text[m[2]:m[3]]
		if seen[constant] {
			continue
		}
		seen[constant] = true
		if v, ok := values[constant]; ok {
			changes = append(changes, change{m[4], m[5], "'" + v + "'"})
		}
	}
	out := make([]byte, 0, len(data)+64)
	last := 0
	for _, c := range changes {
		out = append(out, data[last:c.from]...)
		out = append(out, c.value...)
		last = c.to
	}
	out = append(out, data[last:]...)
	return out, nil
}
