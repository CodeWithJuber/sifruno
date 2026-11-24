package htaccess

import (
	"bytes"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// A converted realm's users come from the AuthUserFile the old server named.
// OpenLiteSpeed reads the same "user:hash" format (src/http/htpasswd.cpp,
// PasswdFile::parseLine), but it checks some hashes differently from Apache
// (src/http/userdir.cpp, UserDir::authenticate; src/http/authuser.cpp,
// updatePasswdEncMethod): $apr1$, {SHA} and bcrypt are recognised by their
// prefix, and anything else is compared first as plain text and then with
// crypt(3). Apache on Linux has no plain-text passwords (apr_password_validate
// hands any unrecognised hash to crypt), so a plain-text line would let its
// literal text in on OpenLiteSpeed only. NormalizeUserFile therefore keeps a
// line only when its hash has one of the shapes below, and writes the file
// again with nothing but "user:hash" lines.
//
// The owner chose (Jev, 2026-11-24, 0.59 over 0.41, confidence 0.18) to keep
// crypt hashes (DES, $1$, $5$, $6$) as well, accepting that on OpenLiteSpeed
// the stored hash text of such a user also signs in. bcrypt is kept only as
// $2y$, the one prefix Apache checks itself rather than through crypt(3).

// MaxUserFileBytes and MaxUserFileUsers bound a user file.
const (
	MaxUserFileBytes = 64 << 10
	MaxUserFileUsers = 1000
)

var hashShapes = []*regexp.Regexp{
	regexp.MustCompile(`^\$apr1\$[./0-9A-Za-z]{1,8}\$[./0-9A-Za-z]{22}$`),
	regexp.MustCompile(`^\{SHA\}[A-Za-z0-9+/]{27}=$`),
	regexp.MustCompile(`^\$2y\$[0-3][0-9]\$[./A-Za-z0-9]{53}$`),
	// crypt(3): DES, MD5, SHA-256 and SHA-512 crypt.
	regexp.MustCompile(`^[./0-9A-Za-z]{13}$`),
	regexp.MustCompile(`^\$1\$[./0-9A-Za-z]{1,8}\$[./0-9A-Za-z]{22}$`),
	regexp.MustCompile(`^\$5\$(rounds=[1-9][0-9]{3,8}\$)?[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{43}$`),
	regexp.MustCompile(`^\$6\$(rounds=[1-9][0-9]{3,8}\$)?[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}$`),
}

// UserFileError says why a user file was refused; User names the line's user
// when the line had one, so the owner knows whose password to reset.
type UserFileError struct {
	Line   int
	User   string
	Reason string
}

func (e *UserFileError) Error() string {
	return "password file line " + strconv.Itoa(e.Line) + ": " + e.Reason
}

// ErrUserFile is wrapped by every UserFileError.
var ErrUserFile = errors.New("password file refused")

func (e *UserFileError) Unwrap() error { return ErrUserFile }

// NormalizeUserFile checks an Apache user file and returns it rewritten as
// "user:hash\n" lines in file order, with the user names. Blank lines and
// lines starting with '#' are left out, as Apache skips them. A line with
// spaces, a third field, a user name outside [A-Za-z0-9._@-], a user listed
// twice, or a hash of another shape refuses the whole file.
func NormalizeUserFile(data []byte) ([]byte, []string, error) {
	if len(data) > MaxUserFileBytes || !utf8.Valid(data) {
		return nil, nil, &UserFileError{Reason: "the file is larger than 64 KiB or not text"}
	}
	var out bytes.Buffer
	var users []string
	seen := map[string]bool{}
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSuffix(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		user, hash, ok := strings.Cut(line, ":")
		if !ok {
			return nil, nil, &UserFileError{Line: i + 1, Reason: "the line is not user:hash"}
		}
		if !realmUserPattern.MatchString(user) {
			return nil, nil, &UserFileError{Line: i + 1, Reason: "the user name is not a plain name"}
		}
		if seen[user] {
			return nil, nil, &UserFileError{Line: i + 1, User: user, Reason: "the user is listed twice"}
		}
		known := false
		for _, shape := range hashShapes {
			if shape.MatchString(hash) {
				known = true
				break
			}
		}
		if !known {
			return nil, nil, &UserFileError{Line: i + 1, User: user, Reason: "the password hash is not one this server checks the way Apache does"}
		}
		if len(users) >= MaxUserFileUsers {
			return nil, nil, &UserFileError{Line: i + 1, Reason: "more than 1000 users"}
		}
		seen[user] = true
		users = append(users, user)
		out.WriteString(user + ":" + hash + "\n")
	}
	if len(users) == 0 {
		return nil, nil, &UserFileError{Reason: "the file has no users"}
	}
	return out.Bytes(), users, nil
}
