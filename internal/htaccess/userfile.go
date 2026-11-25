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
// PasswdFile::parseLine) but checks hashes its own way. In v1.9.4 a user
// starts as ENCRYPT_PLAIN (src/http/authuser.h:51), and when it is loaded
// UserDir::getUser (src/http/userdir.cpp:195) calls
// AuthUser::updatePasswdEncMethod (src/http/authuser.cpp:84), which
// recognises three formats by their prefix:
//
//   - "$apr1$": ENCRYPT_APMD5, checked by verifyApMD5 (userdir.cpp:394),
//     Apache's MD5 with the magic and salt hashed as Apache does;
//   - "{SHA}" whose base64 decodes to 20 bytes: ENCRYPT_SHA, the stored
//     digest compared with SHA-1 of the password (verifySHA, userdir.cpp:272);
//   - "$2a$", "$2b$", "$2y$": ENCRYPT_BCRYPT, checked with
//     _crypt_blowfish_rn and compared in constant time (verifyBcrypt,
//     userdir.cpp:446).
//
// Every other hash stays ENCRYPT_PLAIN, and UserDir::authenticate
// (userdir.cpp:459, the ENCRYPT_PLAIN case at 482) first compares the
// password with the stored text itself and only then with crypt(3): for
// DES, $1$, $5$ and $6$ crypt hashes, and for plain text, the stored text
// signs in as the password. Apache never accepts that (apr_password_validate
// hands an unrecognised hash to crypt). So NormalizeUserFile keeps a line only
// when its hash is $apr1$, {SHA}, $2y$ or $2b$, and refuses the file
// otherwise, naming the user whose password must be set again; $2a$ is left
// out too, as the bcrypt prefix with a known flaw in old implementations.
// It writes the file again with nothing but "user:hash" lines.
//
// Jev had picked keeping crypt hashes (with_crypt, 0.59 over 0.41,
// confidence 0.18); the owner's review chose the strict list instead: a
// protected folder must not accept the stored hash text as a password.

// MaxUserFileBytes and MaxUserFileUsers bound a user file.
const (
	MaxUserFileBytes = 64 << 10
	MaxUserFileUsers = 1000
)

// hashShapes are the hashes OpenLiteSpeed checks against the password
// alone (see above).
var hashShapes = []*regexp.Regexp{
	regexp.MustCompile(`^\$apr1\$[./0-9A-Za-z]{1,8}\$[./0-9A-Za-z]{22}$`),
	regexp.MustCompile(`^\{SHA\}[A-Za-z0-9+/]{27}=$`),
	regexp.MustCompile(`^\$2[by]\$(0[4-9]|[12][0-9]|3[01])\$[./A-Za-z0-9]{53}$`),
}

// weakHash recognises the crypt(3) formats OpenLiteSpeed would also let in
// by their stored text, so a refusal can say what the hash is.
var weakHash = regexp.MustCompile(`^(\$(1|5|6|2a)\$.*|[./0-9A-Za-z]{13})$`)

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
		switch {
		case !known && weakHash.MatchString(hash):
			return nil, nil, &UserFileError{Line: i + 1, User: user, Reason: "the password of " + user + " is stored in an older format (crypt) for which this server's web server would also accept the stored text itself"}
		case !known:
			return nil, nil, &UserFileError{Line: i + 1, User: user, Reason: "the password of " + user + " is not stored in a format this server's web server checks safely"}
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
