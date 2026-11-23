package operator

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"sifruno/internal/securestate"
)

// Admin accounts live in one private JSON file next to access.key until the
// plan's single SQLite store exists. The file holds Argon2id password hashes
// and TOTP secrets; like session.keys it is readable only by the panel's own
// OS user, and anyone who can read it can already forge sessions.

const (
	adminsFile     = "admins.json"
	maxAdminsBytes = 64 << 10
	maxAdmins      = 16
	minPassword    = 12  // characters (NIST SP 800-63B minimum is 8; admins get more)
	maxPassword    = 256 // bytes; Argon2 cost does not depend on length, this bounds parsing
)

// OWASP Password Storage Cheat Sheet minimum for Argon2id: 19 MiB, 2 passes,
// 1 lane. Stored per hash so the cost can be raised without breaking logins.
const (
	argonMemoryKiB = 19 * 1024
	argonPasses    = 2
	argonThreads   = 1
	argonKeyBytes  = 32
	argonSaltBytes = 16
)

var usernamePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{2,31}$`)

type passwordHash struct {
	Algorithm string `json:"algorithm"`
	Version   int    `json:"version"`
	MemoryKiB uint32 `json:"memory_kib"`
	Passes    uint32 `json:"passes"`
	Threads   uint8  `json:"threads"`
	Salt      string `json:"salt"`
	Key       string `json:"key"`
}

type adminTOTP struct {
	Secret   string `json:"secret"`
	LastStep int64  `json:"last_step"`
}

type adminRecord struct {
	Username  string       `json:"username"`
	Password  passwordHash `json:"password"`
	TOTP      adminTOTP    `json:"totp"`
	CreatedAt time.Time    `json:"created_at"`
}

type adminFile struct {
	Version int           `json:"version"`
	Admins  []adminRecord `json:"admins"`
}

func validUsername(s string) bool { return usernamePattern.MatchString(s) }

// passwordProblem returns a sentence for the person choosing the password, or
// "" when it is acceptable. No composition rules: length is what matters.
func passwordProblem(username, password string) string {
	switch {
	case !utf8.ValidString(password) || len(password) > maxPassword:
		return "Use a password of at most 256 bytes of ordinary text."
	case utf8.RuneCountInString(password) < minPassword:
		return "Use a password of at least 12 characters. A few unrelated words work well."
	case strings.EqualFold(strings.TrimSpace(password), username):
		return "The password cannot be the username."
	}
	return ""
}

func hashPassword(password string) (passwordHash, error) {
	salt := make([]byte, argonSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return passwordHash{}, err
	}
	key := argon2.IDKey([]byte(password), salt, argonPasses, argonMemoryKiB, argonThreads, argonKeyBytes)
	return passwordHash{Algorithm: "argon2id", Version: argon2.Version, MemoryKiB: argonMemoryKiB, Passes: argonPasses, Threads: argonThreads,
		Salt: base64.RawStdEncoding.EncodeToString(salt), Key: base64.RawStdEncoding.EncodeToString(key)}, nil
}

// decode bounds stored parameters so an edited file cannot make one login
// allocate unbounded memory or CPU.
func (h passwordHash) decode() (salt, key []byte, ok bool) {
	if h.Algorithm != "argon2id" || h.Version != argon2.Version || h.MemoryKiB < 8*1024 || h.MemoryKiB > 256*1024 ||
		h.Passes < 1 || h.Passes > 10 || h.Threads < 1 || h.Threads > 8 {
		return nil, nil, false
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(h.Salt)
	if err != nil || len(salt) < argonSaltBytes || len(salt) > 64 {
		return nil, nil, false
	}
	key, err = base64.RawStdEncoding.Strict().DecodeString(h.Key)
	if err != nil || len(key) != argonKeyBytes {
		return nil, nil, false
	}
	return salt, key, true
}

func (h passwordHash) matches(password string) bool {
	salt, key, ok := h.decode()
	if !ok {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, h.Passes, h.MemoryKiB, h.Threads, argonKeyBytes)
	return subtle.ConstantTimeCompare(got, key) == 1
}

func (f adminFile) find(username string) (int, bool) {
	for i, a := range f.Admins {
		if a.Username == username {
			return i, true
		}
	}
	return -1, false
}

func (f adminFile) validate() error {
	if f.Version != 1 || len(f.Admins) > maxAdmins {
		return errors.New("unsupported admin file")
	}
	seen := map[string]bool{}
	for _, a := range f.Admins {
		_, _, hashOK := a.Password.decode()
		_, secretOK := decodeTOTPSecret(a.TOTP.Secret)
		if !validUsername(a.Username) || seen[a.Username] || !hashOK || !secretOK || a.TOTP.LastStep < 0 || a.CreatedAt.IsZero() {
			return errors.New("invalid admin record")
		}
		seen[a.Username] = true
	}
	return nil
}

// loadAdmins reads the admin file with the same checks as the other private
// state: no symlinks, a regular file only the owner can read, bounded size.
// A missing file means no admin exists yet.
func loadAdmins(dir string) (adminFile, error) {
	path := filepath.Join(dir, adminsFile)
	if err := securestate.CheckPath(path); err != nil {
		return adminFile{}, err
	}
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return adminFile{Version: 1}, nil
	}
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxAdminsBytes || (runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0) {
		return adminFile{}, errors.New("invalid admin file")
	}
	f, err := os.Open(path)
	if err != nil {
		return adminFile{}, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(st, opened) || privateHandle(f, opened) != nil {
		return adminFile{}, errors.New("admin file changed")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxAdminsBytes+1))
	if err != nil || len(raw) > maxAdminsBytes {
		return adminFile{}, errors.New("invalid admin file")
	}
	var out adminFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil || dec.More() {
		return adminFile{}, errors.New("invalid admin file")
	}
	if err := out.validate(); err != nil {
		return adminFile{}, err
	}
	return out, nil
}

// saveAdmins replaces the file atomically: a new private file in the same
// directory, synced, then renamed over the old one.
func saveAdmins(dir string, file adminFile) error {
	if err := file.validate(); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(file, "", "  ")
	if err != nil || len(raw) > maxAdminsBytes {
		return errors.New("admin file too large")
	}
	path := filepath.Join(dir, adminsFile)
	if err := securestate.CheckPath(path); err != nil {
		return err
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	tmp := filepath.Join(dir, adminsFile+".tmp-"+base64.RawURLEncoding.EncodeToString(suffix))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err == nil {
		err = privateHandle(f, st)
	}
	if err == nil {
		_, err = f.Write(append(raw, '\n'))
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	syncDir(dir)
	return nil
}

// syncDir makes the rename durable where the platform supports it; a failure
// only risks losing the newest write after a power cut, not a corrupt file.
func syncDir(dir string) {
	if runtime.GOOS == "windows" {
		return
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}
