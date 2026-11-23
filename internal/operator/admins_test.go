package operator

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testAdmin(t *testing.T, username, password string) adminRecord {
	t.Helper()
	h, err := hashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := newTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	return adminRecord{Username: username, Password: h, TOTP: adminTOTP{Secret: secret}, CreatedAt: time.Unix(1, 0).UTC()}
}

func TestPasswordHashArgon2idAndBounds(t *testing.T) {
	h, err := hashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if h.Algorithm != "argon2id" || h.MemoryKiB != 19*1024 || h.Passes != 2 || h.Threads != 1 {
		t.Fatalf("unexpected parameters %+v", h)
	}
	if !h.matches("correct horse battery") || h.matches("correct horse batterY") || h.matches("") {
		t.Fatal("password comparison is wrong")
	}
	other, _ := hashPassword("correct horse battery")
	if other.Salt == h.Salt || other.Key == h.Key {
		t.Fatal("salt must differ per hash")
	}
	for _, tamper := range []func(*passwordHash){
		func(p *passwordHash) { p.MemoryKiB = 1 << 30 },
		func(p *passwordHash) { p.Passes = 1000 },
		func(p *passwordHash) { p.Threads = 0 },
		func(p *passwordHash) { p.Algorithm = "argon2i" },
		func(p *passwordHash) { p.Key = p.Key[:10] },
		func(p *passwordHash) { p.Salt = "!" },
	} {
		bad := h
		tamper(&bad)
		if bad.matches("correct horse battery") {
			t.Fatalf("tampered hash accepted: %+v", bad)
		}
	}
}

func TestUsernameAndPasswordRules(t *testing.T) {
	for _, ok := range []string{"admin", "a.b-c_d", "juber2026"} {
		if !validUsername(ok) {
			t.Fatalf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "ab", "Admin", "1admin", "ad min", "admin/", strings.Repeat("a", 33), "admïn"} {
		if validUsername(bad) {
			t.Fatalf("%q accepted", bad)
		}
	}
	if passwordProblem("admin", "short") == "" || passwordProblem("admin", "elevenchars") == "" {
		t.Fatal("short password accepted")
	}
	if passwordProblem("averylongname", "AveryLongName") == "" {
		t.Fatal("password equal to username accepted")
	}
	if passwordProblem("admin", strings.Repeat("x", 257)) == "" || passwordProblem("admin", "valid\xffpassword!!") == "" {
		t.Fatal("oversized or invalid UTF-8 password accepted")
	}
	if p := passwordProblem("admin", "twelve chars"); p != "" {
		t.Fatal(p)
	}
}

func TestAdminFileRoundTripPrivateAndStrict(t *testing.T) {
	dir := t.TempDir()
	empty, err := loadAdmins(dir)
	if err != nil || len(empty.Admins) != 0 || empty.Version != 1 {
		t.Fatal("missing file must mean no admins")
	}
	file := adminFile{Version: 1, Admins: []adminRecord{testAdmin(t, "admin", "a long enough password")}}
	if err := saveAdmins(dir, file); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, adminsFile)
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0600 {
		t.Fatalf("admin file mode %v", st.Mode().Perm())
	}
	got, err := loadAdmins(dir)
	if err != nil || len(got.Admins) != 1 || got.Admins[0].Username != "admin" || !got.Admins[0].Password.matches("a long enough password") {
		t.Fatal("round trip failed")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatal("temporary file left behind")
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "a long enough password") {
		t.Fatal("password stored in clear")
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadAdmins(dir); err == nil {
			t.Fatal("group-readable admin file accepted")
		}
		_ = os.Chmod(path, 0600)
	}
	for _, mutate := range []func(string) string{
		func(s string) string { return strings.Replace(s, `"version": 1`, `"version": 2`, 1) },
		func(s string) string { return strings.Replace(s, `"username"`, `"username_x"`, 1) },
		func(s string) string { return s + "{}" },
		func(s string) string { return strings.Replace(s, `"last_step": 0`, `"last_step": -5`, 1) },
	} {
		if err := os.WriteFile(path, []byte(mutate(string(raw))), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadAdmins(dir); err == nil {
			t.Fatal("malformed admin file accepted")
		}
	}
	dup := adminFile{Version: 1, Admins: []adminRecord{testAdmin(t, "admin", "a long enough password"), testAdmin(t, "admin", "another long password")}}
	if err := saveAdmins(dir, dup); err == nil {
		t.Fatal("duplicate usernames saved")
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(t.TempDir(), "elsewhere")
		os.Remove(path)
		if err := os.Symlink(link, path); err != nil {
			t.Fatal(err)
		}
		if _, err := loadAdmins(dir); err == nil {
			t.Fatal("symlinked admin file accepted")
		}
	}
}
