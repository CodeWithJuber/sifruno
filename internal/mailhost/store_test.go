package mailhost

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newSvc(t *testing.T) *LocalService {
	t.Helper()
	root := t.TempDir()
	return &LocalService{
		Homes: filepath.Join(root, "homes"),
		State: filepath.Join(root, "state"),
	}
}

func TestValidateLocalpart(t *testing.T) {
	for _, ok := range []string{"info", "sales.team", "a_b-c+d", "x"} {
		if err := ValidateLocalpart(ok); err != nil {
			t.Fatalf("%q should pass: %v", ok, err)
		}
	}
	for _, bad := range []string{"", ".lead", "a..b", "a b", "a/b", "a;rm", strings.Repeat("x", 65)} {
		if err := ValidateLocalpart(bad); err == nil {
			t.Fatalf("%q should be rejected", bad)
		}
	}
}

func TestMailboxLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newSvc(t)

	m, err := s.CreateMailbox(ctx, "mailt1", "mailt1.example.test", "info", "Secret!2026", 250)
	if err != nil {
		t.Fatal(err)
	}
	if m.Email != "info@mailt1.example.test" || m.QuotaMiB != 250 {
		t.Fatalf("mailbox: %+v", m)
	}
	// duplicate rejected
	if _, err := s.CreateMailbox(ctx, "mailt1", "mailt1.example.test", "info", "x", 0); err == nil {
		t.Fatal("duplicate must be rejected")
	}
	// maildir skeleton exists
	for _, sub := range []string{"cur", "new", "tmp"} {
		if st, err := os.Stat(filepath.Join(s.Homes, "mailt1", "mail", "mailt1.example.test", "info", sub)); err != nil || !st.IsDir() {
			t.Fatalf("maildir %s missing: %v", sub, err)
		}
	}
	// auth files written, hash never plaintext
	pw, err := os.ReadFile(filepath.Join(s.Homes, "mailt1", "etc", "mailt1.example.test", "passwd"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(pw), "info@mailt1.example.test:{SHA512-CRYPT}$6$") {
		t.Fatalf("passwd file: %s", pw)
	}
	if strings.Contains(string(pw), "Secret!2026") {
		t.Fatal("plaintext password leaked into passwd file")
	}
	// verify password
	ok, err := s.VerifyPassword(ctx, "mailt1", "info@mailt1.example.test", "Secret!2026")
	if err != nil || !ok {
		t.Fatalf("verify: %v %v", ok, err)
	}
	ok, _ = s.VerifyPassword(ctx, "mailt1", "info@mailt1.example.test", "wrong")
	if ok {
		t.Fatal("wrong password must not verify")
	}
	// password change then verify
	if err := s.SetPassword(ctx, "mailt1", "info@mailt1.example.test", "New!2026"); err != nil {
		t.Fatal(err)
	}
	ok, _ = s.VerifyPassword(ctx, "mailt1", "info@mailt1.example.test", "New!2026")
	if !ok {
		t.Fatal("new password must verify")
	}
	// quota round trip
	if err := s.SetQuota(ctx, "mailt1", "info@mailt1.example.test", 500); err != nil {
		t.Fatal(err)
	}
	q, _ := s.Quota(ctx, "mailt1", "info@mailt1.example.test")
	if q != 500 {
		t.Fatalf("quota: %d", q)
	}
	// ownership fence
	if err := s.DeleteMailbox(ctx, "attacker", "info@mailt1.example.test"); err == nil {
		t.Fatal("cross-account delete must be denied")
	}
	if _, err := s.Quota(ctx, "attacker", "info@mailt1.example.test"); err == nil {
		t.Fatal("cross-account quota read must be denied")
	}
	// count + list
	n, _ := s.CountMailboxes(ctx, "mailt1")
	if n != 1 {
		t.Fatalf("count: %d", n)
	}
	// delete + residue
	if err := s.DeleteMailbox(ctx, "mailt1", "info@mailt1.example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.Homes, "mailt1", "mail", "mailt1.example.test", "info")); !os.IsNotExist(err) {
		t.Fatal("maildir must be removed")
	}
	pw, _ = os.ReadFile(filepath.Join(s.Homes, "mailt1", "etc", "mailt1.example.test", "passwd"))
	if strings.Contains(string(pw), "info@") {
		t.Fatal("passwd file must not retain deleted mailbox")
	}
	boxes, _ := s.ListMailboxes(ctx, "")
	if len(boxes) != 0 {
		t.Fatalf("registry residue: %+v", boxes)
	}
}
