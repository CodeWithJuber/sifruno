package mailhost

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDovecotAggregate(t *testing.T) {
	ctx := context.Background()
	svc := newSvc(t)
	m, err := svc.CreateMailbox(ctx, "acct1", "example.com", "info", "pw-12345", 25)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(svc.Homes, "dovecot", "users"))
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(raw))
	// email:hash:2000:2000::<absolute home>::quota
	if !strings.HasPrefix(line, "info@example.com:{SHA512-CRYPT}$6$") &&
		!strings.Contains(line, "info@example.com:") {
		t.Fatalf("aggregate line: %s", line)
	}
	if !strings.Contains(line, ":"+filepath.Join(svc.Homes, "acct1", "mail", "example.com", "info")+":") {
		t.Fatalf("absolute home missing: %s", line)
	}
	if !strings.Contains(line, "userdb_quota_rule=*:bytes=25M") {
		t.Fatalf("quota missing: %s", line)
	}
	// suspended login gets the "!" lock prefix
	if err := svc.SetSuspend(ctx, "acct1", m.Email, SuspendLogin, true); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(filepath.Join(svc.Homes, "dovecot", "users"))
	if !strings.HasPrefix(strings.TrimSpace(string(raw)), "info@example.com:!") {
		t.Fatalf("suspended line not locked: %s", raw)
	}
	// unsuspend restores auth
	if err := svc.SetSuspend(ctx, "acct1", m.Email, SuspendLogin, false); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(filepath.Join(svc.Homes, "dovecot", "users"))
	if strings.HasPrefix(strings.TrimSpace(string(raw)), "info@example.com:!") {
		t.Fatal("lock prefix not cleared")
	}
	// password change propagates into the aggregate
	if err := svc.SetPassword(ctx, "acct1", m.Email, "new-pw-6789"); err != nil {
		t.Fatal(err)
	}
	raw2, _ := os.ReadFile(filepath.Join(svc.Homes, "dovecot", "users"))
	if string(raw2) == string(raw) {
		t.Fatal("aggregate not updated after password change")
	}
	// delete removes the row entirely
	if err := svc.DeleteMailbox(ctx, "acct1", m.Email); err != nil {
		t.Fatal(err)
	}
	raw3, _ := os.ReadFile(filepath.Join(svc.Homes, "dovecot", "users"))
	if strings.Contains(string(raw3), "info@example.com") {
		t.Fatal("deleted mailbox still in aggregate")
	}
}
