package mailhost

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func eximRead(t *testing.T, svc *LocalService, parts ...string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{svc.eximRoot()}, parts...)...))
	if err != nil {
		t.Fatalf("read %v: %v", parts, err)
	}
	return string(raw)
}

func TestEximExport(t *testing.T) {
	ctx := context.Background()
	svc := newSvc(t)
	if _, err := svc.CreateMailbox(ctx, "acct1", "eximt.example.test", "info", "pw-12345", 50); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateMailbox(ctx, "acct1", "eximt.example.test", "sales", "pw-12345", 0); err != nil {
		t.Fatal(err)
	}
	if err := svc.AddForwarder(ctx, "acct1", "eximt.example.test", "contact", "info@eximt.example.test"); err != nil {
		t.Fatal(err)
	}

	ld := eximRead(t, svc, "localdomains")
	if strings.TrimSpace(ld) != "eximt.example.test" {
		t.Fatalf("localdomains: %q", ld)
	}
	mb := eximRead(t, svc, "mailboxes")
	if !strings.Contains(mb, "info@eximt.example.test: "+filepath.Join(svc.Homes, "acct1", "mail", "eximt.example.test", "info")) {
		t.Fatalf("mailboxes missing info row: %q", mb)
	}
	if !strings.Contains(mb, "sales@eximt.example.test: ") {
		t.Fatalf("mailboxes missing sales row: %q", mb)
	}
	va := eximRead(t, svc, "aliases")
	if !strings.Contains(va, "contact@eximt.example.test: info@eximt.example.test") {
		t.Fatalf("aliases export: %q", va)
	}

	// suspension rows appear/disappear
	if err := svc.SetSuspend(ctx, "acct1", "info@eximt.example.test", SuspendIncoming, true); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetSuspend(ctx, "acct1", "info@eximt.example.test", SuspendOutgoing, true); err != nil {
		t.Fatal(err)
	}
	if got := eximRead(t, svc, "suspended_incoming"); !strings.Contains(got, "info@eximt.example.test: 1") {
		t.Fatalf("suspended_incoming: %q", got)
	}
	if got := eximRead(t, svc, "suspended_outgoing"); !strings.Contains(got, "info@eximt.example.test: 1") {
		t.Fatalf("suspended_outgoing: %q", got)
	}
	if err := svc.SetSuspend(ctx, "acct1", "info@eximt.example.test", SuspendIncoming, false); err != nil {
		t.Fatal(err)
	}
	if got := eximRead(t, svc, "suspended_incoming"); strings.Contains(got, "info@") {
		t.Fatalf("suspended_incoming should be empty: %q", got)
	}

	// mailbox deletion drops the row
	if err := svc.DeleteMailbox(ctx, "acct1", "sales@eximt.example.test"); err != nil {
		t.Fatal(err)
	}
	if got := eximRead(t, svc, "mailboxes"); strings.Contains(got, "sales@") {
		t.Fatalf("mailboxes should not contain sales: %q", got)
	}

	// account purge clears domain rows and the valiases export
	if _, errs := svc.PurgeAccount(ctx, "acct1", []string{"eximt.example.test"}); len(errs) > 0 {
		t.Fatalf("purge errors: %v", errs)
	}
	if got := eximRead(t, svc, "localdomains"); strings.Contains(got, "eximt") {
		t.Fatalf("localdomains after purge: %q", got)
	}
	if got := eximRead(t, svc, "mailboxes"); strings.Contains(got, "@") {
		t.Fatalf("mailboxes after purge: %q", got)
	}
	if got := eximRead(t, svc, "aliases"); strings.Contains(got, "@") {
		t.Fatalf("aliases after purge: %q", got)
	}
}
