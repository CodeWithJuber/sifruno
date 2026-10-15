package mailhost

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSuspendFlags(t *testing.T) {
	ctx := context.Background()
	svc := newSvc(t)
	m, err := svc.CreateMailbox(ctx, "acct1", "example.com", "info", "pw-12345", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetSuspend(ctx, "acct1", m.Email, SuspendIncoming, true); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetSuspend(ctx, "acct1", m.Email, SuspendLogin, true); err != nil {
		t.Fatal(err)
	}
	in, out, login, err := svc.Suspensions(ctx, "acct1", m.Email)
	if err != nil {
		t.Fatal(err)
	}
	if !in || out || !login {
		t.Fatalf("flags: in=%v out=%v login=%v", in, out, login)
	}
	// on-disk flag files exist
	for _, f := range []string{"info.suspended_incoming", "info.suspended_login"} {
		if _, err := os.Stat(filepath.Join(svc.Homes, "acct1", "etc", "example.com", f)); err != nil {
			t.Fatalf("flag file %s: %v", f, err)
		}
	}
	// registry persistence across reload
	svc.loaded = false
	in, _, _, _ = svc.Suspensions(ctx, "acct1", m.Email)
	if !in {
		t.Fatal("suspend flag not persisted")
	}
	// unsuspend clears file + registry
	if err := svc.SetSuspend(ctx, "acct1", m.Email, SuspendIncoming, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(svc.Homes, "acct1", "etc", "example.com", "info.suspended_incoming")); !os.IsNotExist(err) {
		t.Fatal("flag file not removed")
	}
	// cross-account fence
	if err := svc.SetSuspend(ctx, "other", m.Email, SuspendLogin, true); err == nil {
		t.Fatal("cross-account suspend accepted")
	}
	if err := svc.SetSuspend(ctx, "acct1", m.Email, "bogus", true); err == nil {
		t.Fatal("bogus flag accepted")
	}
}

func TestAutoResponders(t *testing.T) {
	ctx := context.Background()
	svc := newSvc(t)
	m, err := svc.CreateMailbox(ctx, "acct1", "example.com", "info", "pw-12345", 0)
	if err != nil {
		t.Fatal(err)
	}
	ar := AutoResponder{
		Email: m.Email, From: "Support", Subject: "Away",
		Body: "I am away.", Interval: 3600,
		Start: time.Now().Add(-time.Hour).Unix(), Stop: 0,
	}
	if err := svc.AddAutoResponder(ctx, "acct1", ar); err != nil {
		t.Fatal(err)
	}
	got, err := svc.GetAutoResponder(ctx, "acct1", m.Email)
	if err != nil || got.Subject != "Away" {
		t.Fatalf("get: %v %+v", err, got)
	}
	if n, _ := svc.CountAutoResponders(ctx, "acct1"); n != 1 {
		t.Fatalf("count: %d", n)
	}
	list, _ := svc.ListAutoResponders(ctx, "acct1")
	if len(list) != 1 || !list[0].IsActiveNow(time.Now()) {
		t.Fatalf("list/active: %+v", list)
	}
	// non-existent mailbox rejected
	if err := svc.AddAutoResponder(ctx, "acct1", AutoResponder{Email: "ghost@example.com", Subject: "x"}); err == nil {
		t.Fatal("autoresponder for missing mailbox accepted")
	}
	// header injection rejected
	if err := svc.AddAutoResponder(ctx, "acct1", AutoResponder{Email: m.Email, Subject: "a\r\nBcc: evil@x"}); err == nil {
		t.Fatal("CRLF subject accepted")
	}
	// stop before start rejected
	if err := svc.AddAutoResponder(ctx, "acct1", AutoResponder{Email: m.Email, Subject: "x", Start: 200, Stop: 100}); err == nil {
		t.Fatal("inverted window accepted")
	}
	if err := svc.DeleteAutoResponder(ctx, "acct1", m.Email); err != nil {
		t.Fatal(err)
	}
	if n, _ := svc.CountAutoResponders(ctx, "acct1"); n != 0 {
		t.Fatal("count after delete")
	}
	if _, err := os.Stat(svc.arPath("acct1")); !os.IsNotExist(err) {
		t.Fatal("empty autorespond file not removed")
	}
}
