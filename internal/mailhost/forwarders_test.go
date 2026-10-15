package mailhost

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestForwarderLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newSvc(t)
	d := "fwdt.example.test"

	if err := s.AddForwarder(ctx, "fwdt1", d, "sales", "team@elsewhere.example"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddForwarder(ctx, "fwdt1", d, "sales", "x@y.example"); err == nil {
		t.Fatal("duplicate forwarder must be rejected")
	}
	if err := s.AddForwarder(ctx, "fwdt1", d, "pipe", "|/usr/bin/x"); err == nil {
		t.Fatal("pipe destination must be rejected")
	}
	fwd, err := s.ListForwarders(ctx, "fwdt1", d)
	if err != nil || len(fwd) != 1 || fwd[0].Dest != "team@elsewhere.example" {
		t.Fatalf("list: %+v %v", fwd, err)
	}
	raw, _ := os.ReadFile(s.valiasesPath(d))
	if !strings.Contains(string(raw), "sales: team@elsewhere.example") {
		t.Fatalf("valiases file: %s", raw)
	}
	if err := s.SetDefaultAddress(ctx, "fwdt1", d, ":fail:"); err != nil {
		t.Fatal(err)
	}
	dest, _ := s.ListDefaultAddress(ctx, "fwdt1", d)
	if dest != ":fail:" {
		t.Fatalf("default: %q", dest)
	}
	fwd, _ = s.ListForwarders(ctx, "fwdt1", d)
	if len(fwd) != 1 {
		t.Fatalf("default row must not appear as forwarder: %+v", fwd)
	}
	if err := s.AddDomainForwarder(ctx, "fwdt1", d, "target.example.test"); err != nil {
		t.Fatal(err)
	}
	m, _ := s.ListDomainForwarders(ctx, "fwdt1")
	if m[d] != "target.example.test" {
		t.Fatalf("domain forwarders: %+v", m)
	}
	if err := s.AddDomainForwarder(ctx, "fwdt1", d, "other.example.test"); err == nil {
		t.Fatal("duplicate domain forwarder must be rejected")
	}
	if err := s.DeleteDomainForwarder(ctx, "fwdt1", d); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteForwarder(ctx, "fwdt1", d, "sales", "team@elsewhere.example"); err != nil {
		t.Fatal(err)
	}
	n, _ := s.CountForwarders(ctx, "fwdt1", d)
	if n != 0 {
		t.Fatalf("count after delete: %d", n)
	}
	raw, _ = os.ReadFile(s.valiasesPath(d))
	if strings.Contains(string(raw), "sales:") {
		t.Fatalf("stale forwarder row: %s", raw)
	}
	if err := s.DeleteForwarder(ctx, "fwdt1", d, "sales", "team@elsewhere.example"); err == nil {
		t.Fatal("deleting a missing forwarder must error")
	}
}

func TestPurgeAccount(t *testing.T) {
	ctx := context.Background()
	s := newSvc(t)
	if _, err := s.CreateMailbox(ctx, "purge1", "purge1.example.test", "a", "Pass!2026", 100); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateMailbox(ctx, "purge1", "purge1.example.test", "b", "Pass!2026", 100); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateMailbox(ctx, "other9", "purge1.example.test", "c", "Pass!2026", 100); err != nil {
		t.Fatal(err)
	}
	n, errs := s.PurgeAccount(ctx, "purge1", []string{"purge1.example.test"})
	if n != 2 || len(errs) != 0 {
		t.Fatalf("purge: %d %v", n, errs)
	}
	boxes, _ := s.ListMailboxes(ctx, "purge1")
	if len(boxes) != 0 {
		t.Fatalf("purge residue: %+v", boxes)
	}
	boxes, _ = s.ListMailboxes(ctx, "other9")
	if len(boxes) != 1 {
		t.Fatalf("purge must not touch other accounts: %+v", boxes)
	}
	if _, err := os.Stat(s.Homes + "/purge1"); !os.IsNotExist(err) {
		t.Fatal("account mail root must be removed")
	}
}
