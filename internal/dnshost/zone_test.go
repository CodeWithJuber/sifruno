package dnshost

import (
	"strings"
	"testing"
)

func TestDefaultZoneRender(t *testing.T) {
	z := NewDefaultZone("example.test", "ns1.host.example", "ns2.host.example", "10.0.0.5")
	out := z.Render("")
	for _, want := range []string{"SOA", "NS\tns1.host.example.", "www", "MX\t0 example.test.", "v=spf1", "$TTL 14400"} {
		if !strings.Contains(out, want) {
			t.Fatalf("render missing %q:\n%s", want, out)
		}
	}
}

func TestValidateDomain(t *testing.T) {
	for _, ok := range []string{"example.com", "sub.example.com", "a-b.example.org.", "*.example.com"} {
		if err := ValidateDomain(ok); err != nil {
			t.Fatalf("%q should pass: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "no dot", "a..b.com", "-bad.com", "bad_domain!.com", "x.com; rm -rf /"} {
		if err := ValidateDomain(bad); err == nil {
			t.Fatalf("%q should be rejected", bad)
		}
	}
}

func TestRecordValidation(t *testing.T) {
	z := NewDefaultZone("example.test", "ns1.h", "ns2.h", "10.0.0.5")
	if err := z.AddRecord(Record{Name: "api", Type: "A", Value: "10.0.0.9"}); err != nil {
		t.Fatal(err)
	}
	if err := z.AddRecord(Record{Name: "api", Type: "A", Value: "not-an-ip"}); err == nil {
		t.Fatal("bad IPv4 must be rejected")
	}
	if err := z.AddRecord(Record{Name: "x", Type: "TXT", Value: "any text ok"}); err != nil {
		t.Fatal(err)
	}
	if err := z.AddRecord(Record{Name: "x", Type: "SRV; rm", Value: "0 0 80 host."}); err == nil {
		t.Fatal("unknown type must be rejected")
	}
	if err := z.AddRecord(Record{Name: "@", Type: "MX", Value: "mail only"}); err == nil {
		t.Fatal("MX without priority must be rejected")
	}
	if err := z.AddRecord(Record{Name: "@", Type: "MX", Value: "10 mail.example.test."}); err != nil {
		t.Fatal(err)
	}
	// serial moved forward
	if z.Serial < serialToday() {
		t.Fatalf("serial: %d", z.Serial)
	}
}

func TestRemoveRecordAndSerial(t *testing.T) {
	z := NewDefaultZone("example.test", "ns1.h", "ns2.h", "10.0.0.5")
	before := z.Serial
	if n := z.RemoveRecord("www", "A", ""); n != 1 {
		t.Fatalf("removed %d", n)
	}
	if z.Serial <= before {
		t.Fatal("serial must bump on removal")
	}
	if n := z.RemoveRecord("nope", "A", ""); n != 0 {
		t.Fatal("no match = 0")
	}
}

func TestStoreRoundTrip(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	z := NewDefaultZone("store.test", "ns1.h", "ns2.h", "10.0.0.5")
	if err := s.Save(z); err != nil {
		t.Fatal(err)
	}
	loaded, err := s.Load("store.test")
	if err != nil || loaded.Domain != "store.test" || len(loaded.Records) != len(z.Records) {
		t.Fatalf("round trip: %+v %v", loaded, err)
	}
	list, _ := s.List()
	if len(list) != 1 {
		t.Fatalf("list: %+v", list)
	}
	if err := s.Save(NewDefaultZone("bad domain!", "a", "b", "1.2.3.4")); err == nil {
		t.Fatal("invalid domain must be refused by store")
	}
	if err := s.Delete("store.test"); err != nil {
		t.Fatal(err)
	}
	list, _ = s.List()
	if len(list) != 0 {
		t.Fatal("delete residue")
	}
}
