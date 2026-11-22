package dnshost

import (
	"os"
	"path/filepath"
	"runtime"
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

// The reload setting used to run through sh -c. It is now an argv, and a
// value that needs a shell must fail loudly instead of running differently.
func TestParseReloadCommandRefusesShellSyntax(t *testing.T) {
	argv, err := ParseReloadCommand("  /usr/sbin/rndc   reload example.com ")
	if err != nil || len(argv) != 3 || argv[0] != "/usr/sbin/rndc" || argv[1] != "reload" || argv[2] != "example.com" {
		t.Fatalf("plain command: %v %v", argv, err)
	}
	if argv, err := ParseReloadCommand(" "); err != nil || argv != nil {
		t.Fatalf("empty setting must disable reload: %v %v", argv, err)
	}
	for _, value := range []string{
		"rndc reload",                     // relative program
		"/usr/sbin/../sbin/rndc reload",   // unclean path
		"kill -HUP $(cat /run/named.pid)", // substitution
		"/bin/kill -HUP `cat /run/named.pid`",
		"/usr/sbin/rndc reload; id",
		"/usr/sbin/rndc reload && id",
		"/usr/sbin/rndc reload | tee /tmp/x",
		"/usr/sbin/rndc reload > /tmp/x",
		"/usr/sbin/rndc 'reload'",
		"/usr/sbin/rndc reload\nid",
	} {
		if argv, err := ParseReloadCommand(value); err == nil {
			t.Fatalf("accepted %q as %v", value, argv)
		}
	}
}

func TestExecReloaderRunsArgvWithoutShell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh only as a plain program")
	}
	marker := filepath.Join(t.TempDir(), "ran")
	// The second argument would create the marker if a shell interpreted it.
	if err := (ExecReloader{Argv: []string{"/bin/echo", "ok", "; touch " + marker}}).Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("argument reached a shell")
	}
	if err := (ExecReloader{Argv: []string{"echo", "ok"}}).Reload(); err == nil {
		t.Fatal("relative program accepted")
	}
	if err := (ExecReloader{}).Reload(); err != nil {
		t.Fatalf("empty reloader must be a no-op: %v", err)
	}
}
