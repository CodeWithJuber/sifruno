package tlshost

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateKeyAndCSR(t *testing.T) {
	st := &Store{Root: filepath.Join(t.TempDir(), "ssl")}
	ki, err := st.GenerateKey("acct1")
	if err != nil {
		t.Fatal(err)
	}
	if ki.Type != "ECDSA P-256" || len(ki.ID) != 16 {
		t.Fatalf("key info: %+v", ki)
	}
	fi, _ := os.Stat(filepath.Join(st.keyDir("acct1"), ki.ID+".pem"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode: %o", fi.Mode().Perm())
	}

	ci, err := st.GenerateCSR("acct1", ki.ID, []string{"example.com", "www.example.com"}, "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(ci.Domains) != 2 || ci.KeyID != ki.ID {
		t.Fatalf("csr info: %+v", ci)
	}
	// parse the stored CSR and verify contents + signature
	raw, err := st.CSRPEM("acct1", ci.ID)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal("CSR signature invalid")
	}
	if csr.Subject.CommonName != "example.com" || len(csr.DNSNames) != 2 {
		t.Fatalf("csr parsed: %+v", csr)
	}

	keys, _ := st.ListKeys("acct1")
	if len(keys) != 1 {
		t.Fatalf("list keys: %v", keys)
	}
	csrs, _ := st.ListCSRs("acct1")
	if len(csrs) != 1 || csrs[0].Domains[0] != "example.com" {
		t.Fatalf("list csrs: %v", csrs)
	}

	// negatives
	if _, err := st.GenerateKey("../evil"); err == nil {
		t.Fatal("traversal account key accepted")
	}
	if _, err := st.GenerateCSR("acct1", ki.ID, []string{}, ""); err == nil {
		t.Fatal("empty domains accepted")
	}
	if _, err := st.GenerateCSR("acct1", ki.ID, []string{"x.com"}, "not-an-email"); err == nil {
		t.Fatal("bad email accepted")
	}
	if _, err := st.GenerateCSR("acct1", "0000000000000000", []string{"x.com"}, ""); err == nil {
		t.Fatal("missing key accepted")
	}
	if err := st.DeleteKey("acct1", "../../etc/passwd"); err == nil {
		t.Fatal("traversal key id accepted")
	}
	if err := st.DeleteCSR("acct1", ci.ID); err != nil {
		t.Fatal(err)
	}
	if csrs, _ := st.ListCSRs("acct1"); len(csrs) != 0 {
		t.Fatal("csr list after delete")
	}
	if err := st.DeleteKey("acct1", ki.ID); err != nil {
		t.Fatal(err)
	}
	if keys, _ := st.ListKeys("acct1"); len(keys) != 0 {
		t.Fatal("key list after delete")
	}
}
