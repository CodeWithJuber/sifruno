package tlshost

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// selfSigned makes a real test certificate for the given DNS names.
func selfSigned(t *testing.T, cn string, sans []string, days int) (crtPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1234),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     sans,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func TestInstallInfoListDelete(t *testing.T) {
	ctx := context.Background()
	st := &Store{Root: filepath.Join(t.TempDir(), "ssl")}
	crt, key := selfSigned(t, "shop.example.com", []string{"shop.example.com", "www.shop.example.com"}, 90)

	info, err := st.Install(ctx, "shop.example.com", crt, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if info.SubjectCN != "shop.example.com" || info.DaysRemaining < 89 {
		t.Fatalf("info: %+v", info)
	}
	if !info.SelfSigned {
		t.Fatal("self-signed not detected")
	}
	// key must be 0600
	fi, err := os.Stat(filepath.Join(st.Root, "shop.example.com.key"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode: %o", fi.Mode().Perm())
	}

	// mismatched key rejected
	_, otherKey := selfSigned(t, "shop.example.com", []string{"shop.example.com"}, 90)
	if _, err := st.Install(ctx, "shop.example.com", crt, otherKey, nil); err == nil {
		t.Fatal("mismatched key accepted")
	}
	// wrong-domain cert rejected
	otherCrt, otherKey2 := selfSigned(t, "other.example.com", []string{"other.example.com"}, 90)
	if _, err := st.Install(ctx, "shop.example.com", otherCrt, otherKey2, nil); err == nil {
		t.Fatal("wrong-domain certificate accepted")
	}
	// wildcard covers subdomains
	wcrt, wkey := selfSigned(t, "*.example.com", []string{"*.example.com"}, 30)
	if _, err := st.Install(ctx, "api.example.com", wcrt, wkey, nil); err != nil {
		t.Fatalf("wildcard install: %v", err)
	}
	// path traversal rejected
	if _, err := st.Install(ctx, "../../etc/evil", crt, key, nil); err == nil {
		t.Fatal("traversal domain accepted")
	}
	// garbage PEM rejected
	if _, err := st.Install(ctx, "junk.example.com", []byte("not pem"), []byte("nope"), nil); err == nil {
		t.Fatal("garbage PEM accepted")
	}

	list, err := st.List(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("list: %v %v", list, err)
	}
	if err := st.Delete(ctx, "shop.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Info(ctx, "shop.example.com"); err == nil {
		t.Fatal("info after delete succeeded")
	}
	if _, err := os.Stat(filepath.Join(st.Root, "shop.example.com.key")); !os.IsNotExist(err) {
		t.Fatal("key file not removed")
	}
}

func TestExpiredCertStillStores(t *testing.T) {
	ctx := context.Background()
	st := &Store{Root: filepath.Join(t.TempDir(), "ssl")}
	crt, key := selfSigned(t, "old.example.com", []string{"old.example.com"}, -10)
	info, err := st.Install(ctx, "old.example.com", crt, key, nil)
	if err != nil {
		t.Fatal(err) // storing an expired cert is allowed; expiry is reported
	}
	if info.DaysRemaining >= 0 {
		t.Fatalf("expired cert reported %d days remaining", info.DaysRemaining)
	}
}
