package hostaccounts

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// The helpers below build public key blobs from the RFC 4253 layout by hand,
// independently of the production parser, so a parser bug cannot hide behind
// a shared encoder.
func wireString(b []byte) []byte {
	out := make([]byte, 4, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	return append(out, b...)
}
func wireInt(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return wireString(b)
}
func keyLine(kind string, blob []byte, comment string) string {
	line := kind + " " + base64.StdEncoding.EncodeToString(blob)
	if comment != "" {
		line += " " + comment
	}
	return line
}
func ed25519Blob(t testing.TB) []byte {
	t.Helper()
	pub, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return append(wireString([]byte("ssh-ed25519")), wireString(pub)...)
}
func testEd25519Line(t testing.TB, comment string) string {
	t.Helper()
	return keyLine("ssh-ed25519", ed25519Blob(t), comment)
}
func ecdsaBlob(t testing.TB, curve elliptic.Curve, name string) []byte {
	t.Helper()
	key, e := ecdsa.GenerateKey(curve, rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	point, e := key.PublicKey.Bytes()
	if e != nil {
		t.Fatal(e)
	}
	blob := append(wireString([]byte("ecdsa-sha2-"+name)), wireString([]byte(name))...)
	return append(blob, wireString(point)...)
}
func rsaBlob(t testing.TB, bits int) []byte {
	t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, bits)
	if e != nil {
		t.Fatal(e)
	}
	blob := append(wireString([]byte("ssh-rsa")), wireInt(big.NewInt(int64(key.PublicKey.E)))...)
	return append(blob, wireInt(key.PublicKey.N)...)
}

func TestSSHKeyAdmission(t *testing.T) {
	ed := ed25519Blob(t)
	admitted := map[string]string{
		"ed25519":            keyLine("ssh-ed25519", ed, "dev@laptop"),
		"ed25519 no comment": keyLine("ssh-ed25519", ed25519Blob(t), ""),
		"ecdsa p256":         keyLine("ecdsa-sha2-nistp256", ecdsaBlob(t, elliptic.P256(), "nistp256"), "ci key"),
		"ecdsa p384":         keyLine("ecdsa-sha2-nistp384", ecdsaBlob(t, elliptic.P384(), "nistp384"), "p384"),
		"ecdsa p521":         keyLine("ecdsa-sha2-nistp521", ecdsaBlob(t, elliptic.P521(), "nistp521"), "p521"),
		"rsa 2048":           keyLine("ssh-rsa", rsaBlob(t, 2048), "rsa"),
	}
	for name, line := range admitted {
		t.Run("admit "+name, func(t *testing.T) {
			canonical, key, ok := normalizeSSHKey(line)
			if !ok || canonical != line || key.Type != strings.Fields(line)[0] || !strings.HasPrefix(key.Fingerprint, "SHA256:") || len(key.Fingerprint) != len("SHA256:")+43 {
				t.Fatalf("refused or changed: %q -> %q %+v %v", line, canonical, key, ok)
			}
		})
	}
	// Extra spaces between fields are folded; the canonical form has one.
	if canonical, _, ok := normalizeSSHKey("  ssh-ed25519   " + base64.StdEncoding.EncodeToString(ed) + "   dev   laptop "); !ok || canonical != keyLine("ssh-ed25519", ed, "dev laptop") {
		t.Fatalf("spacing not folded: %q %v", canonical, ok)
	}

	encoded := base64.StdEncoding.EncodeToString(ed)
	rsaPart := wireString([]byte("ssh-rsa"))
	refused := map[string]string{
		"empty":                "",
		"type only":            "ssh-ed25519",
		"options prefix":       `command="/bin/sh" ssh-ed25519 ` + encoded,
		"restrict prefix":      "restrict ssh-ed25519 " + encoded,
		"unknown type dss":     keyLine("ssh-dss", append(wireString([]byte("ssh-dss")), wireString([]byte("x"))...), ""),
		"security key type":    keyLine("sk-ssh-ed25519@openssh.com", append(wireString([]byte("sk-ssh-ed25519@openssh.com")), wireString(make([]byte, 32))...), ""),
		"certificate type":     keyLine("ssh-ed25519-cert-v01@openssh.com", ed, ""),
		"type and blob differ": keyLine("ssh-rsa", ed, ""),
		"blob names other":     keyLine("ssh-ed25519", append(rsaPart, wireString(make([]byte, 32))...), ""),
		"short ed25519":        keyLine("ssh-ed25519", append(wireString([]byte("ssh-ed25519")), wireString(make([]byte, 31))...), ""),
		"trailing blob bytes":  keyLine("ssh-ed25519", append(append([]byte{}, ed...), 0), ""),
		"truncated blob":       keyLine("ssh-ed25519", ed[:len(ed)-1], ""),
		"length overflow":      keyLine("ssh-ed25519", append(wireString([]byte("ssh-ed25519")), 0xff, 0xff, 0xff, 0xff, 1), ""),
		"not base64":           "ssh-ed25519 !!!!",
		"unpadded base64":      "ssh-ed25519 " + strings.TrimRight(base64.StdEncoding.EncodeToString(append(ed, 1, 2)), "="),
		"url-safe base64":      "ssh-ed25519 " + base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0xfb, 0xff}, 30)),
		"rsa 1024":             keyLine("ssh-rsa", rsaBlob(t, 1024), "weak"),
		"rsa exponent one":     keyLine("ssh-rsa", append(append(append([]byte{}, rsaPart...), wireInt(big.NewInt(1))...), wireInt(new(big.Int).Lsh(big.NewInt(1), 2047))...), ""),
		"rsa negative modulus": keyLine("ssh-rsa", append(append(append([]byte{}, rsaPart...), wireInt(big.NewInt(65537))...), wireString(bytes.Repeat([]byte{0xff}, 256))...), ""),
		"rsa padded modulus":   keyLine("ssh-rsa", append(append(append([]byte{}, rsaPart...), wireInt(big.NewInt(65537))...), wireString(append([]byte{0, 0x7f}, bytes.Repeat([]byte{0xff}, 255)...))...), ""),
		"ecdsa curve mismatch": keyLine("ecdsa-sha2-nistp256", ecdsaBlob(t, elliptic.P384(), "nistp384"), ""),
		"ecdsa compressed":     keyLine("ecdsa-sha2-nistp256", append(append(wireString([]byte("ecdsa-sha2-nistp256")), wireString([]byte("nistp256"))...), wireString(append([]byte{2}, make([]byte, 32)...))...), ""),
		"comment with quote":   "ssh-ed25519 " + encoded + ` a"b`,
		"comment with hash":    "ssh-ed25519 " + encoded + " a#b",
		"comment backslash":    "ssh-ed25519 " + encoded + ` a\b`,
		"comment too long":     "ssh-ed25519 " + encoded + " " + strings.Repeat("a", 81),
		"comment unicode":      "ssh-ed25519 " + encoded + " café",
		"newline":              "ssh-ed25519 " + encoded + "\nssh-ed25519 " + encoded,
		"carriage return":      "ssh-ed25519 " + encoded + "\r",
		"tab":                  "ssh-ed25519\t" + encoded,
		"nul":                  "ssh-ed25519 " + encoded + "\x00",
		"over line bound":      "ssh-ed25519 " + encoded + " " + strings.Repeat("a ", 600),
	}
	for name, line := range refused {
		t.Run("refuse "+name, func(t *testing.T) {
			if canonical, _, ok := normalizeSSHKey(line); ok {
				t.Fatalf("admitted %q as %q", line, canonical)
			}
		})
	}
}

func TestSSHKeySetAdmissionAndRendering(t *testing.T) {
	a, b := testEd25519Line(t, "one"), testEd25519Line(t, "two")
	canonical, keys, ok := normalizeSSHKeys([]string{a, b})
	if !ok || len(canonical) != 2 || len(keys) != 2 || keys[0].Comment != "one" || keys[1].Comment != "two" {
		t.Fatalf("set refused: %v %v", canonical, ok)
	}
	// The same key under another comment is still the same key.
	same := strings.Fields(a)[0] + " " + strings.Fields(a)[1] + " other"
	if _, _, ok := normalizeSSHKeys([]string{a, same}); ok {
		t.Fatal("duplicate key admitted")
	}
	many := make([]string, MaxSSHKeys+1)
	for i := range many {
		many[i] = testEd25519Line(t, "")
	}
	if _, _, ok := normalizeSSHKeys(many); ok {
		t.Fatal("oversized set admitted")
	}
	if _, _, ok := normalizeSSHKeys(many[:MaxSSHKeys]); !ok {
		t.Fatal("full-size set refused")
	}
	if canonical, keys, ok := normalizeSSHKeys(nil); !ok || len(canonical) != 0 || len(keys) != 0 {
		t.Fatal("empty set refused")
	}
	want := "# Managed by Sifruno. This file is rewritten from the panel's key list.\n" +
		`restrict,command="internal-sftp" ` + a + "\n" +
		`restrict,command="internal-sftp" ` + b + "\n"
	if got := string(renderAuthorizedKeys(canonical)); got != want {
		t.Fatalf("authorized_keys content:\n%s\nwant:\n%s", got, want)
	}
	// Every rendered key line starts with the fixed options; none can be bare.
	for _, line := range strings.Split(strings.TrimSpace(string(renderAuthorizedKeys(canonical))), "\n")[1:] {
		if !strings.HasPrefix(line, `restrict,command="internal-sftp" ssh-`) {
			t.Fatalf("unrestricted key line: %q", line)
		}
	}
	if sshKeysDigest(canonical) == sshKeysDigest(canonical[:1]) || sshKeysDigest(nil) != sshKeysDigest([]string{}) || !sshDigestPattern.MatchString(sshKeysDigest(canonical)) {
		t.Fatal("digest does not identify the set")
	}
	if !canonicalSSHKeys(joinSSHKeys(canonical)) || !canonicalSSHKeys("") || canonicalSSHKeys(a+"\n") || canonicalSSHKeys("  "+a) {
		t.Fatal("stored-form check is wrong")
	}
}

// Interoperability with the real tool: keys written by ssh-keygen must be
// admitted unchanged, and our fingerprint must be the one ssh-keygen prints.
func TestSSHKeysMatchOpenSSH(t *testing.T) {
	keygen, e := exec.LookPath("ssh-keygen")
	if e != nil {
		t.Skip("ssh-keygen not installed")
	}
	dir := t.TempDir()
	for name, args := range map[string][]string{
		"ed25519":  {"-t", "ed25519"},
		"ecdsa256": {"-t", "ecdsa", "-b", "256"},
		"ecdsa384": {"-t", "ecdsa", "-b", "384"},
		"ecdsa521": {"-t", "ecdsa", "-b", "521"},
		"rsa3072":  {"-t", "rsa", "-b", "3072"},
	} {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(dir, name)
			if out, e := exec.Command(keygen, append(args, "-q", "-N", "", "-C", "user@host", "-f", file)...).CombinedOutput(); e != nil {
				t.Skipf("ssh-keygen cannot make this key here: %v %s", e, out)
			}
			raw, e := os.ReadFile(file + ".pub")
			if e != nil {
				t.Fatal(e)
			}
			line := strings.TrimSpace(string(raw))
			canonical, key, ok := normalizeSSHKey(line)
			if !ok || canonical != line || key.Comment != "user@host" {
				t.Fatalf("OpenSSH key refused or changed: %q %v", canonical, ok)
			}
			out, e := exec.Command(keygen, "-l", "-E", "sha256", "-f", file+".pub").Output()
			if e != nil {
				t.Fatal(e)
			}
			if fields := strings.Fields(string(out)); len(fields) < 2 || fields[1] != key.Fingerprint {
				t.Fatalf("fingerprint %q, ssh-keygen says %q", key.Fingerprint, out)
			}
		})
	}
}

func FuzzNormalizeSSHKey(f *testing.F) {
	f.Add("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA== x")
	f.Add(`restrict,command="x" ssh-rsa AAAA`)
	f.Add("")
	f.Fuzz(func(t *testing.T, line string) {
		canonical, key, ok := normalizeSSHKey(line)
		if !ok {
			return
		}
		// Whatever is admitted must be stable, single-line and option-free.
		again, key2, ok2 := normalizeSSHKey(canonical)
		if !ok2 || again != canonical || key2 != key || strings.ContainsAny(canonical, "\r\n\"'\\#") || !strings.HasPrefix(canonical, key.Type+" ") {
			t.Fatalf("unstable admission %q -> %q", line, canonical)
		}
	})
}

func keysFixture(t *testing.T) (*store, *fakeNative, BrokerOptions, Account) {
	t.Helper()
	s, f, opts := setupStore(t)
	return s, f, opts, createFixture(t, s)
}

func TestSSHKeysOperationLifecycle(t *testing.T) {
	s, f, _, a := keysFixture(t)
	ctx := context.Background()
	one, two := testEd25519Line(t, "laptop"), testEd25519Line(t, "ci")

	empty, e := s.sshKeys(ctx, a.ID)
	if e != nil || len(empty.Keys) != 0 || empty.Account.Revision != 1 {
		t.Fatalf("fresh account keys: %+v %v", empty, e)
	}
	set, e := s.setSSHKeys(ctx, a.ID, SSHKeysInput{Keys: []string{one, two}, ExpectedRevision: 1, Reason: "Add deploy keys"}, "test operator")
	if e != nil || set.Account.Revision != 2 || len(set.Keys) != 2 || set.Keys[0].Comment != "laptop" || set.Account.State != "active" {
		t.Fatalf("set keys: %+v %v", set, e)
	}
	if got := f.keys[a.Username]; len(got) != 2 || got[0] != one || got[1] != two || f.keyWrites != 1 {
		t.Fatalf("native key set: %v writes=%d", got, f.keyWrites)
	}
	// Same set again: nothing is written and the revision does not move.
	again, e := s.setSSHKeys(ctx, a.ID, SSHKeysInput{Keys: []string{one, two}, ExpectedRevision: 2, Reason: "Repeat"}, "test operator")
	if e != nil || again.Account.Revision != 2 || f.keyWrites != 1 {
		t.Fatalf("idempotent set: %+v %v writes=%d", again, e, f.keyWrites)
	}
	// The same set while the installed file has drifted is not a no-op: the
	// broker rewrites it through the journal and the revision moves on.
	f.failure = "keys-drift"
	repaired, e := s.setSSHKeys(ctx, a.ID, SSHKeysInput{Keys: []string{one, two}, ExpectedRevision: 2, Reason: "Repair"}, "test operator")
	f.failure = ""
	if e != nil || repaired.Account.Revision != 3 || f.keyWrites != 2 {
		t.Fatalf("drifted file was not rewritten: %+v %v writes=%d", repaired, e, f.keyWrites)
	}
	for name, c := range map[string]struct {
		id   string
		in   SSHKeysInput
		want error
	}{
		"stale revision": {a.ID, SSHKeysInput{Keys: []string{one}, ExpectedRevision: 2, Reason: "Stale"}, ErrConflict},
		"zero revision":  {a.ID, SSHKeysInput{Keys: []string{one}, Reason: "No revision"}, ErrInvalid},
		"no reason":      {a.ID, SSHKeysInput{Keys: []string{one}, ExpectedRevision: 3}, ErrInvalid},
		"bad key":        {a.ID, SSHKeysInput{Keys: []string{`command="id" ` + one}, ExpectedRevision: 3, Reason: "Options"}, ErrInvalid},
		"duplicate key":  {a.ID, SSHKeysInput{Keys: []string{one, one}, ExpectedRevision: 3, Reason: "Twice"}, ErrInvalid},
		"bad id":         {"../etc", SSHKeysInput{Keys: []string{one}, ExpectedRevision: 3, Reason: "Path"}, ErrInvalid},
		"unknown id":     {strings.Repeat("0", 32), SSHKeysInput{Keys: []string{one}, ExpectedRevision: 3, Reason: "Missing"}, ErrNotFound},
	} {
		if _, e := s.setSSHKeys(ctx, c.id, c.in, "test operator"); e != c.want {
			t.Fatalf("%s: %v, want %v", name, e, c.want)
		}
	}
	if f.keyWrites != 2 {
		t.Fatalf("a refused request reached the native system: %d writes", f.keyWrites)
	}
	// Removing all keys is an ordinary replacement with the empty set.
	cleared, e := s.setSSHKeys(ctx, a.ID, SSHKeysInput{Keys: nil, ExpectedRevision: 3, Reason: "Remove access"}, "test operator")
	if e != nil || cleared.Account.Revision != 4 || len(cleared.Keys) != 0 || len(f.keys[a.Username]) != 0 {
		t.Fatalf("clear keys: %+v %v", cleared, e)
	}
	// The journal must accept its own history, and no key text may be in it.
	items, e := s.records()
	if e != nil || len(items) != 1 || items[0].HistorySequence != 8 || items[0].SSHKeys != "" {
		t.Fatalf("journal after key operations: %+v %v", items, e)
	}
	if e := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(historyBucket).ForEach(func(_, value []byte) error {
			if bytes.Contains(value, []byte(strings.Fields(one)[1])) {
				t.Fatal("key material copied into the audit journal")
			}
			return nil
		})
	}); e != nil {
		t.Fatal(e)
	}
}

func TestSSHKeysInterruptedWriteIsFinishedOnRestart(t *testing.T) {
	for _, failure := range []string{"keys-before", "keys-after"} {
		t.Run(failure, func(t *testing.T) {
			s, f, opts, a := keysFixture(t)
			ctx := context.Background()
			key := testEd25519Line(t, "laptop")
			f.failure = failure
			if _, e := s.setSSHKeys(ctx, a.ID, SSHKeysInput{Keys: []string{key}, ExpectedRevision: 1, Reason: "Add key"}, "test operator"); e != ErrRecovery {
				t.Fatalf("failed native write: %v", e)
			}
			items, e := s.list(ctx)
			if e != nil || len(items) != 1 || items[0].State != "recovery_required" || items[0].Revision != 1 {
				t.Fatalf("interrupted account must show recovery: %+v %v", items, e)
			}
			// While one account is unresolved the broker takes no new mutation.
			if _, e := s.create(ctx, CreateInput{Username: "otheracct", Domain: "other.test", Reason: "Blocked"}, "test operator"); e != ErrRecovery {
				t.Fatalf("mutation during recovery: %v", e)
			}
			if e := s.close(); e != nil {
				t.Fatal(e)
			}
			f.failure = ""
			reopened, e := openStore(ctx, opts, f)
			if e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { reopened.close() })
			result, e := reopened.sshKeys(ctx, a.ID)
			if e != nil || result.Account.State != "active" || result.Account.Revision != 2 || len(result.Keys) != 1 || result.Keys[0].Comment != "laptop" {
				t.Fatalf("restart did not finish the key write: %+v %v", result, e)
			}
			if got := f.keys[a.Username]; len(got) != 1 || got[0] != key {
				t.Fatalf("native key set after restart: %v", got)
			}
		})
	}
}

func TestSSHKeysStoredFormIsChecked(t *testing.T) {
	s, _, _, a := keysFixture(t)
	// A record whose stored key set would not pass admission is corrupt state.
	if e := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(accountBucket)
		var r record
		if json.Unmarshal(b.Get([]byte(a.ID)), &r) != nil {
			t.Fatal("fixture record")
		}
		r.SSHKeys = `command="/bin/sh" ` + testEd25519Line(t, "")
		raw, _ := json.Marshal(r)
		return b.Put([]byte(a.ID), raw)
	}); e != nil {
		t.Fatal(e)
	}
	if _, e := s.list(context.Background()); e != ErrRecovery {
		t.Fatalf("option-bearing stored key accepted: %v", e)
	}
}

func TestSSHKeysHTTPContract(t *testing.T) {
	s, f, _, a := keysFixture(t)
	h := handler(s)
	key := testEd25519Line(t, "laptop")
	body, _ := json.Marshal(map[string]any{"actor": "test operator", "input": map[string]any{"keys": []string{key}, "expected_revision": 1, "reason": "Add key"}})
	post := func(payload string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "http://unix/v1/accounts/"+a.ID+"/ssh-keys", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for name, payload := range map[string]string{
		"unknown input key": `{"actor":"a","input":{"keys":[],"expected_revision":1,"reason":"r","shell":"/bin/bash"}}`,
		"null keys":         `{"actor":"a","input":{"keys":null,"expected_revision":1,"reason":"r"}}`,
		"keys not a list":   `{"actor":"a","input":{"keys":"` + key + `","expected_revision":1,"reason":"r"}}`,
		"duplicate key":     `{"actor":"a","actor":"b","input":{"keys":[],"expected_revision":1,"reason":"r"}}`,
		"trailing data":     string(body) + "{}",
	} {
		if rec := post(payload); rec.Code != 400 {
			t.Fatalf("%s: status %d %s", name, rec.Code, rec.Body)
		}
	}
	if f.keyWrites != 0 {
		t.Fatal("a refused request reached the native system")
	}
	rec := post(string(body))
	var result SSHKeysResult
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &result) != nil || result.Account.Revision != 2 || len(result.Keys) != 1 {
		t.Fatalf("set over HTTP: %d %s", rec.Code, rec.Body)
	}
	get := httptest.NewRequest("GET", "http://unix/v1/accounts/"+a.ID+"/ssh-keys", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, get)
	result = SSHKeysResult{}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &result) != nil || len(result.Keys) != 1 || result.Keys[0].Fingerprint == "" {
		t.Fatalf("get over HTTP: %d %s", rec.Code, rec.Body)
	}
	// The response describes keys; it is not a second copy of the key file.
	if strings.Contains(rec.Body.String(), "internal-sftp") {
		t.Fatal("key options leaked into the API")
	}
}
