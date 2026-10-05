package hostweb

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"sifruno/internal/hostaccounts"
)

func testProfile() Profile {
	return Profile{
		Name:              RestrictedChrootV1,
		ManagedRoot:       "/var/lib/sifruno/hostweb",
		ManagedHomeRoot:   "/srv/sifruno-managed-homes",
		FrontChroot:       "/var/lib/sifruno/front-jail",
		ApacheModuleRoot:  "/usr/lib64/httpd/modules",
		BackendChrootRoot: "/var/lib/sifruno/backend-jails",
		RuntimeRoot:       "/run/sifruno/hostweb",
		ApacheBinary:      "/usr/sbin/httpd",
		FPMBinary:         "/usr/sbin/php-fpm",
		TLSRoot:           "/etc/sifruno/tls",
		CAFile:            "/etc/sifruno/tls/ca.pem",
		FrontendIP:        "0.0.0.0",
	}
}

func testAccount(id, username, domain string, uid int, state string) hostaccounts.Account {
	home := "/srv/sifruno-managed-homes/" + username
	return hostaccounts.Account{ID: id, Username: username, Domain: domain, Home: home, PublicHTML: home + "/public_html", UID: uid, GID: uid, State: state, Revision: 1}
}

func TestCompileDeterministicAndRestricted(t *testing.T) {
	p := testProfile()
	a := testAccount("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "alice", "alice.example.test", 20000, "active")
	b := testAccount("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "bravo", "bravo.example.test", 20001, "active")
	one, err := Compile(p, []hostaccounts.Account{b, a})
	if err != nil {
		t.Fatal(err)
	}
	two, err := Compile(p, []hostaccounts.Account{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if one.SHA256 != two.SHA256 || len(one.Files) != 5 || !bytes.Equal(one.Files[0].Data, two.Files[0].Data) {
		t.Fatalf("compile is not deterministic: %q %q %d", one.SHA256, two.SHA256, len(one.Files))
	}
	if err := one.Validate(); err != nil {
		t.Fatal(err)
	}
	var front string
	for _, f := range one.Files {
		if f.Path == "apache/front.conf" {
			front = string(f.Data)
		}
	}
	for _, want := range []string{"SSLProxyVerify require", "SSLProxyCheckPeerName on", "SSLProxyCheckPeerExpire on", "ProxyPreserveHost On", "User #48", "Group #48", "Require expr \"%{HTTP_HOST} == 'alice.example.test'\"", "LoadModule mpm_event_module \"/usr/lib64/httpd/modules/mod_mpm_event.so\"", "Require all denied", "127.73.78.32:18443", "127.73.78.33:18443"} {
		if !strings.Contains(front, want) {
			t.Errorf("front config missing %q", want)
		}
	}
	if strings.Contains(front, "LoadModule mime_module") || strings.Contains(front, "TypesConfig ") {
		t.Fatal("proxy-only front unexpectedly loads mod_mime or a MIME type database")
	}
	var backend, fpm string
	for _, f := range one.Files {
		if strings.HasSuffix(f.Path, a.ID+".conf") && strings.HasPrefix(f.Path, "apache/") {
			backend = string(f.Data)
		}
		if f.Path == "fpm/"+a.ID+".conf" {
			fpm = string(f.Data)
		}
		if f.Mode != 0600 || len(f.SHA256) != 64 {
			t.Errorf("managed file metadata not strict: %+v", f)
		}
	}
	for _, want := range []string{"ChrootDir \"/var/lib/sifruno/backend-jails/" + a.ID + "\"", "User #20000", "Group #20000", "LoadModule mpm_event_module \"/usr/lib64/httpd/modules/mod_mpm_event.so\"", "LoadModule proxy_module \"/usr/lib64/httpd/modules/mod_proxy.so\"", "TypesConfig /etc/mime.types", "ErrorLog \"/var/lib/sifruno/hostweb/logs/" + a.ID + "-apache.log\"", "ServerName default.invalid", "Options -Indexes -ExecCGI -Includes -FollowSymLinks", "FilesMatch", ".php$", "SetHandler \"proxy:unix:/run/sifruno/hostweb/" + a.ID + "/php-fpm.sock|fcgi://localhost/\"", "Require expr \"%{HTTP_HOST} == 'alice.example.test'\"", "SSLCertificateKeyFile \"/etc/sifruno/tls/" + a.ID + "/key.pem\""} {
		if !strings.Contains(backend, want) {
			t.Errorf("backend config missing %q", want)
		}
	}
	for _, config := range []string{front, backend} {
		module := strings.Index(config, "LoadModule unixd_module ")
		for _, directive := range []string{"User #", "Group #", "ChrootDir "} {
			position := strings.Index(config, directive)
			if position >= 0 && (module < 0 || position < module) {
				t.Fatalf("standalone Apache config uses %s before loading its module", directive)
			}
		}
	}
	for _, want := range []string{"user = 20000", "group = 20000", "slowlog = /var/lib/sifruno/hostweb/logs/" + a.ID + "-fpm-slow.log", "listen.mode = 0600", "chroot = /var/lib/sifruno/backend-jails/" + a.ID, "clear_env = yes", "security.limit_extensions = .php", "pm.max_children = 2", "request_terminate_timeout = 30s"} {
		if !strings.Contains(fpm, want) {
			t.Errorf("fpm config missing %q", want)
		}
	}
	pool := strings.Index(fpm, "["+a.Username+"]")
	slowlog := strings.Index(fpm, "slowlog = ")
	if pool < 0 || slowlog < pool {
		t.Fatalf("fpm slowlog must be pool-scoped: pool=%d slowlog=%d\n%s", pool, slowlog, fpm)
	}
	if strings.Contains(backend, "|fcgi://localhost"+a.PublicHTML) {
		t.Fatalf("backend handler must use the canonical fcgi root URI")
	}
	badGID := a
	badGID.GID++
	if _, err := Compile(p, []hostaccounts.Account{badGID}); !errors.Is(err, ErrInvalidAccount) {
		t.Fatalf("non-private account group accepted: %v", err)
	}
	badProfile := one
	badProfile.Profile = "other"
	if err := badProfile.Validate(); err == nil {
		t.Fatal("bundle accepted an unknown profile")
	}
	badInventory := one
	badInventory.Files = append(append([]File(nil), one.Files...), makeFile("unexpected.conf", []byte("x")))
	if err := badInventory.Validate(); err == nil {
		t.Fatal("bundle accepted an unknown file")
	}
	badSize := one
	badSize.Files = append([]File(nil), one.Files...)
	badSize.Files[0].Data = make([]byte, MaxBundleFileBytes+1)
	if err := badSize.Validate(); err == nil {
		t.Fatal("bundle accepted an oversized file")
	}
}

func TestCompileSuspendedAndInputGuards(t *testing.T) {
	p := testProfile()
	a := testAccount("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "alice", "alice.example.test", 20000, "suspended")
	bundle, err := Compile(p, []hostaccounts.Account{a})
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Files) != 1 || strings.Contains(string(bundle.Files[0].Data), "alice.example.test") == false || !strings.Contains(string(bundle.Files[0].Data), "Require all denied") {
		t.Fatalf("suspended account was not denied: %+v", bundle.Files)
	}
	bad := a
	bad.State = "active"
	bad.PublicHTML = bad.Home + "/../other/public_html"
	if _, err := Compile(p, []hostaccounts.Account{bad}); !errors.Is(err, ErrInvalidAccount) {
		t.Fatalf("unsafe public_html error = %v", err)
	}
	dup := testAccount("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "bravo", "alice.example.test", 20001, "active")
	if _, err := Compile(p, []hostaccounts.Account{a, dup}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate domain error = %v", err)
	}
	tooMany := make([]hostaccounts.Account, MaxManagedAccounts+1)
	for i := range tooMany {
		tooMany[i] = testAccount(strings.Repeat("a", 31)+string(rune('a'+i%2)), "acct"+strings.Repeat("x", i%5+2), "acct"+strings.Repeat("x", i%5+2)+".example.test", 20000+i, "active")
	}
	if _, err := Compile(p, tooMany); !errors.Is(err, ErrLimit) {
		t.Fatalf("limit error = %v", err)
	}
}

func TestProfileRequiresBackendTLSPortAndPOSIXPaths(t *testing.T) {
	p := testProfile()
	p.BackendPort = 18444
	if _, err := Compile(p, nil); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("backend port error = %v", err)
	}
	p = testProfile()
	p.ManagedRoot = `C:\sifruno\hostweb`
	if _, err := Compile(p, nil); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("non-POSIX path error = %v", err)
	}
	p = testProfile()
	p.FrontUID = 2000
	if _, err := Compile(p, nil); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("front/controller identity collision error = %v", err)
	}
}
