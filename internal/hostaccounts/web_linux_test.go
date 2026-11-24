//go:build linux

package hostaccounts

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"sifruno/internal/olsweb"
)

func TestWebACLLayout(t *testing.T) {
	b := webACL(992, 5)
	if len(b) != 4+5*8 || binary.LittleEndian.Uint32(b) != aclVersion {
		t.Fatalf("length %d", len(b))
	}
	type entry struct {
		tag, perm uint16
		id        uint32
	}
	want := []entry{{aclUserObj, 7, aclUndefined}, {aclUser, 5, 992}, {aclGroupObj, 5, aclUndefined}, {aclMask, 5, aclUndefined}, {aclOther, 0, aclUndefined}}
	for i, w := range want {
		off := 4 + i*8
		got := entry{binary.LittleEndian.Uint16(b[off:]), binary.LittleEndian.Uint16(b[off+2:]), binary.LittleEndian.Uint32(b[off+4:])}
		if got != w {
			t.Fatalf("entry %d: %+v want %+v", i, got, w)
		}
	}
	if webACL(992, 1)[4+8+2] != 1 {
		t.Fatal("home entry must be traverse only")
	}
}

func TestIncludeAndQuotaParsing(t *testing.T) {
	if !includesSifruno([]byte("serverName x\n  include   /usr/local/lsws/conf/sifruno.conf  \n")) {
		t.Fatal("include line not found")
	}
	for _, bad := range []string{"#include /usr/local/lsws/conf/sifruno.conf\n", "include /usr/local/lsws/conf/sifruno.conf.bak\n", ""} {
		if includesSifruno([]byte(bad)) {
			t.Fatalf("%q accepted", bad)
		}
	}
	on := "User quota state on /home (/dev/vdb)\n  Accounting: ON\n  Enforcement: ON\n  Inode: #131 (2 blocks, 2 extents)\n"
	if !userQuotaOn([]byte(on)) {
		t.Fatal("enforced quota not recognised")
	}
	if userQuotaOn([]byte("User quota state on /home (/dev/vdb)\n  Accounting: ON\n  Enforcement: OFF\n")) || userQuotaOn(nil) {
		t.Fatal("unenforced quota accepted")
	}
}

func TestOLSTestScopesToChangedVhosts(t *testing.T) {
	stock := "2026-11-22 23:22:09.686429 [WARN] [14944] [config:server:vhosts:vhost:Example] Uid of /usr/local/lsws/Example/html/ is 0, smaller than minimum requirement 11, use server uid!\n"
	mine, other := olsweb.NamePrefix+"uaaaa", olsweb.NamePrefix+"ubbbb"
	tenant := func(level, vhost string) string {
		return "2026-11-23 16:00:00.000001 [" + level + "] [1] [config:server:vhosts:vhost:" + vhost + "] path /home/x/public_html/ does not exist\n"
	}
	docrootGone := func(vhost string) string {
		return "2026-11-23 00:00:00.000000 [WARN] [1] [config:server:vhosts:vhost:" + vhost + "] configuration failed!\n" +
			"2026-11-23 00:00:00.000000 [WARN] [1] Path for document root is not accessible: /home/brk55596/public_html/\n"
	}
	changed := map[string]bool{mine: true, other: false}
	cases := []struct {
		name string
		out  string
		code int
		ok   bool
	}{
		{"clean", "", 0, true},
		{"stock warning", stock, 1, true},
		{"another tenant's warning", stock + tenant("WARN", other), 1, true},
		{"another tenant's error", tenant("ERROR", other), 2, true},
		{"this change's warning", tenant("WARN", mine), 1, false},
		{"this change's error", tenant("ERROR", mine), 2, false},
		{"server error", "2026-11-23 16:00:00.000001 [ERROR] [1] [config:server:listeners:sifruno] address in use\n", 2, false},
		{"error without context", "2026-11-23 16:00:00.000001 [ERROR] [1] bad config\n", 2, false},
		{"exit 2 with no error line", stock, 2, false},
		{"unknown exit", "", 3, false},
		// The messages OpenLiteSpeed 1.9.4 printed on the dev VM after a
		// tenant moved public_html away (time and process ID are
		// placeholders): two warnings, one without a context.
		{"another tenant's missing docroot", stock + docrootGone(other), 1, true},
		{"this change's missing docroot", stock + docrootGone(mine), 1, false},
	}
	for _, c := range cases {
		if got := olsTestPasses([]byte(c.out), c.code, changed); got != c.ok {
			t.Errorf("%s: passes %v, want %v", c.name, got, c.ok)
		}
	}
	for in, want := range map[string]string{
		"[config:server:vhosts:vhost:Example]":          "Example",
		"[config:server:vhosts:vhost:sifruno-ua:ctx:/]": "sifruno-ua",
		"[config:server:listeners:Default]":             "",
		"config:server:vhosts:vhost:Example":            "",
	} {
		if got := olsContextVhost(in); got != want {
			t.Errorf("olsContextVhost(%q) = %q, want %q", in, got, want)
		}
	}
}

// A render that rewrites every vhost (once after an upgrade changes the
// rendered form) still does not let a tenant who broke its own folder
// reject another account's change: the store names that vhost, and the test
// does not judge it. The change's own vhost is always judged.
func TestJudgedVhostsLeaveOutBrokenTenants(t *testing.T) {
	mine, other, broken := olsweb.NamePrefix+"uaaaa", olsweb.NamePrefix+"ubbbb", olsweb.NamePrefix+"ucccc"
	everything := map[string]bool{mine: true, other: true, broken: true}
	judged := judgedVhosts(everything, "", map[string]bool{broken: true})
	if len(judged) != 2 || !judged[mine] || !judged[other] || judged[broken] {
		t.Fatalf("judged %v", judged)
	}
	if got := judgedVhosts(map[string]bool{mine: false, other: true}, mine, nil); len(got) != 2 || !got[mine] || !got[other] {
		t.Fatalf("a touched certificate is judged, an unwritten vhost is not: %v", got)
	}
	// The messages OpenLiteSpeed 1.9.4 printed on the dev VM after a tenant
	// moved public_html away (time and process ID are placeholders).
	out := "2026-11-23 00:00:00.000000 [WARN] [1] [config:server:vhosts:vhost:" + broken + "] configuration failed!\n" +
		"2026-11-23 00:00:00.000000 [WARN] [1] Path for document root is not accessible: /home/brk55596/public_html/\n"
	if olsTestPasses([]byte(out), 1, everything) {
		t.Fatal("judged as rewritten, the broken tenant's vhost should fail the test")
	}
	if !olsTestPasses([]byte(out), 1, judged) {
		t.Fatal("the broken tenant's vhost failed another account's change")
	}
	if olsTestPasses([]byte(out), 1, judgedVhosts(everything, "", nil)) {
		t.Fatal("without the store naming it, the broken vhost is judged")
	}
}

// The web server's access is written through handles that match the
// identities recorded at create, so a tenant who swaps public_html gets a
// refusal, not an ACL on whatever the swap points at.
func TestRootOnlyWebAccessFollowsNoLink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: writes ACLs on directories another user owns")
	}
	base, e := os.MkdirTemp("/etc", "sifruno-test-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	const uid, gid, webUID = 54322, 54322, 65534
	homes, target := filepath.Join(base, "homes"), filepath.Join(base, "target")
	home := filepath.Join(homes, "webacct")
	public := filepath.Join(home, "public_html")
	tenantDir := func(p string) {
		t.Helper()
		if os.Mkdir(p, 0750) != nil || os.Chown(p, uid, gid) != nil || os.Chmod(p, 0750) != nil {
			t.Fatalf("fixture %s", p)
		}
	}
	if os.Chmod(base, 0755) != nil || os.Mkdir(homes, 0755) != nil || os.Chmod(homes, 0755) != nil || os.Mkdir(target, 0750) != nil {
		t.Fatal("fixture")
	}
	tenantDir(home)
	tenantDir(public)
	homeID, e1 := dirIdentity(home, uid, gid, 0750)
	publicID, e2 := dirIdentity(public, uid, gid, 0750)
	if e1 != nil || e2 != nil {
		t.Fatal("fixture identity")
	}
	n := &linuxSystem{opts: BrokerOptions{HomesDir: homes}, webUID: webUID}
	r := record{Account: Account{ID: strings.Repeat("c", 32), Username: "webacct", UID: uid, GID: gid}, Ownership: ownership{Home: homeID, Public: publicID}}
	acl := func(p string) []byte {
		buf := make([]byte, 256)
		size, e := unix.Getxattr(p, aclXattr, buf)
		if e != nil {
			return nil
		}
		return buf[:size]
	}

	if e := n.GrantWebAccess(t.Context(), r); e != nil {
		t.Fatalf("grant on the recorded directories: %v", e)
	}
	if !bytes.Equal(acl(home), webACL(webUID, 1)) || !bytes.Equal(acl(public), webACL(webUID, 5)) {
		t.Fatal("the grant did not write the expected ACLs")
	}
	for _, p := range []string{home, public} {
		if info, e := os.Stat(p); e != nil || info.Mode().Perm() != 0750 {
			t.Fatalf("%s lost mode 0750", p)
		}
	}

	// The tenant moves public_html away and puts a link to a root directory
	// in its place.
	if os.Rename(public, filepath.Join(home, "public_old")) != nil || os.Symlink(target, public) != nil {
		t.Fatal("swap")
	}
	if e := n.GrantWebAccess(t.Context(), r); e == nil {
		t.Fatal("the grant followed a symlinked public_html")
	}
	if acl(target) != nil {
		t.Fatal("the link's target gained an ACL")
	}

	// A different directory under the same name is refused too.
	if os.Remove(public) != nil {
		t.Fatal("unswap")
	}
	tenantDir(public)
	if e := n.GrantWebAccess(t.Context(), r); e == nil {
		t.Fatal("the grant accepted a directory other than the recorded public_html")
	}
	if acl(public) != nil {
		t.Fatal("the replacement directory gained an ACL")
	}
}

// TestOLSOutputOnThisHost judges a saved `openlitespeed -t` run with the
// broker's own rule. The dev VM proof runs it on real output; elsewhere it
// skips.
func TestOLSOutputOnThisHost(t *testing.T) {
	path := os.Getenv("SIFRUNO_OLS_TEST_OUTPUT")
	if path == "" {
		t.Skip("set SIFRUNO_OLS_TEST_OUTPUT, _CODE, _CHANGED and _WANT to judge a saved openlitespeed -t run")
	}
	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	code, err := strconv.Atoi(os.Getenv("SIFRUNO_OLS_TEST_CODE"))
	if err != nil {
		t.Fatal(err)
	}
	changed := map[string]bool{}
	if vhost := os.Getenv("SIFRUNO_OLS_TEST_CHANGED"); vhost != "" {
		changed[vhost] = true
	}
	want := os.Getenv("SIFRUNO_OLS_TEST_WANT") == "pass"
	if got := olsTestPasses(out, code, changed); got != want {
		t.Fatalf("exit %d, rewritten vhosts %v: passes %v, want %v", code, changed, got, want)
	}
}

// The broker makes the ACME challenge directory for the panel's user when it
// is missing, accepts it as it is when safe, and refuses one others can write.
func TestRootOnlyChallengeDir(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: makes a directory owned by another user")
	}
	base, e := os.MkdirTemp("/etc", "sifruno-test-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	if os.Chmod(base, 0755) != nil {
		t.Fatal("fixture")
	}
	const controller = 54323
	n := &linuxSystem{opts: BrokerOptions{ControllerUID: controller}}
	users := []nativeUser{{Username: "panel", UID: controller, GID: controller}}
	dir := filepath.Join(base, "acme")
	if e := n.ensureChallengeDir(dir, users); e != nil {
		t.Fatalf("make: %v", e)
	}
	info, e := os.Lstat(dir)
	st, _ := info.Sys().(*syscall.Stat_t)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0755 || st == nil || st.Uid != controller || st.Gid != controller {
		t.Fatalf("made %v", info)
	}
	if e := n.ensureChallengeDir(dir, users); e != nil {
		t.Fatalf("existing: %v", e)
	}
	if os.Chmod(dir, 0777) != nil {
		t.Fatal("chmod")
	}
	if n.ensureChallengeDir(dir, users) == nil {
		t.Fatal("a directory anyone can write was accepted")
	}
	if n.ensureChallengeDir(dir, nil) == nil {
		t.Fatal("a missing controller user was accepted")
	}
}

// The broker makes the suspended sites' directory, root's and empty, when it
// is missing, accepts it as it is, and refuses one that holds anything or
// that others can write.
func TestRootOnlySuspendedDir(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: makes a root-owned directory under a root-owned parent")
	}
	base, e := os.MkdirTemp("/etc", "sifruno-test-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	if os.Chmod(base, 0755) != nil {
		t.Fatal("fixture")
	}
	dir := filepath.Join(base, "suspended")
	if e := ensureSuspendedDir(dir); e != nil {
		t.Fatalf("make: %v", e)
	}
	info, e := os.Lstat(dir)
	st, _ := info.Sys().(*syscall.Stat_t)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0755 || st == nil || st.Uid != 0 || st.Gid != 0 {
		t.Fatalf("made %v", info)
	}
	if e := ensureSuspendedDir(dir); e != nil {
		t.Fatalf("existing: %v", e)
	}
	if os.WriteFile(filepath.Join(dir, "index.html"), []byte("planted"), 0644) != nil {
		t.Fatal("plant")
	}
	if ensureSuspendedDir(dir) == nil {
		t.Fatal("a directory that holds a file was accepted")
	}
	if os.Remove(filepath.Join(dir, "index.html")) != nil || os.Chmod(dir, 0777) != nil {
		t.Fatal("chmod")
	}
	if ensureSuspendedDir(dir) == nil {
		t.Fatal("a directory anyone can write was accepted")
	}
}
