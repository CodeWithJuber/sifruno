//go:build linux

package hostaccounts

import (
	"encoding/binary"
	"testing"

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

func TestQuotaReadBack(t *testing.T) {
	soft, hard, err := parseQuotaKiB([]byte("/dev/vdb 0 184320 204800 00 [--------] /home\n"))
	if err != nil || soft != 184320 || hard != 204800 {
		t.Fatalf("got %d %d %v", soft, hard, err)
	}
	for _, bad := range []string{"", "/dev/vdb 0 x 1 00 /home\n", "/dev/vdb 0 1\n", "a 0 1 2\nb 0 1 2\n"} {
		if _, _, err := parseQuotaKiB([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
