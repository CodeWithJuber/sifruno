//go:build linux

package hostaccounts

import (
	"encoding/binary"
	"testing"
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
