//go:build windows

package main

import "testing"

func TestTransferRefusesWindowsRemoteAndStreamPathsBeforeOpening(t *testing.T) {
	for _, p := range []string{`\\invalid-server\share\archive.zip`, `\\?\C:\archive.zip`, `C:\archive.zip:stream`} {
		if root, _, e := transferRoot(p); e == nil {
			root.Close()
			t.Fatal("remote, device or stream path accepted")
		}
	}
}
