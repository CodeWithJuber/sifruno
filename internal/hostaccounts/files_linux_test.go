//go:build linux

package hostaccounts

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// The file helper is one site step: the same transient unit in the
// account's slice, with the plan's task limit, NoNewPrivileges and a fixed
// description, started in the home, with no argument at all; the request
// travels on stdin.
func TestFilesHelperRunsAsASiteStepInTheHome(t *testing.T) {
	r := record{Account: Account{UID: 20001, GID: 20001, Username: "alice", Home: "/home/alice", PublicHTML: "/home/alice/public_html", Limits: AccountLimits{Processes: 64, MemoryMiB: 512, CPUPercent: 50}}}
	unit, err := siteUnit(20001)
	if err != nil {
		t.Fatal(err)
	}
	got, err := siteRunArgsIn(r, unit, 2*time.Minute, r.Account.Home, FilesHelper, nil)
	want := []string{
		"--quiet", "--wait", "--pipe", "--collect",
		"--unit=" + unit,
		"--description=sifruno site step",
		"--slice=user-20001.slice",
		"--uid=20001", "--gid=20001",
		"--working-directory=/home/alice",
		"--property=TasksMax=64",
		"--property=RuntimeMaxSec=120",
		"--property=KillMode=control-group",
		"--property=KillSignal=SIGKILL",
		"--property=NoNewPrivileges=yes",
		"--setenv=PATH=/usr/bin:/bin",
		"--setenv=LANG=C.UTF-8",
		"--setenv=HOME=/var/lib/sifruno-site-home",
		"--setenv=USER=alice",
		"--setenv=LOGNAME=alice",
		"--setenv=WP_CLI_CACHE_DIR=/dev/null",
		"--setenv=WP_CLI_DISABLE_AUTO_CHECK_UPDATE=1",
		"--", "/usr/local/lib/sifruno/bin/sifruno-files",
	}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("args: %v\n got %q\nwant %q", err, got, want)
	}
	// Only the account's own home or public_html can be the start folder.
	for _, dir := range []string{"/", "/home", "/home/bob", "/home/alice/", "/home/alice/../bob", "home/alice", "/etc", "/home/alice/public_html/wp-content"} {
		if _, err := siteRunArgsIn(r, unit, time.Minute, dir, FilesHelper, nil); !errors.Is(err, ErrInvalid) {
			t.Errorf("start folder %q: %v", dir, err)
		}
	}
	// The WordPress steps keep starting in public_html.
	if got, err := siteRunArgs(r, unit, time.Minute, "/usr/bin/true", nil); err != nil || !slices.Contains(got, "--working-directory=/home/alice/public_html") {
		t.Fatalf("site steps: %v %q", err, got)
	}
}

// RunFiles starts nothing without the web operation (which makes the empty
// HOME every site step gets), or when the helper is not a trusted file.
func TestRunFilesRefusesBeforeStartingAnything(t *testing.T) {
	r := record{Account: Account{UID: 20001, GID: 20001, Username: "alice", Home: "/home/alice", PublicHTML: "/home/alice/public_html"}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	off := &linuxSystem{opts: BrokerOptions{ControllerUID: 20500}, tools: map[string]os.FileInfo{}}
	if err := off.RunFiles(ctx, r, strings.NewReader(""), new(strings.Builder)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("web operation off: %v", err)
	}
	on := &linuxSystem{opts: BrokerOptions{ControllerUID: 20500}, webUID: 990, tools: map[string]os.FileInfo{}}
	if _, err := trustedFile(FilesHelper, false); err == nil {
		t.Skip("this host has the helper installed; the refusal below needs it absent")
	}
	if err := on.RunFiles(ctx, r, strings.NewReader(""), new(strings.Builder)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no trusted helper: %v", err)
	}
}
