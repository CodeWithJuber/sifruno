//go:build linux

package hostaccounts

import (
	"bytes"
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// A step the broker runs as a site's user is one transient scope in the
// account's own user slice, with the plan's task limit and the time left;
// setpriv drops it to that user with no group, no_new_privs and no
// capability, and env gives it a fixed environment and starts it in
// public_html. Nothing on the way expands "$" or "%", so the arguments
// arrive as sent.
func TestSiteRunArgsBoundTheStepToTheAccountSlice(t *testing.T) {
	r := record{Account: Account{UID: 20001, GID: 20001, Username: "alice", PublicHTML: "/home/alice/public_html", Limits: AccountLimits{Processes: 64, MemoryMiB: 512, CPUPercent: 50}}}
	unit, e := siteUnit(20001)
	if e != nil || !siteUnitPattern.MatchString(unit) || !strings.HasPrefix(unit, "sifruno-site-20001-") || !strings.HasSuffix(unit, ".scope") {
		t.Fatalf("unit %q: %v", unit, e)
	}
	if other, _ := siteUnit(20001); other == unit {
		t.Fatal("two steps got the same unit name")
	}
	php := "/usr/local/lsws/lsphp83/bin/php"
	title := "--title=Proof 100% $HOME %h %n ${HOME} costs $$5"
	got, e := siteRunArgs(r, unit, 90*time.Second+time.Millisecond, php, []string{"-r", "echo $HOME;", title, "a=b", "--"})
	want := []string{
		"--quiet", "--scope", "--collect",
		"--unit=" + unit,
		"--description=sifruno site step",
		"--slice=user-20001.slice",
		"--property=TasksMax=64",
		"--property=RuntimeMaxSec=91",
		"--property=KillMode=control-group",
		"--property=KillSignal=SIGKILL",
		"--", "/usr/bin/setpriv",
		"--reuid=20001", "--regid=20001", "--clear-groups",
		"--no-new-privs", "--inh-caps=-all", "--bounding-set=-all",
		"--pdeathsig=keep",
		"--", "/usr/bin/env", "-i", "--chdir=/home/alice/public_html", "--",
		"PATH=/usr/bin:/bin",
		"LANG=C.UTF-8",
		"HOME=/var/lib/sifruno-site-home",
		"USER=alice",
		"LOGNAME=alice",
		"WP_CLI_CACHE_DIR=/dev/null",
		"WP_CLI_DISABLE_AUTO_CHECK_UPDATE=1",
		php, "-r", "echo $HOME;", title, "a=b", "--",
	}
	if e != nil || !slices.Equal(got, want) {
		t.Fatalf("args: %v\n got %q\nwant %q", e, got, want)
	}
	// systemd-run's own --uid, --gid, --working-directory and --setenv are
	// never used: the drop is setpriv's, and the user enters the folder.
	for _, a := range got {
		for _, option := range []string{"--uid", "--gid", "--working-directory", "--setenv", "--wait", "--pipe"} {
			if strings.HasPrefix(a, option) {
				t.Fatalf("systemd-run option %q", a)
			}
		}
	}

	// A plan change in flight counts as done, as for the slice drop-in.
	planned := r
	planned.Pending = &pending{Action: "plan"}
	planned.LimitsNext = AccountLimits{Processes: 200, MemoryMiB: 2048, CPUPercent: 200}
	if got, e := siteRunArgs(planned, unit, time.Minute, php, nil); e != nil || !slices.Contains(got, "--property=TasksMax=200") {
		t.Fatalf("pending plan: %v %q", e, got)
	}

	refused := map[string]func() (record, string, time.Duration, string){
		"root": func() (record, string, time.Duration, string) {
			x := r
			x.Account.UID, x.Account.GID = 0, 0
			return x, unit, time.Minute, php
		},
		"a system user": func() (record, string, time.Duration, string) {
			x := r
			x.Account.UID, x.Account.GID = 999, 999
			return x, unit, time.Minute, php
		},
		"another group": func() (record, string, time.Duration, string) {
			x := r
			x.Account.GID = 0
			return x, unit, time.Minute, php
		},
		"another account's unit": func() (record, string, time.Duration, string) {
			x := r
			x.Account.UID, x.Account.GID = 20002, 20002
			return x, unit, time.Minute, php
		},
		"a unit name not the broker's": func() (record, string, time.Duration, string) { return r, "sshd.service", time.Minute, php },
		"no time left":                 func() (record, string, time.Duration, string) { return r, unit, 0, php },
		"a relative program":           func() (record, string, time.Duration, string) { return r, unit, time.Minute, "php" },
		"a relative public_html": func() (record, string, time.Duration, string) {
			x := r
			x.Account.PublicHTML = "public_html"
			return x, unit, time.Minute, php
		},
		"a username that is not one": func() (record, string, time.Duration, string) {
			x := r
			x.Account.Username = "alice\nHOME=/root"
			return x, unit, time.Minute, php
		},
		"limits out of bounds": func() (record, string, time.Duration, string) {
			x := r
			x.Account.Limits.Processes = 5
			return x, unit, time.Minute, php
		},
		"a program env would take for a variable": func() (record, string, time.Duration, string) {
			return r, unit, time.Minute, "/usr/bin/A=B"
		},
		"a service unit": func() (record, string, time.Duration, string) {
			return r, strings.TrimSuffix(unit, ".scope") + ".service", time.Minute, php
		},
	}
	for name, input := range refused {
		x, u, left, path := input()
		if _, e := siteRunArgs(x, u, left, path, nil); !errors.Is(e, ErrInvalid) {
			t.Errorf("%s: %v", name, e)
		}
	}
	if _, e := siteUnit(19999); !errors.Is(e, ErrInvalid) {
		t.Fatalf("unit for a UID outside the range: %v", e)
	}
}

// runAsSite starts nothing without a deadline, for the controller, or when
// systemd-run, setpriv or env is not the binary pinned at start; the broker
// kills only a scope name of its own.
func TestRunAsSiteRefusesBeforeStartingAnything(t *testing.T) {
	n := &linuxSystem{opts: BrokerOptions{ControllerUID: 20500}, tools: map[string]os.FileInfo{}}
	r := record{Account: Account{UID: 20001, GID: 20001, Username: "alice", PublicHTML: "/home/alice/public_html"}}
	if _, _, e := n.runAsSite(context.Background(), r, "/usr/bin/true", ""); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("no deadline: %v", e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, _, e := n.runAsSite(ctx, r, "/usr/bin/true", ""); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("systemd-run not pinned: %v", e)
	}
	// systemd-run alone pinned is not enough: setpriv and env must be too.
	if info, err := trustedFile(systemdRun, false); err == nil {
		pinned := &linuxSystem{opts: n.opts, tools: map[string]os.FileInfo{systemdRun: info}}
		if _, _, e := pinned.runAsSite(ctx, r, "/usr/bin/true", ""); !errors.Is(e, ErrUnavailable) {
			t.Fatalf("setpriv and env not pinned: %v", e)
		}
	}
	controller := r
	controller.Account.UID, controller.Account.GID = 20500, 20500
	if _, _, e := n.runAsSite(ctx, controller, "/usr/bin/true", ""); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("the controller's UID: %v", e)
	}
	for _, unit := range []string{"", "sshd.service", "user-20001.slice", "sifruno-site-20001-0123456789abcdef.service", "sifruno-site-20001-0123456789abcdef.scope --signal=SIGTERM"} {
		if e := n.stopSiteUnit(ctx, unit); !errors.Is(e, ErrInvalid) {
			t.Fatalf("kill of %q: %v", unit, e)
		}
	}
}

// After a step the broker kills its scope by name. The kill reaching the
// scope, or systemd answering that it has already unloaded it (which it
// does only once no process is left), means nothing of the step runs on;
// any other answer, or one about another unit, does not.
func TestSiteUnitGoneOnlyWhenKilledOrUnloaded(t *testing.T) {
	unit := "sifruno-site-20001-0123456789abcdef.scope"
	other := "sifruno-site-20001-fedcba9876543210.scope"
	answers := []struct {
		code int
		out  string
		gone bool
	}{
		{0, "", true},
		{1, "Failed to kill unit " + unit + ": Unit " + unit + " not loaded.\n", true},
		{1, "", false},
		{1, "Failed to connect to bus: Connection refused\n", false},
		{1, "Failed to kill unit " + unit + ": Access denied\n", false},
		{1, "Failed to kill unit " + other + ": Unit " + other + " not loaded.\n", false},
		{5, "Unit " + unit + " not loaded.\n", false},
		{-1, "Unit " + unit + " not loaded.\n", false},
	}
	for _, a := range answers {
		if got := siteUnitGone(unit, a.code, []byte(a.out)); got != a.gone {
			t.Errorf("exit %d, %q: gone %v, want %v", a.code, a.out, got, a.gone)
		}
	}
}

// The cache setting uses LiteSpeed Cache's own form ("false") and must
// print the value it stored; a step after core install that fails says
// WordPress is installed, one before it does not.
func TestWordPressStepsAndWhatAFailureSays(t *testing.T) {
	r := record{Account: Account{UID: 20001, GID: 20001, Username: "alice", Domain: "alice.test", PublicHTML: "/home/alice/public_html"}}
	in := wordpressInput("alice", 1)
	steps := wordPressSteps(r, in, "/usr/local/lsws/lsphp83/bin/php")
	var names []string
	for _, st := range steps {
		names = append(names, st.name)
	}
	if want := []string{"download", "config", "config", "install", "cache plugin", "cache plugin", "cache plugin", "cache setting", "version"}; !slices.Equal(names, want) {
		t.Fatalf("steps %q", names)
	}
	setting := steps[7]
	if !slices.Equal(setting.args[len(setting.args)-4:], []string{"litespeed-option", "set", "cache-priv", "false"}) || string(setting.want) != "cache-priv:\n0\n" {
		t.Fatalf("cache setting %q wants %q", setting.args, setting.want)
	}
	for _, st := range steps {
		for _, a := range st.args {
			if strings.Contains(a, in.AdminPassword) || strings.Contains(a, in.DBPassword) {
				t.Fatalf("a password in the arguments of %s", st.name)
			}
		}
	}

	// printed is what each step prints when it succeeds.
	printed := func(st wpStep) []byte {
		switch st.name {
		case "version":
			return []byte("6.8.3\n")
		case "cache setting":
			return []byte("cache-priv:\n0\n")
		}
		if st.want != nil {
			return st.want
		}
		return []byte("Success.\n")
	}
	run := func(failAt string, out []byte) (WordPressResult, error) {
		return runWordPressSteps(steps, []string{in.AdminPassword, in.DBPassword}, func(st wpStep) ([]byte, int, error) {
			if st.name == failAt {
				return out, 1, nil
			}
			return printed(st), 0, nil
		})
	}
	if got, e := run("", nil); e != nil || got.Version != "6.8.3" {
		t.Fatalf("whole install: %+v %v", got, e)
	}
	for _, tc := range []struct {
		step      string
		installed bool
	}{{"download", false}, {"config", false}, {"install", false}, {"cache plugin", true}, {"cache setting", true}, {"version", true}} {
		_, e := run(tc.step, []byte("Error: with "+in.DBPassword))
		var failed *InstallError
		if !errors.As(e, &failed) || failed.Step != tc.step || failed.Installed != tc.installed || strings.Contains(failed.Detail, in.DBPassword) {
			t.Errorf("failure at %s: %+v", tc.step, e)
		}
	}
	// The setting step ends well but stored "on": the install says so.
	_, e := runWordPressSteps(steps, nil, func(st wpStep) ([]byte, int, error) {
		if st.name == "cache setting" {
			return []byte("cache-priv:\n1\n"), 0, nil
		}
		return printed(st), 0, nil
	})
	var failed *InstallError
	if !errors.As(e, &failed) || failed.Step != "cache setting" || !failed.Installed {
		t.Fatalf("setting left on: %v", e)
	}
	// A version that is not one is a failure of the version step.
	_, e = runWordPressSteps(steps, nil, func(st wpStep) ([]byte, int, error) {
		if st.name == "version" {
			return []byte("PHP Warning: something\n"), 0, nil
		}
		return printed(st), 0, nil
	})
	if !errors.As(e, &failed) || failed.Step != "version" || !failed.Installed || !bytes.Contains([]byte(failed.Detail), []byte("PHP Warning")) {
		t.Fatalf("no version: %v", e)
	}
}
