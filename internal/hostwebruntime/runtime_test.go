package hostwebruntime

import (
	"context"
	"errors"
	"path"
	"runtime"
	"strings"
	"testing"
	"time"

	"sifruno/internal/hostaccounts"
	"sifruno/internal/hostweb"
	"sifruno/internal/hostwebgeneration"
)

func testOptions(root string) Options {
	return Options{Root: root, Profile: hostweb.Profile{Name: hostweb.RestrictedChrootV1, ManagedRoot: root + "/managed", ManagedHomeRoot: root + "/homes", FrontChroot: root + "/front", BackendChrootRoot: root + "/jails", RuntimeRoot: root + "/run", TLSRoot: root + "/tls", CAFile: root + "/tls/ca.pem", ApacheBinary: "/usr/sbin/httpd", FPMBinary: "/usr/sbin/php-fpm", ApacheModuleRoot: "/usr/lib64/httpd/modules", FrontendIP: "127.0.0.1", FrontendPort: 18080, BackendPort: 18443, FrontUID: 48, FrontGID: 48, ControllerUID: 2000}}
}
func testGeneration(t *testing.T, o Options, id string, denied bool) hostwebgeneration.Generation {
	t.Helper()
	now := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	a := []hostaccounts.Account{{ID: strings.Repeat("a", 32), Username: "webalpha", Domain: "alpha.test", UID: 20001, GID: 20001, Home: o.Profile.ManagedHomeRoot + "/webalpha", PublicHTML: o.Profile.ManagedHomeRoot + "/webalpha/public_html", State: "active", Revision: 1, CreatedAt: now, UpdatedAt: now}}
	render := append([]hostaccounts.Account{}, a...)
	if denied {
		render[0].State = "suspended"
	}
	b, e := hostweb.Compile(o.Profile, render)
	if e != nil {
		t.Fatal(e)
	}
	return hostwebgeneration.Generation{ID: id, ProfileSHA256: digest(o.Profile), SnapshotSHA256: digest(a), Denied: denied, Accounts: a, Bundle: b}
}
func TestCanonicalAdmission(t *testing.T) {
	o := testOptions("/srv/sifruno-runtime")
	g := testGeneration(t, o, strings.Repeat("b", 32), false)
	if validateOptions(o) != nil || validateGeneration(o.Profile, g, false) != nil {
		t.Fatal("valid original rejected")
	}
	cases := map[string]func(*hostwebgeneration.Generation){
		"snapshot": func(v *hostwebgeneration.Generation) { v.SnapshotSHA256 = strings.Repeat("0", 64) },
		"profile":  func(v *hostwebgeneration.Generation) { v.ProfileSHA256 = strings.Repeat("0", 64) },
		"state": func(v *hostwebgeneration.Generation) {
			v.Accounts[0].State = "suspended"
			v.SnapshotSHA256 = digest(v.Accounts)
		},
		"revision": func(v *hostwebgeneration.Generation) {
			v.Accounts[0].Revision = 0
			v.SnapshotSHA256 = digest(v.Accounts)
		},
		"id":   func(v *hostwebgeneration.Generation) { v.ID = "../../escape" },
		"mode": func(v *hostwebgeneration.Generation) { v.Bundle.Files[0].Mode = 0644 },
		"data": func(v *hostwebgeneration.Generation) { v.Bundle.Files[0].Data[0] = 'x' },
		"different-valid-bundle": func(v *hostwebgeneration.Generation) {
			a := append([]hostaccounts.Account{}, v.Accounts...)
			a[0].Domain = "other.test"
			v.Bundle, _ = hostweb.Compile(o.Profile, a)
			if v.Bundle.Validate() != nil {
				t.Fatal("test bundle not internally valid")
			}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			v := copyGeneration(g)
			change(&v)
			if validateGeneration(o.Profile, v, false) == nil {
				t.Fatal("drift admitted")
			}
		})
	}
}
func TestExactDeniedBootstrap(t *testing.T) {
	o := testOptions("/srv/sifruno-runtime")
	g := testGeneration(t, o, "", true)
	if validateGeneration(o.Profile, g, true) != nil {
		t.Fatal("denial rejected")
	}
	g.Denied = false
	if validateGeneration(o.Profile, g, true) == nil {
		t.Fatal("active bootstrap")
	}
	g.Denied = true
	g.ID = strings.Repeat("b", 32)
	if validateGeneration(o.Profile, g, true) == nil {
		t.Fatal("nonempty bootstrap")
	}
}
func TestCopiedData(t *testing.T) {
	g := testGeneration(t, testOptions("/srv/sifruno-runtime"), "", true)
	v := copyGeneration(g)
	v.Accounts[0].Domain = "different.test"
	v.Bundle.Files[0].Data[0] = 'x'
	if g.Accounts[0].Domain != "alpha.test" || g.Bundle.Files[0].Data[0] == 'x' {
		t.Fatal("alias escaped")
	}
}
func TestProfileBoundaries(t *testing.T) {
	base := testOptions("/srv/sifruno-runtime")
	for name, change := range map[string]func(*Options){"outside": func(o *Options) { o.Profile.RuntimeRoot = "/run/foreign" }, "root": func(o *Options) { o.Root = "/" }, "public": func(o *Options) { o.Profile.FrontendIP = "0.0.0.0" }, "implicit": func(o *Options) { o.Profile.FrontUID = 0 }, "clean": func(o *Options) { o.Root = "/srv/../srv/sifruno-runtime" }} {
		t.Run(name, func(t *testing.T) {
			o := base
			change(&o)
			if validateOptions(o) == nil {
				t.Fatal("invalid profile")
			}
		})
	}
}
func TestRecordProcessAdmission(t *testing.T) {
	o := testOptions("/srv/sifruno-runtime")
	g := testGeneration(t, o, "", true)
	p := processPin{Role: "front", PID: 100, Start: "123", Boot: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", Executable: o.Profile.ApacheBinary, ExecutableSHA256: strings.Repeat("a", 64), Config: path.Join(o.Profile.ManagedRoot, generationPath(g), "apache/front.conf"), Namespace: 55, ExecutableIno: 99}
	v := record{Version: 1, Current: g, Processes: []processPin{p}}
	if validateRecord(o.Profile, v) != nil {
		t.Fatal("valid record rejected")
	}
	for name, change := range map[string]func(*processPin){"pid": func(p *processPin) { p.PID = 1 }, "start": func(p *processPin) { p.Start = "not-a-time" }, "boot": func(p *processPin) { p.Boot = strings.Repeat("x", 36) }, "hash": func(p *processPin) { p.ExecutableSHA256 = strings.Repeat("z", 64) }, "config": func(p *processPin) { p.Config = o.Profile.ManagedRoot + "/other.conf" }, "account": func(p *processPin) { p.AccountID = strings.Repeat("c", 32) }, "namespace": func(p *processPin) { p.Namespace = 0 }} {
		t.Run(name, func(t *testing.T) {
			x := v
			x.Processes = append([]processPin(nil), v.Processes...)
			change(&x.Processes[0])
			if validateRecord(o.Profile, x) == nil {
				t.Fatal("foreign pin admitted")
			}
		})
	}
	v.Processes = append(v.Processes, p)
	if validateRecord(o.Profile, v) == nil {
		t.Fatal("duplicate pin")
	}
}
func TestCanceledInput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, e := bounded(ctx); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, _, e := bounded(nil); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
}
func TestPendingRevisionAdmission(t *testing.T) {
	o := testOptions("/srv/sifruno-runtime")
	before := testGeneration(t, o, "", true)
	after := testGeneration(t, o, strings.Repeat("b", 32), false)
	v := record{Version: 1, Current: before, Pending: &transaction{OperationID: strings.Repeat("c", 32), Before: before, After: after, Target: after}}
	if validateRecord(o.Profile, v) != nil {
		t.Fatal("valid native intent rejected")
	}
	v.Pending.Revision = 1
	if validateRecord(o.Profile, v) == nil {
		t.Fatal("stale pending revision admitted")
	}
	v.Pending.Revision = 0
	v.Revision = 1
	v.LastOperation = strings.Repeat("d", 32)
	v.Current = after
	if validateRecord(o.Profile, v) == nil {
		t.Fatal("unrelated prior operation admitted")
	}
	v.LastOperation = strings.Repeat("c", 32)
	if validateRecord(o.Profile, v) != nil {
		t.Fatal("known exact postcommit repair rejected")
	}
	v.Pending.Revision = 1
	if validateRecord(o.Profile, v) != nil {
		t.Fatal("explicit postcommit repair rejected")
	}
}
func TestNonLinuxUnavailable(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("non-Linux contract")
	}
	if _, e := Open(testOptions("/not-created")); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	r := &Runtime{}
	if _, e := r.Observe(context.Background()); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	if e := r.Bootstrap(context.Background(), hostwebgeneration.Generation{}); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
}
