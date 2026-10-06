package hostwebruntime

import (
	"context"
	"reflect"
	"sifruno/internal/hostweb"
	"testing"
)

func TestInstallationFixedProfile(t *testing.T) {
	o := installationOptions("/private/runtime", 42)
	if validateOptions(o) != nil {
		t.Fatal("invalid fixed profile")
	}
	p := o.Profile
	if p.ManagedRoot != o.Root+"/managed" || p.ManagedHomeRoot != o.Root+"/homes" || p.FrontChroot != o.Root+"/front-jail" || p.BackendChrootRoot != o.Root+"/backend-jails" || p.RuntimeRoot != o.Root+"/run" || p.TLSRoot != o.Root+"/tls" || p.CAFile != o.Root+"/tls/ca.pem" {
		t.Fatal("nested paths changed")
	}
	if p.ApacheBinary != "/usr/sbin/httpd" || p.FPMBinary != "/usr/sbin/php-fpm" || p.ApacheModuleRoot != "/usr/lib64/httpd/modules" || p.FrontendIP != "127.0.0.1" || p.FrontendPort != 80 || p.BackendPort != 18443 || p.FrontUID != 48 || p.FrontGID != 48 || p.ControllerUID != 42 {
		t.Fatal("fixed inputs changed")
	}
}

func TestInstallationRefusesBeforeInspection(t *testing.T) {
	for _, v := range []struct {
		root string
		uid  uint32
	}{{"relative", 42}, {"/", 42}, {"/a/../b", 42}, {"/a", 0}, {"/a", 48}, {"/a", ^uint32(0)}} {
		calls := 0
		out := checkInstallation(context.Background(), v.root, v.uid, func(context.Context, Options, func(string, bool)) error { calls++; return nil })
		if calls != 0 || out.Ready || out.Status != "invalid" {
			t.Fatalf("admitted invalid input: %+v", v)
		}
	}
	for _, ctx := range []context.Context{nil, cancelledInstallationContext()} {
		calls := 0
		out := checkInstallation(ctx, "/private/runtime", 42, func(context.Context, Options, func(string, bool)) error { calls++; return nil })
		if calls != 0 || out.Ready {
			t.Fatal("invalid context inspected")
		}
	}
}
func cancelledInstallationContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestInstallationFinalCancellationAndScopedSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	out := checkInstallation(ctx, "/private/runtime", 42, func(context.Context, Options, func(string, bool)) error { cancel(); return nil })
	if out.Ready || out.Status != "cancelled" {
		t.Fatal("cancelled success escaped")
	}
	failed := checkInstallation(context.Background(), "/private/runtime", 42, func(_ context.Context, _ Options, record func(string, bool)) error {
		record("root", false)
		return ErrUnavailable
	})
	if failed.Ready || failed.Status != "unavailable" || !reflect.DeepEqual(failed.Checks, []InstallationCheck{{"profile", true}, {"root", false}}) {
		t.Fatal("refusal lost")
	}
	// This checks report orchestration only, not native admission.
	passed := checkInstallation(context.Background(), "/private/runtime", 42, func(context.Context, Options, func(string, bool)) error { return nil })
	if passed.SchemaVersion != 1 || !passed.Ready || passed.Scope != "web_runtime_installation_inputs" || passed.RuntimeAccountLimit != 8 || passed.PreviewAccountLimit != hostweb.MaxManagedAccounts || len(passed.NotChecked) != 7 {
		t.Fatal("scope missing")
	}
}
