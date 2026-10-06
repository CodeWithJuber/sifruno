package hostaccounts

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func layoutPassingProbes() layoutProbes {
	return layoutProbes{
		valid: func() bool { return true },
		group: func() error { return nil },
		admission: func(ctx context.Context) BrokerAdmissionReport {
			var checks [9]func() error
			for i := range checks {
				checks[i] = func() error { return nil }
			}
			return probeBrokerAdmission(ctx, "linux", checks)
		},
		access: func(context.Context) error { return nil },
		inspect: func(context.Context) ([4]string, error) {
			return [4]string{"planned_create", "admitted_existing", "planned_create", "planned_create"}, nil
		},
		prepare: func(_ context.Context, r *LayoutReport) error {
			for i := range r.Directories {
				if r.Directories[i].Action == "planned_create" {
					r.Directories[i].Action = "created"
				}
			}
			return nil
		},
	}
}

func TestControllerLayoutReportContract(t *testing.T) {
	for _, prepare := range []bool{false, true} {
		r := probeControllerLayout(context.Background(), "linux", prepare, layoutPassingProbes())
		if !r.Ready || r.ReadOnly == prepare || r.SchemaVersion != 1 || r.Scope != "native_linux_controller_layout" || len(r.Checks) != 14 || len(r.Directories) != 4 {
			t.Fatal(r)
		}
		b, e := json.Marshal(r)
		if e != nil {
			t.Fatal(e)
		}
		var envelope map[string]json.RawMessage
		if json.Unmarshal(b, &envelope) != nil || len(envelope) != 8 {
			t.Fatalf("unexpected JSON: %s", b)
		}
		for _, field := range []string{"schema_version", "scope", "platform", "ready", "read_only", "checks", "directories", "restrictions"} {
			if _, found := envelope[field]; !found {
				t.Fatal("missing field", field)
			}
		}
		if strings.Contains(string(b), "/") || strings.Contains(string(b), "UID") {
			t.Fatal("host metadata leaked", string(b))
		}
		for i, role := range []string{"broker_state", "managed_homes", "socket_parent", "controller_state"} {
			if r.Directories[i].Role != role {
				t.Fatal(r.Directories)
			}
			var entry map[string]json.RawMessage
			eb, _ := json.Marshal(r.Directories[i])
			if json.Unmarshal(eb, &entry) != nil || len(entry) != 2 {
				t.Fatal("directory entry leaks metadata", string(eb))
			}
		}
	}
}

func TestControllerLayoutPrerequisiteNoWrite(t *testing.T) {
	for _, fail := range []string{"configuration", "admission", "ownership", "access", "directories"} {
		t.Run(fail, func(t *testing.T) {
			p := layoutPassingProbes()
			writes := 0
			p.prepare = func(context.Context, *LayoutReport) error { writes++; return nil }
			switch fail {
			case "configuration":
				p.valid = func() bool { return false }
			case "admission":
				p.admission = func(context.Context) BrokerAdmissionReport {
					return uncheckedBrokerAdmission("linux", "prerequisite_refused")
				}
			case "access":
				p.access = func(context.Context) error { return errors.New("native error /secret/path UID 987654") }
			case "ownership":
				p.group = func() error { return ErrUnavailable }
			case "directories":
				p.inspect = func(context.Context) ([4]string, error) {
					return [4]string{"planned_create", "planned_create", "planned_create", "refused"}, errors.New("/secret/path 987654")
				}
			}
			r := probeControllerLayout(context.Background(), "linux", true, p)
			if r.Ready || writes != 0 {
				t.Fatal(r, "writes", writes)
			}
			b, _ := json.Marshal(r)
			if strings.Contains(string(b), "/secret") || strings.Contains(string(b), "987654") || strings.Contains(string(b), "native error") {
				t.Fatal("native detail leaked", string(b))
			}
		})
	}
	p := layoutPassingProbes()
	called := false
	p.prepare = func(context.Context, *LayoutReport) error { called = true; return nil }
	if r := probeControllerLayout(context.Background(), "linux", false, p); !r.Ready || called || r.Directories[0].Action != "planned_create" {
		t.Fatal("read-only check invoked writes", r)
	}
}

func TestControllerLayoutContextAndPlatform(t *testing.T) {
	for _, stage := range []string{"before", "admission", "access", "inspect"} {
		ctx, cancel := context.WithCancel(context.Background())
		p := layoutPassingProbes()
		switch stage {
		case "before":
			cancel()
		case "admission":
			previous := p.admission
			p.admission = func(ctx context.Context) BrokerAdmissionReport { r := previous(ctx); cancel(); return r }
		case "access":
			p.access = func(context.Context) error { cancel(); return nil }
		case "inspect":
			p.inspect = func(context.Context) ([4]string, error) { cancel(); return [4]string{}, nil }
		}
		p.prepare = func(context.Context, *LayoutReport) error { t.Fatal("canceled probe wrote"); return nil }
		got := probeControllerLayout(ctx, "linux", true, p)
		if !reflect.DeepEqual(got, uncheckedLayout("linux", true, "probe_context_unavailable")) {
			t.Fatal(stage, got)
		}
		cancel()
	}
	if r := probeControllerLayout(nil, "linux", false, layoutPassingProbes()); !reflect.DeepEqual(r, uncheckedLayout("linux", false, "probe_context_unavailable")) {
		t.Fatal(r)
	}
	if r := probeControllerLayout(context.Background(), "windows", true, layoutProbes{}); !reflect.DeepEqual(r, uncheckedLayout("windows", true, "linux_required")) {
		t.Fatal(r)
	}
}

func TestControllerLayoutPartialResultPreserved(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		p := layoutPassingProbes()
		p.prepare = func(_ context.Context, r *LayoutReport) error {
			r.Directories[0].Action = "created"
			if canceled {
				cancel()
			}
			return layoutFailure{directory: 2, created: true}
		}
		r := probeControllerLayout(ctx, "linux", true, p)
		if r.Ready || r.ReadOnly || r.Directories[0].Action != "created" || r.Directories[2].Action != "refused" || r.Checks[12].Status != "refused" {
			t.Fatal(r)
		}
		cancel()
	}
}

func TestControllerLayoutPublicGuards(t *testing.T) {
	opts := LayoutOptions{BrokerOptions: BrokerOptions{StateDir: "/secret/state", ControllerUID: 987654}, ControllerStateDir: "/secret/controller"}
	for _, fn := range []func(context.Context, LayoutOptions) LayoutReport{CheckControllerLayout, PrepareControllerLayout} {
		r := fn(nil, opts)
		b, _ := json.Marshal(r)
		if r.Ready || strings.Contains(string(b), "secret") || strings.Contains(string(b), "987654") {
			t.Fatal(r)
		}
		if runtime.GOOS != "linux" {
			if got := fn(context.Background(), opts); got.Ready || got.Checks[0].Reason != "linux_required" {
				t.Fatal(got)
			}
		}
	}
}
