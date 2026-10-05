package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func validInput() []byte {
	in := inputJSON{
		SchemaVersion: 1,
		Profile: profileJSON{
			Name: "restricted-chroot-v1", ManagedRoot: "/var/lib/sifruno/hostweb", ManagedHomeRoot: "/srv/sifruno-managed-homes",
			FrontChroot: "/var/lib/sifruno/front-jail", ApacheModuleRoot: "/usr/lib64/httpd/modules", BackendChrootRoot: "/var/lib/sifruno/backend-jails",
			RuntimeRoot: "/run/sifruno/hostweb", ApacheBinary: "/usr/sbin/httpd", FPMBinary: "/usr/sbin/php-fpm", TLSRoot: "/etc/sifruno/tls", CAFile: "/etc/sifruno/tls/ca.pem",
			FrontendIP: "0.0.0.0", FrontendPort: 443, BackendPort: 18443, FrontUID: 48, FrontGID: 48, ControllerUID: 2000,
		},
		Accounts: []accountJSON{{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Username: "alice", Domain: "alice.example.test", Home: "/srv/sifruno-managed-homes/alice", PublicHTML: "/srv/sifruno-managed-homes/alice/public_html", State: "active", UID: 20000, GID: 20000, Revision: 1, CreatedAt: time.Unix(0, 0).UTC(), UpdatedAt: time.Unix(0, 0).UTC()}},
	}
	b, _ := json.Marshal(in)
	return b
}

func TestRenderJSONContract(t *testing.T) {
	out, err := render(validInput())
	if err != nil {
		t.Fatal(err)
	}
	var decoded outputJSON
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != 1 || decoded.Compatibility || decoded.Activation || len(decoded.Bundle.Files) != 3 {
		t.Fatalf("unexpected output contract: %+v", decoded)
	}
	for _, f := range decoded.Bundle.Files {
		if f.Mode != "0600" || f.Config == "" || !strings.Contains(f.Config, "restricted-chroot-v1") {
			t.Fatalf("unexpected output file: %+v", f)
		}
	}
}

func TestRenderRejectsDuplicateUnknownAndActivation(t *testing.T) {
	if _, err := render([]byte(`{"schemaVersion":1,"schemaVersion":1}`)); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate key error = %v", err)
	}
	unknown := strings.TrimSuffix(string(validInput()), "}") + `,"unexpected":true}`
	if _, err := render([]byte(unknown)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field error = %v", err)
	}
	caseVariant := strings.Replace(string(validInput()), `"schemaVersion"`, `"SchemaVersion"`, 1)
	if _, err := render([]byte(caseVariant)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("case variant error = %v", err)
	}
	activation := strings.Replace(string(validInput()), `"activation":false`, `"activation":true`, 1)
	if _, err := render([]byte(activation)); err == nil || !strings.Contains(err.Error(), "activation=false") {
		t.Fatalf("activation error = %v", err)
	}
}

func TestRejectDuplicateKeysNested(t *testing.T) {
	if err := rejectDuplicateKeys([]byte(`{"profile":{"name":"a","name":"b"}}`)); err == nil {
		t.Fatal("nested duplicate accepted")
	}
}

func TestRenderBoundedInput(t *testing.T) {
	if _, err := render(make([]byte, maxInputBytes+1)); err == nil || !strings.Contains(err.Error(), "exceeds 1048576") {
		t.Fatalf("oversized input error = %v", err)
	}
}
