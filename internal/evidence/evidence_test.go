package evidence

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func fixture(t *testing.T, role string) Bundle {
	t.Helper()
	zero := 0
	b, err := Seal(Bundle{SchemaVersion: 1, ID: "fixture-" + role, Kind: "synthetic", Role: role, Provenance: Provenance{Product: "fixture", ExactBuild: "fixture-build-1", OS: "AlmaLinux 9.6", Arch: "x86_64", CapturedAt: "2026-10-04T00:00:00Z", Features: []string{"fixture"}, Artifacts: []Artifact{{Name: "fixture", Path: "/fixtures/input", SHA256: strings.Repeat("a", 64)}}}, Cases: []Case{{Operation: Operation{ID: "defaults", ObligationID: "cli.whmapi1", Transport: "cli", Command: []string{"/usr/local/cpanel/bin/whmapi1", "--output=jsonpretty", "version"}}, Outcome: Outcome{Format: "json", ExitCode: &zero, Stdout: `{"data":{"value":1},"metadata":{"result":1}}`, Stderr: ""}}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func reseal(t *testing.T, b Bundle) Bundle {
	t.Helper()
	b, err := Seal(b)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSyntheticRoundTripAndTamper(t *testing.T) {
	b := fixture(t, "reference")
	var saved bytes.Buffer
	if err := Save(&saved, b); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(&saved)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Kind != "synthetic" || loaded.SHA256 != b.SHA256 {
		t.Fatal("classification or digest changed")
	}
	loaded.Cases[0].Outcome.Stdout = `{"data":{"value":0},"metadata":{"result":1}}`
	if Verify(loaded) == nil {
		t.Fatal("altered output accepted")
	}
	loaded = b
	loaded.Provenance.ExactBuild = "different-build"
	if Verify(loaded) == nil {
		t.Fatal("altered provenance accepted")
	}
}

func TestCanonicalJSONExactNumbersObjectsAndArrays(t *testing.T) {
	a, err := CanonicalJSON([]byte(` {"z":[2,1],"x":1.00,"large":9007199254740993,"zero":-0.0} `))
	if err != nil {
		t.Fatal(err)
	}
	b, err := CanonicalJSON([]byte(`{"zero":0,"large":9007199254740993.0,"x":10e-1,"z":[2.0,1]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("equivalent JSON differs: %s / %s", a, b)
	}
	c, _ := CanonicalJSON([]byte(`{"zero":0,"large":9007199254740992,"x":1,"z":[2,1]}`))
	if bytes.Equal(a, c) {
		t.Fatal("large number rounded")
	}
	c, _ = CanonicalJSON([]byte(`{"zero":0,"large":9007199254740993,"x":1,"z":[1,2]}`))
	if bytes.Equal(a, c) {
		t.Fatal("array ordering ignored")
	}
}

func TestMalformedAndBoundedJSON(t *testing.T) {
	for _, data := range [][]byte{[]byte(`{"a":1,"a":2}`), []byte(`{"a":{"b":1,"b":2}}`), []byte(`{} {}`), []byte(`{"a":`), []byte(`1e513`), []byte(strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66)), {0xff}} {
		if _, err := CanonicalJSON(data); err == nil {
			t.Fatalf("malformed or excessive JSON accepted: %.30q", data)
		}
	}
	if _, err := Load(strings.NewReader(strings.Repeat(" ", MaxBundleBytes+1))); err == nil {
		t.Fatal("oversize document accepted")
	}
	b := fixture(t, "reference")
	data, _ := json.Marshal(b)
	data = bytes.Replace(data, []byte(`"schema_version":1`), []byte(`"unknown_field":1,"schema_version":1`), 1)
	if _, err := Load(bytes.NewReader(data)); err == nil {
		t.Fatal("unknown evidence field accepted")
	}
}

func TestUnicodeEscapeIntegrity(t *testing.T) {
	for _, v := range []string{`"\ud800"`, `"\udfff"`, `"\ud800\u0041"`} {
		if _, err := CanonicalJSON([]byte(v)); err == nil {
			t.Fatalf("unpaired surrogate accepted: %s", v)
		}
	}
	a, err := CanonicalJSON([]byte(`"\ud83d\ude00"`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := CanonicalJSON([]byte(`"😀"`))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("valid surrogate pair differs")
	}
	if _, err := CanonicalJSON([]byte(`"\\ud800"`)); err != nil {
		t.Fatal("literal escaped backslash treated as Unicode escape")
	}
}

func TestMalformedProvenanceAndOperations(t *testing.T) {
	changes := map[string]func(*Bundle){
		"missing build":       func(b *Bundle) { b.Provenance.ExactBuild = "" },
		"bad artifact":        func(b *Bundle) { b.Provenance.Artifacts[0].SHA256 = "not-a-hash" },
		"relative artifact":   func(b *Bundle) { b.Provenance.Artifacts[0].Path = "../binary" },
		"missing features":    func(b *Bundle) { b.Provenance.Features = nil },
		"unsorted features":   func(b *Bundle) { b.Provenance.Features = []string{"z", "a"} },
		"duplicate features":  func(b *Bundle) { b.Provenance.Features = []string{"a", "a"} },
		"bad timestamp":       func(b *Bundle) { b.Provenance.CapturedAt = "yesterday" },
		"non UTC":             func(b *Bundle) { b.Provenance.CapturedAt = "2026-10-04T00:00:00+01:00" },
		"licensed synthetic":  func(b *Bundle) { b.Provenance.LicensedReferenceAttested = true },
		"unattested observed": func(b *Bundle) { b.Kind = "observed" },
		"unknown kind":        func(b *Bundle) { b.Kind = "passed" },
		"empty cases":         func(b *Bundle) { b.Cases = nil },
		"duplicate cases":     func(b *Bundle) { b.Cases = append(b.Cases, b.Cases[0]) },
		"large output":        func(b *Bundle) { b.Cases[0].Outcome.Stdout = strings.Repeat("x", MaxOutputBytes+1) },
		"missing exit":        func(b *Bundle) { b.Cases[0].Outcome.ExitCode = nil },
		"secret argument":     func(b *Bundle) { b.Cases[0].Operation.Command = append(b.Cases[0].Operation.Command, "token=secret") },
		"secret pair": func(b *Bundle) {
			b.Cases[0].Operation.Command = append(b.Cases[0].Operation.Command, "--password", "secret")
		},
		"control command": func(b *Bundle) { b.Cases[0].Operation.Command[0] = "bad\targument" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			b := fixture(t, "reference")
			change(&b)
			if _, err := Seal(b); err == nil {
				t.Fatal("invalid evidence accepted")
			}
		})
	}
}

func TestComparisonIncludesDefaultsErrorsStatusAndMissingCases(t *testing.T) {
	ref := fixture(t, "reference")
	candidate := fixture(t, "candidate")
	candidate.Cases[0].Outcome.Stdout = `{"metadata":{"result":1.0},"data":{"value":1e0}}`
	candidate = reseal(t, candidate)
	r, err := Compare(ref, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != "synthetic" || r.Matching != 1 || r.CertifiesCompatibility {
		t.Fatal("synthetic matches incorrectly classified")
	}
	exit := 1
	candidate.Cases[0].Outcome.ExitCode = &exit
	candidate.Cases[0].Outcome.Stderr = "permission denied\n"
	candidate.Cases[0].Outcome.Stdout = `{"metadata":{"result":0,"reason":"permission denied"}}`
	candidate = reseal(t, candidate)
	r, err = Compare(ref, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if r.Different != 1 || len(r.Cases[0].Differences) != 3 {
		t.Fatalf("error differences missing: %+v", r)
	}
	candidate.Cases[0].Operation.ID = "another-case"
	candidate = reseal(t, candidate)
	r, _ = Compare(ref, candidate)
	if r.Total != 2 || r.Different != 2 {
		t.Fatal("missing/extra cases ignored")
	}
	if _, err := Compare(candidate, ref); err == nil {
		t.Fatal("roles ignored")
	}
}

func TestObservedAttestationsNeverCertifyAndContextMismatch(t *testing.T) {
	ref := fixture(t, "reference")
	candidate := fixture(t, "candidate")
	ref.Kind = "observed"
	ref.Provenance.DisposableHostAttested = true
	ref.Provenance.LicensedReferenceAttested = true
	candidate.Kind = "observed"
	candidate.Provenance.DisposableHostAttested = true
	ref = reseal(t, ref)
	candidate = reseal(t, candidate)
	r, err := Compare(ref, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != "observed_differential" || r.Matching != 1 || r.CertifiesCompatibility {
		t.Fatal("attestations promoted into a certificate")
	}
	candidate.Provenance.OS = "CloudLinux 9"
	candidate = reseal(t, candidate)
	r, _ = Compare(ref, candidate)
	if r.ContextMatches || len(r.ContextDifferences) != 1 {
		t.Fatal("different OS context hidden")
	}
}

func TestHTTPComparisonAndRawText(t *testing.T) {
	ref := fixture(t, "reference")
	candidate := fixture(t, "candidate")
	for _, b := range []*Bundle{&ref, &candidate} {
		b.Cases[0].Operation = Operation{ID: "not-found", ObligationID: "api.whm1", Transport: "http", Method: "GET", Path: "/json-api/sifruno_invalid_function?api.version=1"}
		b.Cases[0].Outcome = Outcome{Format: "text", HTTPStatus: 404, Stdout: "missing\n", Stderr: ""}
	}
	ref = reseal(t, ref)
	candidate.Cases[0].Outcome.HTTPStatus = 200
	candidate.Cases[0].Outcome.Stdout = "missing"
	candidate = reseal(t, candidate)
	r, err := Compare(ref, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Cases[0].Differences) != 2 {
		t.Fatalf("status or exact newline ignored: %+v", r.Cases)
	}
}

func TestPythonCaptureDigestInteroperability(t *testing.T) {
	load := func(name string) Bundle {
		t.Helper()
		f, err := os.Open("../../lab/fixtures/" + name + ".json")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		b, err := Load(f)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	r, err := Compare(load("synthetic-reference"), load("synthetic-candidate"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != "synthetic" || r.Total != 2 || r.Matching != 1 || r.Different != 1 || r.CertifiesCompatibility {
		t.Fatalf("unexpected fixture evidence: %+v", r)
	}
}

func TestAggregateAndCaseBounds(t *testing.T) {
	b := fixture(t, "reference")
	for i := 1; i <= MaxCases; i++ {
		c := b.Cases[0]
		c.Operation.ID = "case-" + strings.Repeat("x", i%20) + string(rune('a'+i/20))
		b.Cases = append(b.Cases, c)
	}
	if _, err := Seal(b); err == nil {
		t.Fatal("case count overflow accepted")
	}
	b = fixture(t, "reference")
	b.Cases[0].Outcome.Format = "text"
	b.Cases[0].Outcome.Stdout = strings.Repeat("x", MaxOutputBytes)
	base := b.Cases[0]
	for i := 1; i < 20; i++ {
		c := base
		c.Operation.ID = "case-" + string(rune('a'+i))
		b.Cases = append(b.Cases, c)
	}
	if _, err := Seal(b); err == nil {
		t.Fatal("aggregate bundle overflow accepted")
	}
}
