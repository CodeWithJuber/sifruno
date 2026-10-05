package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func invoke(t *testing.T, args ...string) map[string]any {
	t.Helper()
	var out, errout bytes.Buffer
	if e := run(args, &out, &errout); e != nil {
		t.Fatal(e, errout.String())
	}
	var v map[string]any
	if e := json.Unmarshal(out.Bytes(), &v); e != nil {
		t.Fatal(e, out.String())
	}
	return v
}
func TestCLIRecoveryRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if runtime.GOOS != "windows" {
		var err error
		dir, err = filepath.EvalSymlinks(dir)
		if err != nil {
			t.Fatal(err)
		}
	}
	root := filepath.Join(dir, "files")
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(root, "site.conf")
	os.WriteFile(path, []byte("before"), 0600)
	prefix := []string{"--state", filepath.Join(dir, "state"), "trail"}
	call := func(args ...string) map[string]any {
		return invoke(t, append(append([]string{}, prefix...), args...)...)
	}
	change := call("checkpoint", "--root", root, "--paths", "site.conf", "--reason", "CLI integration test", "--actor", "test operator")
	id := change["id"].(string)
	os.WriteFile(path, []byte("after"), 0600)
	call("seal", id)
	call("rollback", id)
	call("verify")
	raw, e := os.ReadFile(path)
	if e != nil || string(raw) != "before" {
		t.Fatal("rollback mismatch", e)
	}
}
func TestCLIUnverifiedGateAndSyntheticEvidence(t *testing.T) {
	var out, errout bytes.Buffer
	if e := run([]string{"status", "--require-ready"}, &out, &errout); e == nil {
		t.Fatal("unverified readiness succeeded")
	}
	reference := filepath.Join("..", "..", "lab", "fixtures", "synthetic-reference.json")
	candidate := filepath.Join("..", "..", "lab", "fixtures", "synthetic-candidate.json")
	result := invoke(t, "evidence", "compare", reference, candidate)
	if result["kind"] != "synthetic" || result["certifies_compatibility"] != false {
		t.Fatal("synthetic data misrepresented")
	}
}
