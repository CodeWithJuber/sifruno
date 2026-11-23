package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sifruno/internal/olsweb"
)

func writeSpec(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "spec.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRenderProof1Spec(t *testing.T) {
	out := filepath.Join(t.TempDir(), "ols")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--spec", "proof1.json", "--out", out}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	want := "conf/sifruno.conf\nconf/vhosts/sifruno-wpproof/vhconf.conf\n"
	if stdout.String() != want {
		t.Fatalf("printed %q, want %q", stdout.String(), want)
	}
	vhconf, err := os.ReadFile(filepath.Join(out, "conf", "vhosts", "sifruno-wpproof", "vhconf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"namespace                 2\n", "  extUser                 wpproof\n", "  maxConns                4\n", "  path                    /usr/local/lsws/lsphp83/bin/lsphp\n"} {
		if !strings.Contains(string(vhconf), line) {
			t.Errorf("vhconf.conf lacks %q", line)
		}
	}
	server, err := os.ReadFile(filepath.Join(out, "conf", "sifruno.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(server), "  map                     sifruno-wpproof wpproof.proof.test\n") {
		t.Error("server fragment does not map the proof domain")
	}

	// A second run into the same directory needs --force and gives the same
	// bytes.
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"--spec", "proof1.json", "--out", out}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "not empty") {
		t.Fatalf("non-empty output accepted without --force: exit %d %s", code, stderr.String())
	}
	if code := run([]string{"--spec", "proof1.json", "--out", out, "--force"}, &stdout, &stderr); code != 0 {
		t.Fatalf("--force failed: exit %d %s", code, stderr.String())
	}
	again, err := os.ReadFile(filepath.Join(out, "conf", "vhosts", "sifruno-wpproof", "vhconf.conf"))
	if err != nil || !bytes.Equal(again, vhconf) {
		t.Fatalf("forced re-render changed the output: %v", err)
	}
}

func TestRefusals(t *testing.T) {
	valid := `{"listeners":[{"name":"http","address":"*","port":80}],"sites":[]}`
	cases := []struct {
		name string
		args func(spec, out string) []string
		spec string
		code int
		want string
	}{
		{"usage", func(spec, out string) []string { return []string{"--spec", spec} }, valid, 2, "usage"},
		{"stray argument", func(spec, out string) []string { return []string{"--spec", spec, "--out", out, "extra"} }, valid, 2, "usage"},
		{"unknown field", nil, `{"listeners":[],"sites":[],"sitez":[]}`, 1, "unknown field"},
		{"trailing data", nil, valid + `{}`, 1, "data after"},
		{"not json", nil, `listener x {`, 1, "spec.json"},
		{"missing spec", func(spec, out string) []string { return []string{"--spec", spec + ".missing", "--out", out} }, valid, 1, "no such file"},
		{"invalid site names its field", nil, `{"listeners":[],"sites":[{"name":"x","username":"root","group":"root","domains":["a.example"],"doc_root":"/home/root/x","php_version":"8.3","limits":{},"isolation":{},"tls":{}}]}`, 1, "sites[0].username"},
		{"newline in domain", nil, `{"listeners":[],"sites":[{"name":"x","username":"abc","group":"abc","domains":["a.example\n}"],"doc_root":"/home/abc/x","php_version":"8.3","limits":{},"isolation":{},"tls":{}}]}`, 1, "sites[0].domains[0]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := writeSpec(t, tc.spec)
			out := filepath.Join(t.TempDir(), "out")
			args := []string{"--spec", spec, "--out", out}
			if tc.args != nil {
				args = tc.args(spec, out)
			}
			var stdout, stderr bytes.Buffer
			code := run(args, &stdout, &stderr)
			if code != tc.code || !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("exit %d stderr %q, want exit %d containing %q", code, stderr.String(), tc.code, tc.want)
			}
			if stdout.Len() != 0 {
				t.Fatalf("printed paths for a refused run: %q", stdout.String())
			}
			if entries, _ := os.ReadDir(out); len(entries) != 0 {
				t.Fatal("wrote files for a refused run")
			}
		})
	}
}

// TestForcedWriteStaysInside keeps a symlink planted in a forced output
// directory from redirecting a write outside it.
func TestForcedWriteStaysInside(t *testing.T) {
	out := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(out, "conf")); err != nil {
		t.Fatal(err)
	}
	files, err := olsweb.Render(olsweb.Server{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writeTree(out, files, true); err == nil {
		t.Fatal("write through a symlink leaving the output directory succeeded")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatal("a file was written outside the output directory")
	}
}
