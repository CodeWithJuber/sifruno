package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

// migrateSite serves a two-page site with one password-protected and one
// denied location. broken makes /about/ answer 500.
func migrateSite(t *testing.T, broken bool, requests *atomic.Int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests != nil {
			requests.Add(1)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch r.URL.Path {
		case "/":
			_, _ = io.WriteString(w, `<html><head><title>Home</title></head><body><a href="/about/">About</a></body></html>`)
		case "/about/":
			if broken {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_, _ = io.WriteString(w, `<html><head><title>About</title></head><body>About us</body></html>`)
		case "/private/":
			w.Header().Set("WWW-Authenticate", `Basic realm="Private"`)
			w.WriteHeader(http.StatusUnauthorized)
		case "/wp-config.php":
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestMigrateVerifyExitCodes(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	oldURL := migrateSite(t, false, nil).URL
	goodURL := migrateSite(t, false, nil).URL
	brokenURL := migrateSite(t, true, nil).URL
	cases := []struct {
		name   string
		args   []string
		code   int
		output string
	}{
		{"gate open", []string{"migrate", "verify", "--old", oldURL, "--new", goodURL, "--probe", "auth:/private/"}, 0, "CUTOVER ALLOWED: every compared page and closed URL matches the old site"},
		{"gate closed", []string{"migrate", "verify", "--old", oldURL, "--new", brokenURL}, migrateGateClosedExit, "CUTOVER LOCKED: 1 failed check(s)"},
		{"usage error", []string{"migrate", "verify", "--old", oldURL}, 1, "usage: panelctl migrate verify"},
	}
	for _, c := range cases {
		raw, err := json.Marshal(c.args)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(exe, "-test.run=^TestMigrateHelperProcess$", "-test.timeout=60s")
		cmd.Env = append(os.Environ(), "SIFRUNO_MIGRATE_HELPER_ARGS="+string(raw))
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err = cmd.Run()
		code := 0
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		if code != c.code || !strings.Contains(stdout.String()+stderr.String(), c.output) {
			t.Fatalf("%s: exit %d, want %d\nstdout:\n%s\nstderr:\n%s", c.name, code, c.code, stdout.String(), stderr.String())
		}
	}
}

// TestMigrateHelperProcess runs the real main so the process exit status is
// observed rather than inferred.
func TestMigrateHelperProcess(t *testing.T) {
	raw := os.Getenv("SIFRUNO_MIGRATE_HELPER_ARGS")
	if raw == "" {
		t.Skip("helper invoked only by TestMigrateVerifyExitCodes")
	}
	var args []string
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		t.Fatal(err)
	}
	os.Args = append([]string{"panelctl"}, args...)
	main()
	os.Exit(0)
}

func TestMigrateVerifyReportFile(t *testing.T) {
	var requests atomic.Int64
	oldURL := migrateSite(t, false, &requests).URL
	newURL := migrateSite(t, false, nil).URL
	path := filepath.Join(t.TempDir(), "report.json")
	args := []string{"verify", "--old", oldURL, "--new", newURL, "--json", "--out", path}
	var out, errs bytes.Buffer
	allowed, err := migrateVerify(context.Background(), args, &out, &errs)
	if err != nil || !allowed {
		t.Fatalf("verify: %v allowed=%v %s", err, allowed, errs.String())
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(written, out.Bytes()) {
		t.Fatal("--json output and --out report differ")
	}
	var report map[string]any
	if err = json.Unmarshal(written, &report); err != nil || report["cutover_allowed"] != true {
		t.Fatalf("report %v %s", err, written)
	}
	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(path)
		if statErr != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("report mode %v %v", info.Mode(), statErr)
		}
	}

	before := requests.Load()
	out.Reset()
	allowed, err = migrateVerify(context.Background(), args, &out, &errs)
	if err == nil || allowed || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("existing report overwritten: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, written) {
		t.Fatal("refused run changed the existing report")
	}
	if requests.Load() != before || out.Len() != 0 {
		t.Fatal("refused run still contacted the old site or printed a report")
	}

	failed := filepath.Join(t.TempDir(), "failed.json")
	if _, err = migrateVerify(context.Background(), []string{"verify", "--old", oldURL, "--new", oldURL, "--out", failed}, &out, &errs); err == nil {
		t.Fatal("same old and new origin accepted")
	}
	if _, err = os.Lstat(failed); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unfinished report left behind: %v", err)
	}
}

func TestMigrateVerifyGateClosedStillWritesReport(t *testing.T) {
	oldURL := migrateSite(t, false, nil).URL
	brokenURL := migrateSite(t, true, nil).URL
	path := filepath.Join(t.TempDir(), "locked.json")
	var out, errs bytes.Buffer
	allowed, err := migrateVerify(context.Background(), []string{"verify", "--old", oldURL, "--new", brokenURL, "--out", path}, &out, &errs)
	if err != nil || allowed {
		t.Fatalf("broken copy: %v allowed=%v", err, allowed)
	}
	if !strings.HasPrefix(out.String(), "CUTOVER LOCKED: 1 failed check(s)\nFAIL page /about/: status 200 → 500\n") {
		t.Fatalf("text report:\n%s", out.String())
	}
	raw, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(raw), `"cutover_allowed": false`) {
		t.Fatalf("locked report %v %s", err, raw)
	}
}

func TestMigrateVerifyProbes(t *testing.T) {
	oldURL := migrateSite(t, false, nil).URL
	newURL := migrateSite(t, false, nil).URL
	dir := t.TempDir()
	probes := filepath.Join(dir, "probes.json")
	content := `[{"path": "/private/", "kind": "auth", "rule": ".htaccess:3 AuthType Basic"}, {"path": "/wp-config.php", "kind": "deny"}]`
	if err := os.WriteFile(probes, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	allowed, err := migrateVerify(context.Background(), []string{"verify", "--old", oldURL, "--new", newURL, "--probe", "deny:/wp-config.php", "--probes-file", probes, "--json"}, &out, &errs)
	if err != nil || !allowed {
		t.Fatalf("probes: %v allowed=%v", err, allowed)
	}
	var report struct {
		Probes []struct {
			Path string `json:"path"`
			Kind string `json:"kind"`
			Code string `json:"code"`
		} `json:"probes"`
	}
	if err = json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Probes) != 2 || report.Probes[0].Path != "/wp-config.php" || report.Probes[1].Kind != "auth" || report.Probes[1].Code != "ok" {
		t.Fatalf("probes %+v", report.Probes)
	}

	bad := filepath.Join(dir, "bad.json")
	if err = os.WriteFile(bad, []byte(`{"path": "/x", "kind": "auth"}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"verify", "--old", oldURL, "--new", newURL, "--probes-file", bad},
		{"verify", "--old", oldURL, "--new", newURL, "--probe", "/private/"},
		{"verify", "--old", oldURL, "--new", newURL, "--probe", "open:/private/"},
		{"verify", "--old", oldURL, "--new", newURL, "--pages", "0"},
		{"check", "--old", oldURL, "--new", newURL},
	} {
		if _, err = migrateVerify(context.Background(), args, &out, &errs); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
