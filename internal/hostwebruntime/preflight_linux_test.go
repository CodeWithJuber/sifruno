//go:build linux

package hostwebruntime

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Synthetic ELF headers/module/CA bytes test admission and bounded reading only.
// They are never executed and cannot establish real Apache/PHP/TLS readiness.
func installationFixture(t *testing.T) Options {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires isolated Linux root filesystem ownership")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	opts := installationOptions(root, 42)
	opts.Profile.ApacheModuleRoot = filepath.Join(root, "modules")
	opts.Profile.ApacheBinary = filepath.Join(root, "bin/httpd")
	opts.Profile.FPMBinary = filepath.Join(root, "bin/php-fpm")
	for _, dir := range []string{opts.Profile.ManagedRoot, opts.Profile.ManagedHomeRoot, opts.Profile.FrontChroot, opts.Profile.BackendChrootRoot, opts.Profile.RuntimeRoot, opts.Profile.TLSRoot, opts.Profile.ApacheModuleRoot, filepath.Join(root, "bin")} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{opts.Profile.ApacheBinary, opts.Profile.FPMBinary} {
		if err := os.WriteFile(file, []byte("\x7fELFfixture"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"mpm_event", "unixd", "authz_core", "authz_host", "dir", "log_config", "proxy", "proxy_http", "proxy_fcgi", "ssl", "mime"} {
		if err := os.WriteFile(filepath.Join(opts.Profile.ApacheModuleRoot, "mod_"+name+".so"), []byte("fixture module"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(opts.Profile.CAFile, []byte("fixture CA, not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	return opts
}
func installationTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		var sum [32]byte
		if info.Mode().IsRegular() {
			b, e := os.ReadFile(p)
			if e != nil {
				return e
			}
			sum = sha256.Sum256(b)
		}
		out[p] = fmt.Sprintf("%v:%d:%d:%x", info.Mode(), info.Size(), info.ModTime().UnixNano(), sum)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func TestInstallationLinuxReadOnlyAndDigestCompatibility(t *testing.T) {
	opts := installationFixture(t)
	before := installationTree(t, opts.Root)
	var checks []InstallationCheck
	if err := inspectInstallation(context.Background(), opts, func(n string, p bool) { checks = append(checks, InstallationCheck{n, p}) }); err != nil {
		t.Fatal(err)
	}
	if len(checks) != 9 {
		t.Fatalf("checks=%d", len(checks))
	}
	for _, c := range checks {
		if !c.Passed {
			t.Fatal(c)
		}
	}
	value, binaries, err := installationInputDigest(context.Background(), opts.Profile)
	if err != nil || len(value) != 64 || len(binaries) != 2 {
		t.Fatal("digest failed")
	}
	// Independently reconstruct the existing ordered digest contract.
	var parts []string
	for _, p := range []string{opts.Profile.ApacheBinary, opts.Profile.FPMBinary} {
		parts = append(parts, p+":"+hash([]byte("\x7fELFfixture")))
	}
	for _, n := range []string{"mpm_event", "unixd", "authz_core", "authz_host", "dir", "log_config", "proxy", "proxy_http", "proxy_fcgi", "ssl", "mime"} {
		parts = append(parts, n+":"+hash([]byte("fixture module")))
	}
	parts = append(parts, "ca:"+hash([]byte("fixture CA, not a certificate")))
	if value != hash([]byte(strings.Join(parts, "\n"))) {
		t.Fatal("digest contract changed")
	}
	r := &Runtime{opts: opts}
	legacy, e := r.inputDigest()
	if e != nil || legacy != value || !reflect.DeepEqual(r.binaries, binaries) {
		t.Fatal("runtime wrapper changed")
	}
	if !reflect.DeepEqual(before, installationTree(t, opts.Root)) {
		t.Fatal("preflight changed bytes/entries/modes/mtime")
	}
	r.binaries["existing-pin"] = "retained"
	if _, err := r.inputDigest(); err != nil || r.binaries["existing-pin"] != "retained" {
		t.Fatal("existing cache entry lost")
	}
	cached := map[string]string{}
	for p, h := range r.binaries {
		cached[p] = h
	}
	if err := os.WriteFile(opts.Profile.ApacheBinary, []byte("\x7fELFchanged"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(opts.Profile.CAFile); err != nil {
		t.Fatal(err)
	}
	if _, err := r.inputDigest(); err == nil || !reflect.DeepEqual(cached, r.binaries) {
		t.Fatal("failed input admission committed partial cache")
	}

}
func TestInstallationLinuxRefusalAndCancellation(t *testing.T) {
	opts := installationFixture(t)
	if err := os.Chmod(opts.Profile.ManagedRoot, 0755); err != nil {
		t.Fatal(err)
	}
	before := installationTree(t, opts.Root)
	if inspectInstallation(context.Background(), opts, func(string, bool) {}) == nil {
		t.Fatal("nonprivate managed accepted")
	}
	if !reflect.DeepEqual(before, installationTree(t, opts.Root)) {
		t.Fatal("refusal changed tree")
	}
	if err := os.Chmod(opts.Profile.ManagedRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(opts.Profile.CAFile, 0666); err != nil {
		t.Fatal(err)
	}
	if _, _, err := installationInputDigest(context.Background(), opts.Profile); err == nil {
		t.Fatal("writable CA accepted")
	}
	if err := os.Chmod(opts.Profile.CAFile, 0600); err != nil {
		t.Fatal(err)
	}
	for _, after := range []int{1, 2, 3, 5, 14, 15, 16} {
		ctx := &installationCountingContext{Context: context.Background(), after: after}
		value, binaries, err := installationInputDigest(ctx, opts.Profile)
		if !errors.Is(err, context.Canceled) || value != "" || binaries != nil {
			t.Fatalf("partial result after refusal/cancel %d", after)
		}
	}
}

type installationCountingContext struct {
	context.Context
	calls, after int
}

func (c *installationCountingContext) Err() error {
	c.calls++
	if c.calls >= c.after {
		return context.Canceled
	}
	return nil
}

func TestInstallationLinuxRejectsLinksAndMissingInputs(t *testing.T) {
	for _, mode := range []string{"symlink", "hardlink", "missing", "bad_elf"} {
		t.Run(mode, func(t *testing.T) {
			opts := installationFixture(t)
			target := opts.Profile.ApacheBinary
			switch mode {
			case "symlink":
				if err := os.Remove(target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(opts.Profile.FPMBinary, target); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Remove(target); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(opts.Profile.FPMBinary, target); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(opts.Profile.CAFile); err != nil {
					t.Fatal(err)
				}
			case "bad_elf":
				if err := os.WriteFile(target, []byte("not ELF"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := installationInputDigest(context.Background(), opts.Profile); err == nil {
				t.Fatal("untrusted input admitted")
			}
		})
	}
}
