//go:build linux

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func ownedTemp(t *testing.T) (string, int) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root filesystem admission required")
	}
	root := t.TempDir()
	if os.Chmod(root, 0700) != nil {
		t.Fatal("chmod")
	}
	fd, e := openRoot(root)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return root, fd
}
func TestOwnedInputRejectLinksModesAndEscape(t *testing.T) {
	root, fd := ownedTemp(t)
	p := filepath.Join(root, "input.json")
	if os.WriteFile(p, []byte("{}"), 0600) != nil {
		t.Fatal("write")
	}
	if _, e := readOwned(fd, "input.json", 0600, 32); e != nil {
		t.Fatal(e)
	}
	if os.Link(p, filepath.Join(root, "hard")) != nil {
		t.Fatal("link")
	}
	if _, e := readOwned(fd, "input.json", 0600, 32); e == nil {
		t.Fatal("hardlink admitted")
	}
	os.Remove(filepath.Join(root, "hard"))
	os.Chmod(p, 0644)
	if _, e := readOwned(fd, "input.json", 0600, 32); e == nil {
		t.Fatal("mode admitted")
	}
	if os.Symlink(p, filepath.Join(root, "symbolic")) != nil {
		t.Fatal("symlink")
	}
	if _, e := readOwned(fd, "symbolic", 0644, 32); e == nil {
		t.Fatal("symlink admitted")
	}
	if _, e := readOwned(fd, "../outside", 0600, 32); e == nil {
		t.Fatal("escape admitted")
	}
}
func TestReportExclusiveBoundedJSON(t *testing.T) {
	root, fd := ownedTemp(t)
	r := report{SchemaVersion: 1, Stage: "complete", Passed: true}
	if e := writeReport(fd, r); e != nil {
		t.Fatal(e)
	}
	b, e := readOwned(fd, "qualification-report.json", 0600, reportLimit)
	if e != nil {
		t.Fatal(e)
	}
	var got report
	if json.Unmarshal(b, &got) != nil || got.Stage != "complete" {
		t.Fatal("not JSON")
	}
	if writeReport(fd, r) == nil {
		t.Fatal("overwrote report")
	}
	os.Remove(filepath.Join(root, "qualification-report.json"))
	r.Stage = strings.Repeat("x", reportLimit)
	if writeReport(fd, r) == nil {
		t.Fatal("oversize accepted")
	}
	if _, e := os.Stat(filepath.Join(root, "qualification-report.json")); !os.IsNotExist(e) {
		t.Fatal("oversize wrote file")
	}
}
func TestProcessStartIgnoresMutableCounters(t *testing.T) {
	f := make([]string, 25)
	for i := range f {
		f[i] = "0"
	}
	f[19] = "123"
	a := []byte("123 (php worker) " + strings.Join(f, " "))
	s, e := processStart(a)
	if e != nil || s != "123" {
		t.Fatal(e)
	}
	f[10] = "999"
	if s2, e := processStart([]byte("123 (php worker) " + strings.Join(f, " "))); e != nil || s2 != s {
		t.Fatal("counter drift changed identity")
	}
	if _, e := processStart([]byte("bad")); e == nil {
		t.Fatal("bad stat admitted")
	}
}
