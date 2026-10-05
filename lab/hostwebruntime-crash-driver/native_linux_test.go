//go:build linux

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
func TestNamespaceEpochAllowsInodeReuseButRejectsRoleAndDuplicate(t *testing.T) {
	in := sample()
	makeRaw := func(stage string, base int) []byte {
		rows := []map[string]any{}
		if stage != "repair_denied" {
			for i, a := range in.Accounts {
				if stage == "selective" && i == 1 {
					continue
				}
				for _, role := range []string{"fpm", "backend"} {
					rows = append(rows, map[string]any{"Role": role, "AccountID": a.ID, "PID": base + len(rows), "Start": "100", "Namespace": 1000 + len(rows)})
				}
			}
		}
		rows = append(rows, map[string]any{"Role": "front", "AccountID": "", "PID": base + len(rows), "Start": "100", "Namespace": 1000 + len(rows)})
		b, _ := json.Marshal(map[string]any{"Processes": rows})
		return b
	}
	var r report
	for i, stage := range []string{"before_kill", "repair_denied", "selective"} {
		if e := collectNamespaces(makeRaw(stage, 100+i*100), stage, in, &r); e != nil {
			t.Fatal(e)
		}
	}
	if len(r.NamespaceEpochs) != 3 || len(r.ObservedNamespaces) != 5 {
		t.Fatal("inode reuse erased an epoch or required nine fresh IDs")
	}
	for _, bad := range []string{"wrong_role", "duplicate_namespace", "duplicate_pid", "noncanonical_start"} {
		var obj map[string][]map[string]any
		_ = json.Unmarshal(makeRaw("before_kill", 100), &obj)
		switch bad {
		case "wrong_role":
			obj["Processes"][0]["Role"] = "backend"
		case "duplicate_namespace":
			obj["Processes"][1]["Namespace"] = obj["Processes"][0]["Namespace"]
		case "duplicate_pid":
			obj["Processes"][1]["PID"] = obj["Processes"][0]["PID"]
		case "noncanonical_start":
			obj["Processes"][0]["Start"] = "0100"
		}
		b, _ := json.Marshal(obj)
		var got report
		if collectNamespaces(b, "before_kill", in, &got) == nil {
			t.Fatal("invalid epoch admitted", bad)
		}
	}
}
func TestNamespaceDrainRequiresMeasuredExtinction(t *testing.T) {
	busy := namespaceScan{Matching: []namespaceMember{{PID: 42, Start: "10", Namespace: 1000}}}
	empty := namespaceScan{Matching: []namespaceMember{}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	n := 0
	r := drainNamespaces(ctx, []uint64{1000}, func([]uint64) namespaceScan {
		n++
		if n == 1 {
			return busy
		}
		return empty
	})
	if !r.Extinct || r.Attempts != 2 || len(r.Initial.Matching) != 1 || len(r.Final.Matching) != 0 {
		t.Fatal("drain did not preserve measured busy-to-empty transition", r)
	}
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	r = drainNamespaces(ctx, []uint64{1000}, func([]uint64) namespaceScan { return busy })
	if r.Extinct || r.Attempts != 1 {
		t.Fatal("cancellation hid surviving namespace", r)
	}
	r = drainNamespaces(ctx, []uint64{1000}, func([]uint64) namespaceScan {
		return namespaceScan{Matching: []namespaceMember{}, Error: "proc_namespace_read", ErrorPID: 42, ErrorErrno: 13}
	})
	if r.Extinct || r.Final.Error == "" {
		t.Fatal("scan error treated as extinction", r)
	}
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
