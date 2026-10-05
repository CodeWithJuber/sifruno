package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sifruno/internal/hostaccounts"
)

func sample() fixtureInput {
	in := fixtureInput{SchemaVersion: 1, FixtureOnly: true, RunID: strings.Repeat("a", 32), Root: fixtureRoot, Profile: fixedProfile()}
	for i, user := range []string{"webalpha", "webbravo"} {
		in.Accounts = append(in.Accounts, hostaccounts.Account{ID: strings.Repeat(string(rune('a'+i)), 32), Username: user, Domain: []string{"alpha.test", "bravo.test"}[i], Home: fixtureRoot + "/homes/" + user, PublicHTML: fixtureRoot + "/homes/" + user + "/public_html", State: "active", UID: 20001 + i, GID: 20001 + i, Revision: 1, CreatedAt: time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC), UpdatedAt: time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)})
	}
	return in
}
func inputBytes(t *testing.T, in fixtureInput) []byte {
	t.Helper()
	b, e := json.Marshal(in)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestStrictInput(t *testing.T) {
	b := inputBytes(t, sample())
	if _, e := parseInput(b); e != nil {
		t.Fatal(e)
	}
	bad := [][]byte{bytes.Replace(b, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1), bytes.Replace(b, []byte(`"ManagedRoot"`), []byte(`"managedroot"`), 1), bytes.Replace(b, []byte(`"uid":20001`), []byte(`"uid":20001,"UID":20001`), 1), append(append([]byte{}, b...), []byte(` {}`)...), append([]byte(`{"unknown":1,`), b[1:]...), bytes.Repeat([]byte(" "), inputLimit+1)}
	for i, b := range bad {
		if _, e := parseInput(b); e == nil {
			t.Fatalf("invalid JSON %d admitted", i)
		}
	}
	for name, mutate := range map[string]func(*fixtureInput){"foreign root": func(in *fixtureInput) { in.Root = "/tmp/other" }, "binary": func(in *fixtureInput) { in.Profile.ApacheBinary = "/bin/echo" }, "public listener": func(in *fixtureInput) { in.Profile.FrontendIP = "0.0.0.0" }, "port": func(in *fixtureInput) { in.Profile.FrontendPort = 18080 }, "home": func(in *fixtureInput) { in.Accounts[0].Home = "/etc" }, "UID": func(in *fixtureInput) { in.Accounts[0].UID = 0 }, "state": func(in *fixtureInput) { in.Accounts[0].State = "suspended" }, "order": func(in *fixtureInput) { in.Accounts[0], in.Accounts[1] = in.Accounts[1], in.Accounts[0] }, "revision": func(in *fixtureInput) { in.Accounts[0].Revision = 0 }, "fixture flag": func(in *fixtureInput) { in.FixtureOnly = false }, "run ID": func(in *fixtureInput) { in.RunID = "../../x" }} {
		t.Run(name, func(t *testing.T) {
			in := sample()
			mutate(&in)
			if _, e := parseInput(inputBytes(t, in)); e == nil {
				t.Fatal("bad contract admitted")
			}
		})
	}
}
func TestCLIExact(t *testing.T) {
	if arguments([]string{"--input", inputPath}) != nil {
		t.Fatal("valid args")
	}
	for _, a := range [][]string{nil, {"--input", "/tmp/input"}, {"--input", inputPath, "--input", inputPath}, {"--report", inputPath}, {"--input=" + inputPath}} {
		if arguments(a) == nil {
			t.Fatal("unbounded args admitted")
		}
	}
}
func TestGenerationSnapshotAndCopy(t *testing.T) {
	in := sample()
	g, e := generation(in, "", true)
	if e != nil {
		t.Fatal(e)
	}
	active, e := generation(in, strings.Repeat("c", 32), false)
	if e != nil {
		t.Fatal(e)
	}
	if g.ID != "" || !g.Denied || g.SnapshotSHA256 != active.SnapshotSHA256 || g.Bundle.SHA256 == active.Bundle.SHA256 || g.Accounts[0].State != "active" {
		t.Fatal("bootstrap does not retain original snapshot")
	}
	in.Accounts[0].State = "suspended"
	if g.Accounts[0].State != "active" {
		t.Fatal("alias")
	}
	in.Accounts[0].Revision++
	s, e := generation(in, strings.Repeat("d", 32), true)
	if e != nil {
		t.Fatal(e)
	}
	if s.SnapshotSHA256 == g.SnapshotSHA256 {
		t.Fatal("revision/state change lost")
	}
}
func TestPHPCoreContract(t *testing.T) {
	a := sample().Accounts[0]
	good := []byte("SIFRUNO_PHP_webalpha\nSELF=readable\nHOST=denied\nSIBLING=denied\nPID=7\n")
	p, e := phpBody(good, a)
	if e != nil || p.PID != 7 {
		t.Fatal("good core output rejected")
	}
	for _, b := range [][]byte{bytes.Replace(good, []byte("HOST=denied"), []byte("HOST=readable"), 1), bytes.Replace(good, []byte("SIBLING=denied"), []byte("SIBLING=readable"), 1), bytes.Replace(good, []byte("PID=7"), []byte("PID=1"), 1), bytes.Replace(good, []byte("PID=7"), []byte("PID=007"), 1), append(append([]byte{}, good...), []byte("UID=20001\n")...), bytes.ReplaceAll(good, []byte("\n"), []byte(`\n`)), []byte("SIFRUNO_PHP_webalpha"), bytes.Repeat([]byte("x"), 2049)} {
		if _, e := phpBody(b, a); e == nil {
			t.Fatal("unsafe or malformed probe admitted")
		}
	}
	if _, e := phpBody(good, sample().Accounts[1]); e == nil {
		t.Fatal("wrong tenant marker admitted")
	}
}
func TestClientNoProxyRedirectBound(t *testing.T) {
	c := servingClient()
	if c.Timeout != 2*time.Second || c.CheckRedirect(nil, nil) == nil {
		t.Fatal("client contract changed")
	}
}

func TestClientActuallyRefusesRedirect(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.Write([]byte("unexpected")) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer redirect.Close()
	c := servingClient()
	defer c.CloseIdleConnections()
	r, e := c.Get(redirect.URL)
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode != 302 || hits.Load() != 0 {
		t.Fatal("redirect followed")
	}
}
