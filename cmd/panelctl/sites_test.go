package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sifruno/internal/api"
	"sifruno/internal/operator"
	"sifruno/internal/sites"
	"sifruno/internal/trail"
)

func TestSitesCLIAuthenticatedRecoveryAndPersistence(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	journal, err := trail.Open(filepath.Join(state, "trail"))
	if err != nil {
		t.Fatal(err)
	}
	op, err := operator.Open(filepath.Join(state, "operator"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := sites.Open(filepath.Join(state, "sites"), journal)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { store.Close() }()
	start := func() *httptest.Server {
		listener, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		base := "http://" + listener.Addr().String()
		s := httptest.NewUnstartedServer(api.New(api.Options{Sites: store, Operator: op, AllowedOrigins: []string{base}}))
		s.Listener = listener
		s.Start()
		return s
	}
	server := start()
	defer func() { server.Close() }()
	call := func(arguments ...string) json.RawMessage {
		t.Helper()
		var out, errs bytes.Buffer
		args := append([]string{"--state", state, "--panel-url", server.URL, "sites"}, arguments...)
		if e := run(args, &out, &errs); e != nil {
			t.Fatal(e, errs.String())
		}
		if !json.Valid(out.Bytes()) {
			t.Fatal("invalid CLI JSON")
		}
		key, e := readOperatorKey(state)
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(out.String()+errs.String(), key) || strings.Contains(out.String(), "csrf_token") {
			t.Fatal("credential emitted by CLI")
		}
		return append(json.RawMessage{}, out.Bytes()...)
	}
	var site sites.Site
	if err = json.Unmarshal(call("create", "--name", "CLI fixture", "--domain", "cli-fixture.example"), &site); err != nil {
		t.Fatal(err)
	}
	var original sites.FileContent
	if err = json.Unmarshal(call("read", "--id", site.ID, "--path", "index.html"), &original); err != nil {
		t.Fatal(err)
	}
	content := "<!doctype html><title>Fixture</title><p>Saved before backup</p>"
	input := filepath.Join(t.TempDir(), "page.html")
	if err = os.WriteFile(input, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(call("write", "--id", site.ID, "--path", "index.html", "--from", input, "--revision", fmt.Sprint(original.Revision), "--sha256", original.SHA256), &site); err != nil {
		t.Fatal(err)
	}
	var backup sites.BackupInfo
	if err = json.Unmarshal(call("backup", "--id", site.ID, "--revision", fmt.Sprint(site.Revision)), &backup); err != nil {
		t.Fatal(err)
	}
	var saved sites.FileContent
	json.Unmarshal(call("read", "--id", site.ID, "--path", "index.html"), &saved)
	os.WriteFile(input, []byte("<p>Changed after backup</p>"), 0600)
	json.Unmarshal(call("write", "--id", site.ID, "--path", "index.html", "--from", input, "--revision", fmt.Sprint(saved.Revision), "--sha256", saved.SHA256), &site)
	json.Unmarshal(call("restore", "--id", site.ID, "--backup", backup.ID, "--revision", fmt.Sprint(site.Revision)), &site)
	var restored sites.FileContent
	json.Unmarshal(call("read", "--id", site.ID, "--path", "index.html"), &restored)
	if restored.Content != content {
		t.Fatal("actual restored bytes mismatch")
	}
	var output, errorsOut bytes.Buffer
	if run([]string{"--state", state, "--panel-url", server.URL, "sites", "write", "--id", site.ID, "--path", "index.html", "--from", input, "--revision", fmt.Sprint(saved.Revision), "--sha256", saved.SHA256}, &output, &errorsOut) == nil {
		t.Fatal("stale CLI update succeeded")
	}
	public := httptest.NewServer(store.Handler())
	checkPreview := func(wantActive bool) {
		t.Helper()
		req, e := http.NewRequest(http.MethodGet, public.URL+"/", nil)
		if e != nil {
			t.Fatal(e)
		}
		req.Host = site.PreviewHost
		resp, e := http.DefaultClient.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		if (resp.StatusCode == http.StatusOK) != wantActive {
			t.Fatal("website suspension serving mismatch", resp.StatusCode)
		}
	}
	checkPreview(true)
	json.Unmarshal(call("state", "--id", site.ID, "--state", "suspended", "--revision", fmt.Sprint(site.Revision)), &site)
	checkPreview(false)
	json.Unmarshal(call("state", "--id", site.ID, "--state", "active", "--revision", fmt.Sprint(site.Revision)), &site)
	checkPreview(true)
	public.Close()
	server.Close()
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = sites.Open(filepath.Join(state, "sites"), journal)
	if err != nil {
		t.Fatal(err)
	}
	server = start()
	json.Unmarshal(call("read", "--id", site.ID, "--path", "index.html"), &restored)
	if restored.Content != content {
		t.Fatal("website content did not persist across restart")
	}
	call("backups", "--id", site.ID)
}

func TestSiteClientRefusesRemoteDestinationsAndRedirects(t *testing.T) {
	for _, u := range []string{"https://example.com:443", "http://localhost:8080", "http://203.0.113.30:8081", "http://127.0.0.1:8080/api", "http://user@127.0.0.1:8080", "http://127.0.0.1:8080?secret=x", "http://127.0.0.1:8080#x"} {
		if _, e := newSiteClient(u); e == nil {
			t.Fatal("unsafe destination accepted")
		}
	}
	var redirected bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected = true; w.Write([]byte("{}")) }))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	c, e := newSiteClient(source.URL)
	if e != nil {
		t.Fatal(e)
	}
	if c.login("synthetic-test-key-which-is-not-an-operator-secret") == nil || redirected {
		t.Fatal("login followed redirect")
	}
}
