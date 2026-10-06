package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"sifruno/internal/api"
	"sifruno/internal/operator"
	"sifruno/internal/sites"
	"sifruno/internal/trail"
)

func TestRestorePreviewCLIActualAuthenticatedHTTP(t *testing.T) {
	state := filepath.Join(t.TempDir(), "isolated-state")
	j, err := trail.Open(filepath.Join(state, "trail"))
	if err != nil {
		t.Fatal(err)
	}
	op, err := operator.Open(filepath.Join(state, "operator"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := sites.Open(filepath.Join(state, "sites"), j)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	site, err := s.Create(sites.CreateInput{Name: "CLI preview", Domain: "cli-preview.test"}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Backup(site.ID, site.Revision, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	site, err = s.Get(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	f, err := s.ReadFile(site.ID, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	site, err = s.WriteFile(site.ID, sites.WriteInput{Path: "index.html", Content: "actual current edited HTML", ExpectedSHA256: f.SHA256, ExpectedRevision: site.Revision}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + listener.Addr().String()
	server := httptest.NewUnstartedServer(api.New(api.Options{Sites: s, Operator: op, AllowedOrigins: []string{base}}))
	server.Listener = listener
	server.Start()
	defer server.Close()
	before, err := j.List()
	if err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	args := []string{"--state", state, "--panel-url", base, "sites", "restore-preview", "--id", site.ID, "--backup", b.ID, "--revision", fmt.Sprint(site.Revision)}
	if err = run(args, &out, &errs); err != nil {
		t.Fatal(err)
	}
	var p sites.RestorePreview
	if json.Unmarshal(out.Bytes(), &p) != nil || p.SiteID != site.ID || p.CurrentRevision != site.Revision || p.BackupID != b.ID || p.BackupSHA256 != b.SHA256 || p.Counts != (sites.RestorePreviewCounts{Modified: 1}) || len(p.Files) != 1 || p.Files[0].Before.SHA256 == p.Files[0].After.SHA256 {
		t.Fatal("CLI did not deliver actual verified HTTP diff")
	}
	key, err := readOperatorKey(state)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String()+errs.String(), key) || strings.Contains(out.String(), "csrf_token") || strings.Contains(out.String(), state) || strings.Contains(out.String(), "actual current edited HTML") {
		t.Fatal("CLI emitted sensitive content")
	}
	after, err := j.List()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("CLI preview changed trail")
	}
	siteAfter, err := s.Get(site.ID)
	if err != nil || siteAfter != site {
		t.Fatal("CLI preview changed site")
	}
	fAfter, err := s.ReadFile(site.ID, "index.html")
	if err != nil || fAfter.Content != "actual current edited HTML" {
		t.Fatal("CLI preview changed current content")
	}
	out.Reset()
	errs.Reset()
	args[len(args)-1] = fmt.Sprint(site.Revision - 1)
	if err = run(args, &out, &errs); err == nil || !strings.Contains(err.Error(), "HTTP 409") || out.Len() != 0 {
		t.Fatal("CLI accepted stale preview", err)
	}
}

func TestRestorePreviewCLIRejectsInvalidInputsBeforeCredentials(t *testing.T) {
	id, backup := strings.Repeat("a", 32), strings.Repeat("b", 32)
	for _, flags := range [][]string{
		{}, {"--id", id, "--backup", backup}, {"--id", id, "--backup", backup, "--revision", "0"},
		{"--id", id, "--backup", backup, "--revision", "9007199254740992"},
		{"--id", strings.ToUpper(id), "--backup", backup, "--revision", "1"},
		{"--id", id, "--backup", "wrong", "--revision", "1"},
	} {
		var out, errs bytes.Buffer
		args := append([]string{"restore-preview"}, flags...)
		err := runSites(args, filepath.Join(t.TempDir(), "absent-state"), "http://127.0.0.1:1", &out, &errs)
		if err == nil || strings.Contains(err.Error(), "access key") || out.Len() != 0 {
			t.Fatal("invalid CLI input reached credential read", err)
		}
	}
	if !strings.Contains(usage, "sites restore-preview --id ID --backup ID --revision N") {
		t.Fatal("CLI help missing preview")
	}
}
