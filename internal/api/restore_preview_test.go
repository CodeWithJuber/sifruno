package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"sifruno/internal/sites"
)

func previewAPIFixture(t *testing.T) (siteFixture, sites.Site, sites.BackupInfo) {
	t.Helper()
	f := websiteFixture(t)
	s, err := f.store.Create(sites.CreateInput{Name: "Preview fixture", Domain: "preview.test"}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.store.Backup(s.ID, s.Revision, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	s, err = f.store.Get(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	return f, s, b
}

type previewUnreadBody struct{ reads int }

func (b *previewUnreadBody) Read([]byte) (int, error) { b.reads++; return 0, io.ErrUnexpectedEOF }
func (*previewUnreadBody) Close() error               { return nil }

func TestRestorePreviewAdmissionBeforeBody(t *testing.T) {
	f, s, _ := previewAPIFixture(t)
	c, csrf := websiteSignIn(t, f)
	for _, mode := range []string{"session", "csrf", "origin", "empty-origin", "host", "remote", "fetch"} {
		t.Run(mode, func(t *testing.T) {
			r := httptest.NewRequest("POST", "http://127.0.0.1:8080/api/v1/sites/"+s.ID+"/restore-preview", nil)
			r.RemoteAddr = "127.0.0.1:15000"
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", "http://127.0.0.1:8080")
			r.Header.Set("X-CSRF-Token", csrf)
			if mode != "session" {
				r.AddCookie(c)
			}
			switch mode {
			case "csrf":
				r.Header.Del("X-CSRF-Token")
			case "origin":
				r.Header.Set("Origin", "http://evil.invalid")
			case "empty-origin":
				r.Header.Del("Origin")
			case "host":
				r.Host = "evil.invalid"
			case "remote":
				r.RemoteAddr = "192.0.2.9:15000"
			case "fetch":
				r.Header.Set("Sec-Fetch-Site", "cross-site")
			}
			body := &previewUnreadBody{}
			r.Body = body
			r.ContentLength = 4097
			w := httptest.NewRecorder()
			f.handler.ServeHTTP(w, r)
			want := 403
			if mode == "session" {
				want = 401
			}
			if w.Code != want || body.reads != 0 {
				t.Fatalf("admission status=%d body reads=%d", w.Code, body.reads)
			}
		})
	}
}

func TestRestorePreviewStrictJSONAndActualDTO(t *testing.T) {
	f, s, b := previewAPIFixture(t)
	c, csrf := websiteSignIn(t, f)
	endpoint := "/api/v1/sites/" + s.ID + "/restore-preview"
	valid := fmt.Sprintf(`{"backup_id":%q,"expected_revision":%d}`, b.ID, s.Revision)
	for _, raw := range []string{"", "null", "[]", "{}", `{broken`, fmt.Sprintf(`{"backup_id":%q}`, b.ID), fmt.Sprintf(`{"expected_revision":%d}`, s.Revision), fmt.Sprintf(`{"backup_id":null,"expected_revision":%d}`, s.Revision), fmt.Sprintf(`{"backup_id":%q,"expected_revision":null}`, b.ID), fmt.Sprintf(`{"BACKUP_ID":%q,"expected_revision":%d}`, b.ID, s.Revision), fmt.Sprintf(`{"backup_id":%q,"Expected_Revision":%d}`, b.ID, s.Revision), fmt.Sprintf(`{"backup_id":%q,"backup_id":%q,"expected_revision":%d}`, b.ID, b.ID, s.Revision), fmt.Sprintf(`{"backup_id":%q,"expected_revision":%d,"expected_revision":%d}`, b.ID, s.Revision, s.Revision), strings.TrimSuffix(valid, "}") + `,"extra":"private-secret"}`, valid + ` {}`, fmt.Sprintf(`{"backup_id":%q,"expected_revision":"2"}`, b.ID)} {
		w := websiteRequest(f.handler, "POST", endpoint, raw, c, csrf)
		if w.Code != 400 || strings.Contains(w.Body.String(), "private-secret") {
			t.Fatalf("strict JSON rejection status=%d", w.Code)
		}
	}
	for _, input := range []sites.RestoreInput{{BackupID: b.ID, ExpectedRevision: 0}, {BackupID: b.ID, ExpectedRevision: 9007199254740992}, {BackupID: "../unsafe", ExpectedRevision: s.Revision}} {
		if w := websiteRequest(f.handler, "POST", endpoint, input, c, csrf); w.Code != 422 {
			t.Fatalf("invalid semantic input status %d", w.Code)
		}
	}
	if w := websiteRequest(f.handler, "POST", endpoint, sites.RestoreInput{BackupID: b.ID, ExpectedRevision: s.Revision - 1}, c, csrf); w.Code != 409 {
		t.Fatal("stale preview accepted")
	}
	if w := websiteRequest(f.handler, "POST", endpoint, sites.RestoreInput{BackupID: strings.Repeat("a", 32), ExpectedRevision: s.Revision}, c, csrf); w.Code != 404 {
		t.Fatal("missing backup status", w.Code)
	}
	if w := websiteRequest(f.handler, "POST", "/api/v1/sites/invalid/restore-preview", sites.RestoreInput{BackupID: b.ID, ExpectedRevision: s.Revision}, c, csrf); w.Code != 422 {
		t.Fatal("invalid ID status", w.Code)
	}
	other, err := f.store.Create(sites.CreateInput{Name: "Other", Domain: "other-preview.test"}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	if w := websiteRequest(f.handler, "POST", "/api/v1/sites/"+other.ID+"/restore-preview", sites.RestoreInput{BackupID: b.ID, ExpectedRevision: other.Revision}, c, csrf); w.Code != 404 {
		t.Fatal("different-site archive accepted")
	}
	for _, pad := range []int{4096, 4097} {
		w := websiteRequest(f.handler, "POST", endpoint, valid+strings.Repeat(" ", pad-len(valid)), c, csrf)
		want := 200
		if pad == 4097 {
			want = 413
		}
		if w.Code != want {
			t.Fatal("4 KiB boundary", pad, w.Code)
		}
	}
	journalBefore, err := f.journal.List()
	if err != nil {
		t.Fatal(err)
	}
	w := websiteRequest(f.handler, "POST", endpoint, valid, c, csrf)
	var p sites.RestorePreview
	var fields map[string]json.RawMessage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &p) != nil || json.Unmarshal(w.Body.Bytes(), &fields) != nil || len(fields) != 7 || fields["$schema"] != nil || w.Header().Get("Link") != "" {
		t.Fatal("raw exact DTO response", w.Code)
	}
	if p.SiteID != s.ID || p.CurrentRevision != s.Revision || p.BackupSHA256 != b.SHA256 || p.BackupRevision != b.Revision || len(p.Files) != 1 || p.Counts != (sites.RestorePreviewCounts{Unchanged: 1}) {
		t.Fatalf("incorrect actual preview %+v", p)
	}
	sAfter, err := f.store.Get(s.ID)
	if err != nil || sAfter != s {
		t.Fatal("preview changed site metadata")
	}
	journalAfter, err := f.journal.List()
	if err != nil || !reflect.DeepEqual(journalBefore, journalAfter) {
		t.Fatal("preview changed trail")
	}
	if strings.Contains(w.Body.String(), f.key) || strings.Contains(w.Body.String(), csrf) || strings.Contains(w.Body.String(), "content\"") {
		t.Fatal("preview exposed sensitive content")
	}
	if w := websiteRequest(f.handler, "GET", endpoint, nil, c, ""); w.Code != 404 {
		t.Fatal("unexpected preview method enabled", w.Code)
	}
}

func TestRestorePreviewStorageFailureSanitized(t *testing.T) {
	f, s, b := previewAPIFixture(t)
	c, csrf := websiteSignIn(t, f)
	// AccessKeyPath locates only this newly generated isolated fixture state.
	root := filepath.Dir(filepath.Dir(f.manager.AccessKeyPath()))
	content := filepath.Join(root, "sites", "data", s.ID, "content", "index.html")
	original, err := os.ReadFile(content)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(content, []byte("external private-secret edit"), 0600); err != nil {
		t.Fatal(err)
	}
	endpoint := "/api/v1/sites/" + s.ID + "/restore-preview"
	w := websiteRequest(f.handler, "POST", endpoint, sites.RestoreInput{BackupID: b.ID, ExpectedRevision: s.Revision}, c, csrf)
	if w.Code != 409 || strings.Contains(w.Body.String(), "private-secret") {
		t.Fatal("content mismatch did not fail closed", w.Code)
	}
	if err = os.WriteFile(content, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "sites", "data", s.ID, "backups", b.ID+".zip"), []byte("private-secret corrupt archive"), 0600); err != nil {
		t.Fatal(err)
	}
	w = websiteRequest(f.handler, "POST", endpoint, sites.RestoreInput{BackupID: b.ID, ExpectedRevision: s.Revision}, c, csrf)
	if w.Code != 503 || strings.Contains(w.Body.String(), "private-secret") || strings.Contains(w.Body.String(), root) {
		t.Fatal("corrupt archive response", w.Code)
	}
}

func TestRestorePreviewOpenAPIContract(t *testing.T) {
	f := websiteFixture(t)
	w := websiteRequest(f.handler, "GET", "/openapi.json", nil, nil, "")
	var spec struct {
		Paths map[string]struct {
			Post struct {
				Security   []map[string][]string `json:"security"`
				Parameters []struct {
					Name     string
					Required bool
				} `json:"parameters"`
				RequestBody struct {
					Required bool
					Content  map[string]struct{ Schema map[string]any }
				} `json:"requestBody"`
				Responses map[string]json.RawMessage `json:"responses"`
			}
		}
		Components struct {
			Schemas map[string]struct {
				Type                 string
				Required             []string
				AdditionalProperties bool `json:"additionalProperties"`
				Properties           map[string]map[string]any
			}
		}
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &spec) != nil {
		t.Fatal("OpenAPI unavailable")
	}
	op := spec.Paths["/api/v1/sites/{id}/restore-preview"].Post
	if len(op.Security) != 1 || op.Security[0]["operatorSession"] == nil || op.Security[0]["sessionCSRF"] == nil || !op.RequestBody.Required || op.RequestBody.Content["application/json"].Schema["$ref"] != "#/components/schemas/NativeRestorePreviewInput" {
		t.Fatal("missing auth/input contract")
	}
	for _, code := range []string{"200", "400", "401", "403", "404", "409", "413", "415", "422", "503"} {
		if op.Responses[code] == nil {
			t.Fatal("undocumented status", code)
		}
	}
	for _, name := range []string{"id", "Origin", "X-CSRF-Token"} {
		found := false
		for _, p := range op.Parameters {
			if p.Name == name && p.Required {
				found = true
			}
		}
		if !found {
			t.Fatal("missing required parameter", name)
		}
	}
	expect := map[string][]string{"NativeRestorePreviewInput": {"backup_id", "expected_revision"}, "NativeRestorePreview": {"site_id", "current_revision", "backup_id", "backup_sha256", "backup_revision", "files", "counts"}, "NativeRestorePreviewFile": {"path", "kind", "before", "after"}, "NativeRestorePreviewFileInfo": {"path", "bytes", "sha256"}, "NativeRestorePreviewCounts": {"added", "modified", "removed", "unchanged"}}
	for name, keys := range expect {
		schema := spec.Components.Schemas[name]
		if schema.Type != "object" || schema.AdditionalProperties || !reflect.DeepEqual(schema.Required, keys) || len(schema.Properties) != len(keys) {
			t.Fatal("nonexact schema", name)
		}
	}
	for _, name := range []string{"before", "after"} {
		alternatives, ok := spec.Components.Schemas["NativeRestorePreviewFile"].Properties[name]["oneOf"].([]any)
		if !ok || len(alternatives) != 2 || alternatives[1].(map[string]any)["type"] != "null" {
			t.Fatal("nullable file metadata missing", name)
		}
	}
	for _, key := range []string{"current_revision", "backup_revision"} {
		p := spec.Components.Schemas["NativeRestorePreview"].Properties[key]
		if p["minimum"] != float64(1) || p["maximum"] != float64(9007199254740991) {
			t.Fatal("unsafe revision schema", key)
		}
	}
	if spec.Components.Schemas["NativeRestorePreview"].Properties["files"]["maxItems"] != float64(128) || spec.Components.Schemas["NativeRestorePreviewFileInfo"].Properties["bytes"]["maximum"] != float64(sites.MaxFileBytes) {
		t.Fatal("missing output bounds")
	}
}
