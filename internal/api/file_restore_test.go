package api

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"sifruno/internal/sites"
	"strings"
	"testing"
)

func TestFileRestoreAPIContractAndAdmission(t *testing.T) {
	f, s, b := previewAPIFixture(t)
	c, csrf := websiteSignIn(t, f)
	input := sites.FileRestoreInput{BackupID: b.ID, ExpectedBackupSHA256: b.SHA256, ExpectedRevision: s.Revision, Path: "index.html"}
	for _, suffix := range []string{"restore-file-preview", "restore-file"} {
		endpoint := "/api/v1/sites/" + s.ID + "/" + suffix
		for _, mode := range []string{"session", "csrf", "origin"} {
			r := httptest.NewRequest("POST", "http://127.0.0.1:8080"+endpoint, nil)
			r.RemoteAddr = "127.0.0.1:15000"
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", "http://127.0.0.1:8080")
			r.Header.Set("X-CSRF-Token", csrf)
			if mode != "session" {
				r.AddCookie(c)
			}
			if mode == "csrf" {
				r.Header.Del("X-CSRF-Token")
			}
			if mode == "origin" {
				r.Header.Set("Origin", "http://evil.invalid")
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
				t.Fatalf("%s %s admission %d reads %d", suffix, mode, w.Code, body.reads)
			}
		}
		raw, _ := json.Marshal(input)
		valid := string(raw)
		if suffix == "restore-file" {
			valid = strings.TrimSuffix(valid, "}") + `,"confirmed":true}`
		}
		for _, bad := range []string{"{}", strings.Replace(valid, `"path"`, `"PATH"`, 1), strings.Replace(valid, `"path":"index.html"`, `"path":null`, 1), strings.TrimSuffix(valid, "}") + `,"extra":1}`, strings.TrimSuffix(valid, "}") + `,"path":"index.html"}`, valid + " {}"} {
			if w := websiteRequest(f.handler, "POST", endpoint, bad, c, csrf); w.Code != 400 {
				t.Fatalf("%s strict status %d", suffix, w.Code)
			}
		}
		if w := websiteRequest(f.handler, "POST", endpoint, valid+strings.Repeat(" ", 4097-len(valid)), c, csrf); w.Code != 413 {
			t.Fatal("body bound", w.Code)
		}
	}
	endpoint := "/api/v1/sites/" + s.ID
	w := websiteRequest(f.handler, "POST", endpoint+"/restore-file-preview", input, c, csrf)
	var p sites.FileRestorePreview
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &p) != nil || p.File.Path != "index.html" || p.File.Kind != "unchanged" || p.BackupSHA256 != b.SHA256 {
		t.Fatalf("preview DTO %d %s", w.Code, w.Body.String())
	}
	if w = websiteRequest(f.handler, "POST", endpoint+"/restore-file", input, c, csrf); w.Code != 400 {
		t.Fatal("missing confirmation", w.Code)
	}
	if w = websiteRequest(f.handler, "POST", endpoint+"/restore-file", sites.ConfirmFileRestoreInput{FileRestoreInput: input, Confirmed: false}, c, csrf); w.Code != 422 {
		t.Fatal("false confirmation", w.Code)
	}
	bad := input
	bad.ExpectedBackupSHA256 = strings.Repeat("0", 64)
	if w = websiteRequest(f.handler, "POST", endpoint+"/restore-file", sites.ConfirmFileRestoreInput{FileRestoreInput: bad, Confirmed: true}, c, csrf); w.Code != 409 {
		t.Fatal("archive binding", w.Code)
	}
	if w = websiteRequest(f.handler, "POST", endpoint+"/restore-file", sites.ConfirmFileRestoreInput{FileRestoreInput: input, Confirmed: true}, c, csrf); w.Code != 200 {
		t.Fatal("confirm", w.Code, w.Body.String())
	}
	if w = websiteRequest(f.handler, "POST", endpoint+"/restore-file", sites.ConfirmFileRestoreInput{FileRestoreInput: input, Confirmed: true}, c, csrf); w.Code != 409 {
		t.Fatal("stale double submit", w.Code)
	}
	if strings.Contains(fmt.Sprint(p), "<html") {
		t.Fatal("contents leaked")
	}
}
