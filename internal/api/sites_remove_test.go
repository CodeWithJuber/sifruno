package api

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"sifruno/internal/sites"
)

func TestWebsiteRemovalHTTPConfirmationAndWireContract(t *testing.T) {
	f := websiteFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	site, e := f.store.Create(sites.CreateInput{Name: "Removal", Domain: "remove.test"}, "local-operator")
	if e != nil {
		t.Fatal(e)
	}
	backup, e := f.store.Backup(site.ID, site.Revision, "local-operator")
	if e != nil {
		t.Fatal(e)
	}
	site, _ = f.store.Get(site.ID)
	path := "/api/v1/sites/" + site.ID
	in := sites.RemoveInput{ExpectedRevision: site.Revision, ConfirmationDomain: site.Domain, Confirmed: true}
	raw, _ := json.Marshal(in)
	before, _ := f.journal.List()
	for _, tc := range []struct {
		name string
		body any
		want int
	}{
		{"missing", strings.Replace(string(raw), `,"confirmed":true`, "", 1), 400},
		{"null", strings.Replace(string(raw), `"confirmed":true`, `"confirmed":null`, 1), 400},
		{"alias", strings.Replace(string(raw), `"confirmed"`, `"Confirmed"`, 1), 400},
		{"duplicate", strings.Replace(string(raw), `"confirmed":true`, `"confirmed":true,"confirmed":true`, 1), 400},
		{"unknown", strings.Replace(string(raw), `"confirmed":true`, `"confirmed":true,"all":true`, 1), 400},
		{"false", strings.Replace(string(raw), `"confirmed":true`, `"confirmed":false`, 1), 422},
		{"wrong domain", sites.RemoveInput{ExpectedRevision: site.Revision, ConfirmationDomain: "other.test", Confirmed: true}, 409},
		{"stale", sites.RemoveInput{ExpectedRevision: site.Revision - 1, ConfirmationDomain: site.Domain, Confirmed: true}, 409},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := websiteRequest(f.handler, "DELETE", path, tc.body, cookie, csrf)
			if w.Code != tc.want {
				t.Fatal(w.Code, w.Body.String())
			}
			current, _ := f.store.Get(site.ID)
			history, _ := f.journal.List()
			if !reflect.DeepEqual(current, site) || !reflect.DeepEqual(history, before) {
				t.Fatal("refusal mutated")
			}
		})
	}
	for _, tc := range []struct {
		cookie *http.Cookie
		csrf   string
		want   int
	}{{nil, "", 401}, {cookie, "", 403}} {
		if w := websiteRequest(f.handler, "DELETE", path, in, tc.cookie, tc.csrf); w.Code != tc.want {
			t.Fatal("auth", w.Code)
		}
	}
	w := websiteRequest(f.handler, "DELETE", path, in, cookie, csrf)
	var result map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result["id"] != site.ID || result["domain"] != site.Domain || result["revision"] != float64(site.Revision) || result["removed"] != true {
		t.Fatal("wire contract", w.Code, w.Body.String())
	}
	// Huma can include its root $schema hint. Clients bind all four result fields.
	for key := range result {
		if key != "$schema" && key != "id" && key != "domain" && key != "revision" && key != "removed" {
			t.Fatal("unexpected wire field", key)
		}
	}
	for _, suffix := range []string{"", "/files", "/file?path=index.html", "/backups", "/backup-schedule", "/backups/" + backup.ID + "/download"} {
		if w := websiteRequest(f.handler, "GET", path+suffix, nil, cookie, ""); w.Code != 404 {
			t.Fatal("removed endpoint", suffix, w.Code)
		}
	}
	if w := websiteRequest(f.handler, "DELETE", path, in, cookie, csrf); w.Code != 404 {
		t.Fatal("replay", w.Code)
	}
}
