package api

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"sifruno/internal/sites"
)

func TestRemoveBackupHTTPExactConfirmationAndGuards(t *testing.T) {
	f := websiteFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	site, e := f.store.Create(sites.CreateInput{Name: "Removal fixture", Domain: "remove.test"}, "local-operator")
	if e != nil {
		t.Fatal(e)
	}
	b, e := f.store.Backup(site.ID, site.Revision, "local-operator")
	if e != nil {
		t.Fatal(e)
	}
	site, e = f.store.Get(site.ID)
	if e != nil {
		t.Fatal(e)
	}
	base := "/api/v1/sites/" + site.ID
	path := base + "/remove-backup"
	input := sites.RemoveBackupInput{BackupID: b.ID, ExpectedBackupSHA256: b.SHA256, ExpectedRevision: site.Revision, Confirmed: true}
	raw, _ := json.Marshal(input)
	before, _ := f.journal.List()
	beforeItems, _ := f.store.Backups(site.ID)
	for _, tc := range []struct {
		name string
		body any
		want int
	}{
		{"missing confirmation", strings.Replace(string(raw), `,"confirmed":true`, "", 1), 400},
		{"null", strings.Replace(string(raw), `"confirmed":true`, `"confirmed":null`, 1), 400},
		{"case alias", strings.Replace(string(raw), `"confirmed"`, `"Confirmed"`, 1), 400},
		{"duplicate", strings.Replace(string(raw), `"confirmed":true`, `"confirmed":true,"confirmed":true`, 1), 400},
		{"unknown", strings.Replace(string(raw), `"confirmed":true`, `"confirmed":true,"retention":true`, 1), 400},
		{"false", strings.Replace(string(raw), `"confirmed":true`, `"confirmed":false`, 1), 422},
		{"wrong hash", sites.RemoveBackupInput{BackupID: b.ID, ExpectedBackupSHA256: strings.Repeat("f", 64), ExpectedRevision: site.Revision, Confirmed: true}, 409},
		{"stale", sites.RemoveBackupInput{BackupID: b.ID, ExpectedBackupSHA256: b.SHA256, ExpectedRevision: site.Revision - 1, Confirmed: true}, 409},
		{"invalid id", sites.RemoveBackupInput{BackupID: "../outside", ExpectedBackupSHA256: b.SHA256, ExpectedRevision: site.Revision, Confirmed: true}, 422},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := websiteRequest(f.handler, "POST", path, tc.body, cookie, csrf)
			if w.Code != tc.want {
				t.Fatal(w.Code, w.Body.String())
			}
			current, _ := f.store.Get(site.ID)
			history, _ := f.journal.List()
			items, _ := f.store.Backups(site.ID)
			if !reflect.DeepEqual(current, site) || !reflect.DeepEqual(before, history) || !reflect.DeepEqual(beforeItems, items) {
				t.Fatal("refusal mutated")
			}
		})
	}
	for _, tc := range []struct {
		cookie *http.Cookie
		csrf   string
		want   int
	}{{nil, "", 401}, {cookie, "", 403}} {
		if w := websiteRequest(f.handler, "POST", path, input, tc.cookie, tc.csrf); w.Code != tc.want {
			t.Fatal("authentication", w.Code)
		}
	}
	other, e := f.store.Create(sites.CreateInput{Name: "Other", Domain: "other.test"}, "local-operator")
	if e != nil {
		t.Fatal(e)
	}
	cross := input
	cross.ExpectedRevision = other.Revision
	if w := websiteRequest(f.handler, "POST", "/api/v1/sites/"+other.ID+"/remove-backup", cross, cookie, csrf); w.Code != 404 {
		t.Fatal("cross-site", w.Code)
	}
	result := siteResponse(t, websiteRequest(f.handler, "POST", path, input, cookie, csrf))
	if result.Revision != site.Revision+1 {
		t.Fatal("revision")
	}
	if w := websiteRequest(f.handler, "GET", base+"/backups/"+b.ID+"/download", nil, cookie, ""); w.Code != 404 {
		t.Fatal("removed download", w.Code)
	}
	if w := websiteRequest(f.handler, "POST", path, input, cookie, csrf); w.Code != 409 {
		t.Fatal("no replay", w.Code)
	}
}
