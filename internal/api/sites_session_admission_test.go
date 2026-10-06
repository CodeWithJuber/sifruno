package api

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"sifruno/internal/operator"
	"sifruno/internal/sites"
)

type siteAdmissionBody struct {
	io.Reader
	entered, release chan struct{}
	once             sync.Once
}

func (b *siteAdmissionBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered); <-b.release })
	return b.Reader.Read(p)
}
func (b *siteAdmissionBody) Close() error { return nil }

// Snapshot only site records/content/backups/schedule and audit summaries, never
// operator fixture keys or cookies. API reads do not change these records.
func siteAdmissionSnapshot(t *testing.T, f siteFixture) []byte {
	t.Helper()
	rows, err := f.store.List()
	if err != nil {
		t.Fatal(err)
	}
	values := []any{rows}
	for _, s := range rows {
		files, err := f.store.Files(s.ID)
		if err != nil {
			t.Fatal(err)
		}
		values = append(values, files)
		for _, file := range files {
			v, err := f.store.ReadFile(s.ID, file.Path)
			if err != nil {
				t.Fatal(err)
			}
			values = append(values, v)
		}
		backups, err := f.store.Backups(s.ID)
		if err != nil {
			t.Fatal(err)
		}
		values = append(values, backups)
		schedule, err := f.store.BackupSchedule(s.ID)
		if err != nil {
			t.Fatal(err)
		}
		values = append(values, schedule)
	}
	events, err := f.journal.List()
	if err != nil {
		t.Fatal(err)
	}
	values = append(values, events)
	b, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSiteSessionAdmissionAfterBody(t *testing.T) {
	for _, operation := range []string{"create", "file", "state", "import", "backups", "restore", "restore-preview", "backup-schedule"} {
		changes := []string{"logout"}
		if operation == "create" || operation == "file" || operation == "state" || operation == "import" {
			changes = []string{"logout", "targeted-revoke", "revoke-others", "active"}
		}
		for _, change := range changes {
			t.Run(operation+"/"+change, func(t *testing.T) {
				f := websiteFixture(t)
				cookie, csrf := websiteSignIn(t, f)
				other, otherCSRF := websiteSignIn(t, f)
				source, err := f.store.Create(sites.CreateInput{Name: "Source", Domain: "source.example"}, "local-operator")
				if err != nil {
					t.Fatal(err)
				}
				file, err := f.store.ReadFile(source.ID, "index.html")
				if err != nil {
					t.Fatal(err)
				}
				source, err = f.store.WriteFile(source.ID, sites.WriteInput{Path: "index.html", Content: "<h1>Exact source bytes</h1>", ExpectedSHA256: file.SHA256, ExpectedRevision: source.Revision}, "local-operator")
				if err != nil {
					t.Fatal(err)
				}
				file, err = f.store.ReadFile(source.ID, "index.html")
				if err != nil {
					t.Fatal(err)
				}
				backup, err := f.store.Backup(source.ID, source.Revision, "local-operator")
				if err != nil {
					t.Fatal(err)
				}
				source, err = f.store.Get(source.ID)
				if err != nil {
					t.Fatal(err)
				}
				inventory := websiteRequest(f.handler, "GET", "/api/v1/session/sessions", nil, cookie, "")
				var sessions operator.Inventory
				if inventory.Code != 200 || json.Unmarshal(inventory.Body.Bytes(), &sessions) != nil {
					t.Fatal("session inventory")
				}
				target := ""
				for _, s := range sessions.Items {
					if s.Current {
						target = s.ID
					}
				}
				if target == "" {
					t.Fatal("missing current handle")
				}
				method, path, ct := "POST", "/api/v1/sites/"+source.ID+"/"+operation, "application/json"
				var input any
				var payload []byte
				switch operation {
				case "create":
					path = "/api/v1/sites"
					input = sites.CreateInput{Name: "New", Domain: "new.example"}
				case "file":
					method = "PUT"
					input = sites.WriteInput{Path: "index.html", Content: "<h1>Changed exact bytes</h1>", ExpectedSHA256: file.SHA256, ExpectedRevision: source.Revision}
				case "state":
					input = sites.StateInput{State: "suspended", ExpectedRevision: source.Revision}
				case "backups":
					input = backupBody{ExpectedRevision: source.Revision}
				case "restore", "restore-preview":
					input = sites.RestoreInput{BackupID: backup.ID, ExpectedRevision: source.Revision}
				case "backup-schedule":
					method = "PUT"
					disabled := false
					input = sites.BackupScheduleInput{ExpectedRevision: source.Revision, ExpectedScheduleRevision: 0, Interval: "daily", Enabled: &disabled}
				case "import":
					path = "/api/v1/sites/import"
					archive, _, err := f.store.ExportBackup(source.ID, backup.ID)
					if err != nil {
						t.Fatal(err)
					}
					var buf bytes.Buffer
					mw := multipart.NewWriter(&buf)
					if err = mw.WriteField("name", "Imported"); err != nil {
						t.Fatal(err)
					}
					if err = mw.WriteField("domain", "imported.example"); err != nil {
						t.Fatal(err)
					}
					part, err := mw.CreateFormFile("archive", "site.zip")
					if err != nil {
						t.Fatal(err)
					}
					if _, err = part.Write(archive); err != nil {
						t.Fatal(err)
					}
					if err = mw.Close(); err != nil {
						t.Fatal(err)
					}
					payload = buf.Bytes()
					ct = mw.FormDataContentType()
				}
				if input != nil {
					payload, err = json.Marshal(input)
					if err != nil {
						t.Fatal(err)
					}
				}
				before := siteAdmissionSnapshot(t, f)
				body := &siteAdmissionBody{Reader: bytes.NewReader(payload), entered: make(chan struct{}), release: make(chan struct{})}
				var releaseOnce sync.Once
				release := func() { releaseOnce.Do(func() { close(body.release) }) }
				r := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, nil)
				r.Body = body
				r.RemoteAddr = "127.0.0.1:14000"
				r.Header.Set("Origin", "http://127.0.0.1:8080")
				r.Header.Set("Content-Type", ct)
				r.Header.Set("X-CSRF-Token", csrf)
				r.AddCookie(cookie)
				w := httptest.NewRecorder()
				done := make(chan struct{})
				go func() { defer close(done); f.handler.ServeHTTP(w, r) }()
				defer func() {
					release()
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Error("handler cleanup timed out")
					}
				}()
				select {
				case <-body.entered:
				case <-time.After(5 * time.Second):
					t.Fatal("body checkpoint not reached")
				}
				var revoked *httptest.ResponseRecorder
				switch change {
				case "logout":
					revoked = websiteRequest(f.handler, "POST", "/api/v1/session/logout", `{}`, cookie, csrf)
				case "targeted-revoke":
					revoked = websiteRequest(f.handler, "POST", "/api/v1/session/sessions/"+target+"/revoke", `{}`, other, otherCSRF)
				case "revoke-others":
					revoked = websiteRequest(f.handler, "POST", "/api/v1/session/revoke-others", `{}`, other, otherCSRF)
				}
				if revoked != nil && revoked.Code != 200 {
					t.Fatalf("revocation status %d", revoked.Code)
				}
				release()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("dispatch did not finish")
				}
				if change != "active" {
					if w.Code != 401 {
						t.Errorf("status %d want401", w.Code)
					}
					if !bytes.Equal(before, siteAdmissionSnapshot(t, f)) {
						t.Error("denied request changed real site or trail state")
					}
					return
				}
				if w.Code != 200 {
					t.Fatalf("active status %d", w.Code)
				}
				rows, err := f.store.List()
				if err != nil {
					t.Fatal(err)
				}
				switch operation {
				case "create":
					if len(rows) != 2 {
						t.Fatal("create not persisted")
					}
					found := false
					for _, v := range rows {
						if v.Name == "New" && v.Domain == "new.example" {
							found = true
						}
					}
					if !found {
						t.Fatal("create metadata changed")
					}
				case "import":
					if len(rows) != 2 {
						t.Fatal("import not persisted")
					}
					found := false
					for _, v := range rows {
						if v.Domain == "imported.example" {
							got, err := f.store.ReadFile(v.ID, "index.html")
							if err != nil || got.Content != file.Content || v.Name != "Imported" {
								t.Fatal("import bytes or metadata changed")
							}
							found = true
						}
					}
					if !found {
						t.Fatal("import missing")
					}
				case "file":
					got, err := f.store.ReadFile(source.ID, "index.html")
					if err != nil || got.Content != "<h1>Changed exact bytes</h1>" || got.Revision != source.Revision+1 {
						t.Fatal("file or revision not persisted")
					}
				case "state":
					got, err := f.store.Get(source.ID)
					if err != nil || got.State != "suspended" || got.Revision != source.Revision+1 {
						t.Fatal("state or revision not persisted")
					}
				}
				if bytes.Equal(before, siteAdmissionSnapshot(t, f)) {
					t.Fatal("active mutation did not persist")
				}
			})
		}
	}
}
