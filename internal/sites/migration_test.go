package sites

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestNativeExportImportHTTPAndRestart(t *testing.T) {
	source, _, sourceBase := fixture(t)
	site := makeSite(t, source)
	index, err := source.ReadFile(site.ID, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	site, err = source.WriteFile(site.ID, WriteInput{Path: "index.html", Content: "<!doctype html><h1>Original exported bytes</h1>", ExpectedRevision: site.Revision, ExpectedSHA256: index.SHA256}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	site, err = source.WriteFile(site.ID, WriteInput{Path: "assets/style.css", Content: "body { color: teal }", ExpectedRevision: site.Revision}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	backup, err := source.Backup(site.ID, site.Revision, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	raw, exported, err := source.ExportBackup(site.ID, backup.ID)
	if err != nil || exported != backup || int64(len(raw)) != backup.Bytes || sum(raw) != backup.SHA256 {
		t.Fatal("hash-bound original export", err)
	}
	disk, err := os.ReadFile(filepath.Join(sourceBase, "sites", "data", site.ID, "backups", backup.ID+".zip"))
	if err != nil || !bytes.Equal(raw, disk) {
		t.Fatal("export repacked original ZIP", err)
	}
	target, journal, targetBase := fixture(t)
	imported, err := target.ImportArchive(ImportInput{Name: "Explicit target name", Domain: "IMPORTED.TEST", Archive: raw}, "local-operator")
	if err != nil || imported.ID == site.ID || imported.Name != "Explicit target name" || imported.Domain != "imported.test" || imported.Revision != 1 || imported.State != "active" {
		t.Fatal("fresh explicit target identity", imported, err)
	}
	files, err := target.Files(imported.ID)
	if err != nil || len(files) != 2 {
		t.Fatal("complete imported catalog", err)
	}
	if backups, err := target.Backups(imported.ID); err != nil || len(backups) != 0 {
		t.Fatal("import fabricated source backup history", err)
	}
	assertSocketBytes(t, target, imported.PreviewHost, "/", []byte("<!doctype html><h1>Original exported bytes</h1>"))
	assertSocketBytes(t, target, imported.Domain, "/assets/style.css", []byte("body { color: teal }"))
	if err = target.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(filepath.Join(targetBase, "sites"), journal)
	if err != nil {
		t.Fatal("import restart", err)
	}
	defer again.Close()
	persisted, err := again.Get(imported.ID)
	if err != nil || persisted != imported {
		t.Fatal("persisted import identity", err)
	}
	afterFiles, err := again.Files(imported.ID)
	if err != nil || !reflect.DeepEqual(files, afterFiles) || journal.Verify() != nil {
		t.Fatal("persisted complete signed catalog", err)
	}
	assertSocketBytes(t, again, imported.Domain, "/", []byte("<!doctype html><h1>Original exported bytes</h1>"))
	// Export is a detached byte slice; a caller cannot alter the on-disk ZIP.
	raw[0] ^= 0xff
	second, _, err := source.ExportBackup(site.ID, backup.ID)
	if err != nil || !bytes.Equal(second, disk) {
		t.Fatal("caller changed original archive", err)
	}
}

func assertSocketBytes(t *testing.T, s *Store, host, path string, want []byte) {
	t.Helper()
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	r, err := http.NewRequest("GET", server.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Host = host
	response, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || !bytes.Equal(got, want) {
		t.Fatal("actual imported HTTP bytes", response.StatusCode, err)
	}
}

type migrationEntry struct {
	name string
	data []byte
	mode os.FileMode
}

func migrationZIP(t *testing.T, manifest []byte, entries []migrationEntry) []byte {
	t.Helper()
	var out bytes.Buffer
	w := zip.NewWriter(&out)
	all := append([]migrationEntry{{"manifest.json", manifest, 0600}}, entries...)
	for _, e := range all {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		h.SetMode(e.mode)
		f, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func nativeMigrationArchive(t *testing.T, data map[string][]byte) []byte {
	t.Helper()
	raw, err := buildArchive(record{Site: Site{ID: strings.Repeat("a", 32), Revision: 7}}, strings.Repeat("b", 32), data)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestImportHostileArchivesCreateNoRecordOrFiles(t *testing.T) {
	data := []byte("<h1>native archive</h1>")
	m := archiveManifest{Version: 1, BackupID: strings.Repeat("b", 32), SiteID: strings.Repeat("a", 32), Revision: 1, Files: []FileInfo{{Path: "index.html", Bytes: int64(len(data)), SHA256: sum(data)}}}
	manifest, _ := json.Marshal(m)
	valid := migrationZIP(t, manifest, []migrationEntry{{"files/index.html", data, 0600}})
	cases := []struct {
		name string
		raw  []byte
	}{
		{"not ZIP", []byte("not a Sifruno ZIP")},
		{"empty", nil},
		{"truncated", valid[:len(valid)-7]},
		{"oversized raw", make([]byte, MaxBackupBytes+1)},
	}
	for _, tc := range []struct {
		name, path string
		mode       os.FileMode
		content    []byte
	}{
		{"traversal", "files/../escape.html", 0600, data},
		{"absolute", "/outside.html", 0600, data},
		{"backslash", "files/a\\escape.html", 0600, data},
		{"private", "files/credentials.txt", 0600, data},
		{"source PHP", "files/index.php", 0600, data},
		{"symlink", "files/index.html", os.ModeSymlink | 0777, []byte("../../outside")},
		{"directory", "files/index.html", os.ModeDir | 0700, nil},
		{"file bomb", "files/index.html", 0600, bytes.Repeat([]byte("x"), MaxFileBytes+1)},
		{"hash mismatch", "files/index.html", 0600, []byte("different")},
	} {
		cases = append(cases, struct {
			name string
			raw  []byte
		}{tc.name, migrationZIP(t, manifest, []migrationEntry{{tc.path, tc.content, tc.mode}})})
	}
	for _, tc := range []struct{ name, manifest string }{
		{"foreign manifest", `{}`},
		{"unknown schema", strings.Replace(string(manifest), `"version":1`, `"version":2`, 1)},
		{"invalid source ID", strings.Replace(string(manifest), strings.Repeat("a", 32), "../../outside", 1)},
		{"zero source revision", strings.Replace(string(manifest), `"revision":1`, `"revision":0`, 1)},
		{"unknown JSON field", strings.Replace(string(manifest), `"version":1`, `"version":1,"unexpected":true`, 1)},
		{"duplicate JSON identity", strings.Replace(string(manifest), `"version":1`, `"version":0,"VERSION":1`, 1)},
		{"Unicode folded identity alias", strings.Replace(string(manifest), `"site_id":"`+m.SiteID+`"`, `"site_id":"`+m.SiteID+`","ſite_id":"`+strings.Repeat("c", 32)+`"`, 1)},
		{"Unicode folded hash alias", strings.Replace(string(manifest), `"sha256":`, `"ſha256":"`+strings.Repeat("c", 64)+`","sha256":`, 1)},
		{"duplicate file JSON hash", strings.Replace(string(manifest), `"sha256":`, `"SHA256":"forged","sha256":`, 1)},
		{"size mismatch", strings.Replace(string(manifest), fmt.Sprintf(`"bytes":%d`, len(data)), `"bytes":1`, 1)},
		{"empty catalog", strings.Replace(string(manifest), string(mustJSON(t, m.Files)), `[]`, 1)},
	} {
		cases = append(cases, struct {
			name string
			raw  []byte
		}{tc.name, migrationZIP(t, []byte(tc.manifest), []migrationEntry{{"files/index.html", data, 0600}})})
	}
	for _, entries := range [][]migrationEntry{
		{{"files/index.html", data, 0600}, {"files/index.html", data, 0600}},
		{{"files/index.html", data, 0600}, {"files/INDEX.html", data, 0600}},
		{{"files/index.html", data, 0600}, {"manifest.json", manifest, 0600}},
		{{"files/index.html", data, 0600}, {"files/unlisted.txt", data, 0600}},
	} {
		cases = append(cases, struct {
			name string
			raw  []byte
		}{fmt.Sprintf("duplicate or unlisted %d", len(cases)), migrationZIP(t, manifest, entries)})
	}
	tooMany := []migrationEntry{}
	for i := 0; i <= MaxFiles; i++ {
		tooMany = append(tooMany, migrationEntry{fmt.Sprintf("files/f%d.txt", i), nil, 0600})
	}
	cases = append(cases, struct {
		name string
		raw  []byte
	}{"too many central entries", migrationZIP(t, manifest, tooMany)})
	// A forged low EOCD count cannot hide a large central-directory inventory.
	forgedCount := append([]byte{}, cases[len(cases)-1].raw...)
	binary.LittleEndian.PutUint16(forgedCount[len(forgedCount)-14:], 2)
	binary.LittleEndian.PutUint16(forgedCount[len(forgedCount)-12:], 2)
	cases = append(cases, struct {
		name string
		raw  []byte
	}{"forged central count", forgedCount})
	bigData := bytes.Repeat([]byte("x"), MaxFileBytes)
	bigFiles := []FileInfo{}
	bigEntries := []migrationEntry{}
	for i := 0; i < 17; i++ {
		name := fmt.Sprintf("f%d.txt", i)
		bigFiles = append(bigFiles, FileInfo{Path: name, Bytes: int64(len(bigData)), SHA256: sum(bigData)})
		bigEntries = append(bigEntries, migrationEntry{"files/" + name, bigData, 0600})
	}
	tooBig := m
	tooBig.Files = bigFiles
	cases = append(cases, struct {
		name string
		raw  []byte
	}{"total decompressed cap", migrationZIP(t, mustJSON(t, tooBig), bigEntries)})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _, base := fixture(t)
			if _, err := s.ImportArchive(ImportInput{Name: "Rejected import", Domain: "reject.test", Archive: tc.raw}, "local-operator"); !errors.Is(err, ErrInvalid) {
				t.Fatal("hostile native archive accepted", err)
			}
			items, err := s.List()
			if err != nil || len(items) != 0 {
				t.Fatal("invalid archive created a record", err)
			}
			dirs, err := os.ReadDir(filepath.Join(base, "sites", "data"))
			if err != nil || len(dirs) != 0 {
				t.Fatal("invalid archive created files", err)
			}
		})
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestImportComplete64FileCatalogAndBinary(t *testing.T) {
	s, j, _ := fixture(t)
	data := map[string][]byte{"image.png": {0x89, 'P', 'N', 'G', 0, 0xff, 0xfe}}
	for i := 1; i < MaxFiles; i++ {
		data[fmt.Sprintf("nested/f%02d.txt", i)] = []byte(fmt.Sprintf("actual file %d", i))
	}
	site, err := s.ImportArchive(ImportInput{Name: "Complete catalog", Domain: "many.test", Archive: nativeMigrationArchive(t, data)}, "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	files, err := s.Files(site.ID)
	if err != nil || len(files) != MaxFiles {
		t.Fatal("partial imported catalog", err)
	}
	r, err := s.load(site.ID)
	if err != nil || len(r.ChangeIDs) != 2 || r.Pending != nil || j.Verify() != nil {
		t.Fatal("64 files were not one committed scoped operation", err)
	}
	assertSocketBytes(t, s, site.Domain, "/image.png", data["image.png"])
	for _, file := range files {
		if sum(data[file.Path]) != file.SHA256 || int64(len(data[file.Path])) != file.Bytes {
			t.Fatal("import changed original file bytes")
		}
	}
}

func TestImportTargetValidationAndConcurrentDomain(t *testing.T) {
	s, _, base := fixture(t)
	raw := nativeMigrationArchive(t, map[string][]byte{"index.html": []byte("same native bytes")})
	for _, tc := range []struct{ name, domain, actor string }{{"", "valid.test", "local-operator"}, {"valid", "../invalid.test", "local-operator"}, {"valid", "valid.test", "root"}} {
		if _, err := s.ImportArchive(ImportInput{Name: tc.name, Domain: tc.domain, Archive: raw}, tc.actor); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid target accepted", err)
		}
	}
	items, err := s.List()
	dirs, readErr := os.ReadDir(filepath.Join(base, "sites", "data"))
	if err != nil || readErr != nil || len(items) != 0 || len(dirs) != 0 {
		t.Fatal("invalid target created state", err, readErr)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	success, conflict := 0, 0
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.ImportArchive(ImportInput{Name: "One target", Domain: "unique.test", Archive: raw}, "local-operator")
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				success++
			} else if errors.Is(err, ErrConflict) {
				conflict++
			} else {
				t.Errorf("import concurrency: %v", err)
			}
		}()
	}
	wg.Wait()
	items, err = s.List()
	dirs, readErr = os.ReadDir(filepath.Join(base, "sites", "data"))
	if err != nil || readErr != nil || success != 1 || conflict != 5 || len(items) != 1 || len(dirs) != 1 {
		t.Fatal("domain conflict created partial targets", success, conflict, err, readErr)
	}
}

func TestExportBackupRejectsTamperAndLinks(t *testing.T) {
	for _, kind := range []string{"bytes", "hardlink", "symlink", "catalog anchor"} {
		t.Run(kind, func(t *testing.T) {
			s, _, base := fixture(t)
			site := makeSite(t, s)
			backup, err := s.Backup(site.ID, site.Revision, "local-operator")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(base, "sites", "data", site.ID, "backups", backup.ID+".zip")
			switch kind {
			case "bytes":
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				raw[len(raw)/2] ^= 0xff
				if os.WriteFile(path, raw, 0600) != nil {
					t.Fatal("corrupt export fixture")
				}
			case "hardlink":
				if err = os.Link(path, filepath.Join(base, "outside.zip")); err != nil {
					t.Fatal("real archive hardlink", err)
				}
			case "symlink":
				raw, err := os.ReadFile(path)
				outside := filepath.Join(base, "outside.zip")
				if err != nil || os.WriteFile(outside, raw, 0600) != nil || os.Remove(path) != nil {
					t.Fatal("real archive symlink fixture", err)
				}
				if err = os.Symlink(outside, path); err != nil {
					t.Skip("native symlink creation unavailable", err)
				}
			case "catalog anchor":
				r, err := s.load(site.ID)
				if err != nil {
					t.Fatal(err)
				}
				r.Backups[0].SHA256 = strings.Repeat("0", 64)
				if s.save(r) != nil || os.WriteFile(filepath.Join(base, "sites", "data", site.ID, "state.json"), mustJSON(t, r), 0600) != nil {
					t.Fatal("coordinated unsigned export metadata fixture")
				}
			}
			if raw, info, err := s.ExportBackup(site.ID, backup.ID); !errors.Is(err, ErrUnavailable) || raw != nil || info != (BackupInfo{}) {
				t.Fatal("unverified backup bytes disclosed", err)
			}
		})
	}
}

func TestImportFailedJournalCommitPersistsRecoveryRequired(t *testing.T) {
	s, j, base := fixture(t)
	raw := nativeMigrationArchive(t, map[string][]byte{"index.html": []byte("must never serve partial import"), "nested/second.txt": []byte("second original file")})
	keyPath := filepath.Join(base, "journal", "key")
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	broken := append([]byte{}, key...)
	broken[0] ^= 0xff
	if err = os.WriteFile(keyPath, broken, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ImportArchive(ImportInput{Name: "Interrupted import", Domain: "pending.test", Archive: raw}, "local-operator"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("failed journal commit reported success", err)
	}
	if err = os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	items, err := s.List()
	if err != nil || len(items) != 1 || items[0].State != "recovery_required" {
		t.Fatal("failed import hidden or active", err)
	}
	if served(s, items[0].Domain, "/", "GET").Code != http.StatusServiceUnavailable {
		t.Fatal("partial import served")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(filepath.Join(base, "sites"), j)
	if err != nil {
		t.Fatal("reopen interrupted import", err)
	}
	defer again.Close()
	site, err := again.Get(items[0].ID)
	if err != nil || site.State != "recovery_required" {
		t.Fatal("failed import became active after restart", err)
	}
	if _, err = again.Files(site.ID); !errors.Is(err, ErrUnavailable) {
		t.Fatal("partial import catalog returned", err)
	}
	if _, _, err = again.ExportBackup(site.ID, strings.Repeat("c", 32)); !errors.Is(err, ErrUnavailable) {
		t.Fatal("failed import export accepted", err)
	}
}
