package native_restore_preview_review_test

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	"sifruno/internal/api"
	"sifruno/internal/operator"
	"sifruno/internal/sites"
	"sifruno/internal/trail"
)

const origin = "http://127.0.0.1:8181"

type fixture struct {
	base   string
	s      *sites.Store
	j      *trail.Store
	m      *operator.Manager
	h      http.Handler
	site   sites.Site
	cookie *http.Cookie
	csrf   string
}

func digest(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func isolated(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{base: t.TempDir()}
	var err error
	f.base, err = filepath.EvalSymlinks(f.base)
	if err != nil {
		t.Fatal("temp admission")
	}
	f.j, err = trail.Open(filepath.Join(f.base, "journal"))
	if err != nil {
		t.Fatal("journal admission")
	}
	f.s, err = sites.Open(filepath.Join(f.base, "sites"), f.j)
	if err != nil {
		t.Fatal("sites admission")
	}
	t.Cleanup(func() {
		if f.s != nil && f.s.Close() != nil {
			t.Error("owned Store.Close failed")
		}
	})
	f.site, err = f.s.Create(sites.CreateInput{Name: "Preview review", Domain: "preview-review.test"}, "local-operator")
	if err != nil {
		t.Fatal("site creation")
	}
	m, err := operator.Open(filepath.Join(f.base, "operator"))
	if err != nil {
		t.Fatal("operator admission")
	}
	f.m = m
	f.bind()
	key, err := os.ReadFile(m.AccessKeyPath())
	if err != nil {
		t.Fatal("fixture login")
	}
	body, _ := json.Marshal(map[string]string{"access_key": strings.TrimSpace(string(key))})
	w := f.req("/api/v1/session/login", string(body), nil)
	mustStatus(t, w, 200)
	var session operator.Session
	if json.Unmarshal(w.Body.Bytes(), &session) != nil || !session.Authenticated {
		t.Fatal("fixture session")
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || session.CSRFToken == "" {
		t.Fatal("fixture credentials")
	}
	f.cookie, f.csrf = cookies[0], session.CSRFToken
	return f
}
func (f *fixture) bind() {
	f.h = api.New(api.Options{Sites: f.s, Trail: f.j, Operator: f.m, AllowedOrigins: []string{origin}, BackupSchedulerEnabled: true})
}
func (f *fixture) req(path, body string, adjust func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", origin+path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:43111"
	r.Header.Set("Origin", origin)
	r.Header.Set("Content-Type", "application/json")
	if f.cookie != nil {
		r.AddCookie(f.cookie)
		r.Header.Set("X-CSRF-Token", f.csrf)
	}
	if adjust != nil {
		adjust(r)
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	return w
}
func (f *fixture) path() string { return "/api/v1/sites/" + f.site.ID + "/restore-preview" }
func payload(id string, rev uint64) string {
	b, _ := json.Marshal(sites.RestoreInput{BackupID: id, ExpectedRevision: rev})
	return string(b)
}
func mustStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("response status %d, want %d", w.Code, want)
	}
}
func (f *fixture) current(t *testing.T) {
	t.Helper()
	v, e := f.s.Get(f.site.ID)
	if e != nil {
		t.Fatal("current metadata")
	}
	f.site = v
}
func (f *fixture) write(t *testing.T, path, content string) {
	t.Helper()
	sha := ""
	v, e := f.s.ReadFile(f.site.ID, path)
	if e == nil {
		sha = v.SHA256
	} else if !errors.Is(e, sites.ErrNotFound) {
		t.Fatal("write precondition")
	}
	f.site, e = f.s.WriteFile(f.site.ID, sites.WriteInput{Path: path, Content: content, ExpectedRevision: f.site.Revision, ExpectedSHA256: sha}, "local-operator")
	if e != nil {
		t.Fatal("owned file write")
	}
}
func (f *fixture) backup(t *testing.T) sites.BackupInfo {
	t.Helper()
	b, e := f.s.Backup(f.site.ID, f.site.Revision, "local-operator")
	if e != nil {
		t.Fatal("owned backup")
	}
	f.current(t)
	return b
}

type diskEntry struct {
	Hash string
	Mode os.FileMode
	Size int64
}

func disk(t *testing.T, root string) map[string]diskEntry {
	t.Helper()
	out := map[string]diskEntry{}
	e := filepath.WalkDir(root, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		i, e := d.Info()
		if e != nil {
			return e
		}
		if !i.Mode().IsRegular() {
			return errors.New("unexpected nonregular fixture")
		}
		raw, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(root, p)
		if e != nil {
			return e
		}
		out[filepath.ToSlash(rel)] = diskEntry{digest(raw), i.Mode(), i.Size()}
		return nil
	})
	if e != nil {
		t.Fatal("disk capture")
	}
	return out
}
func unchanged(t *testing.T, f *fixture, fn func()) {
	t.Helper()
	before := disk(t, f.base)
	fn()
	if !reflect.DeepEqual(before, disk(t, f.base)) {
		t.Fatal("preview changed exact fixture bytes/modes/membership")
	}
}
func exact(t *testing.T, raw []byte, names ...string) map[string]json.RawMessage {
	t.Helper()
	var v map[string]json.RawMessage
	if json.Unmarshal(raw, &v) != nil || len(v) != len(names) {
		t.Fatal("wire object shape")
	}
	for _, n := range names {
		if _, ok := v[n]; !ok {
			t.Fatal("wire field absent/aliased")
		}
	}
	return v
}

// Reconstruct metadata from the actual exported ZIP payload, rather than trusting
// the implementation's file catalog or its preview counts.
func archiveFiles(t *testing.T, raw []byte) map[string]sites.FileInfo {
	t.Helper()
	z, e := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if e != nil {
		t.Fatal("actual archive parse")
	}
	out := map[string]sites.FileInfo{}
	for _, entry := range z.File {
		if !strings.HasPrefix(entry.Name, "files/") {
			continue
		}
		stream, e := entry.Open()
		if e != nil {
			t.Fatal("actual archive entry")
		}
		b, e := io.ReadAll(io.LimitReader(stream, sites.MaxFileBytes+1))
		ce := stream.Close()
		if e != nil || ce != nil || len(b) > sites.MaxFileBytes {
			t.Fatal("archive read/cleanup")
		}
		p := strings.TrimPrefix(entry.Name, "files/")
		out[p] = sites.FileInfo{Path: p, Bytes: int64(len(b)), SHA256: digest(b)}
	}
	return out
}
func validate(t *testing.T, f *fixture, b sites.BackupInfo, w *httptest.ResponseRecorder) sites.RestorePreview {
	t.Helper()
	mustStatus(t, w, 200)
	v := exact(t, w.Body.Bytes(), "site_id", "current_revision", "backup_id", "backup_sha256", "backup_revision", "files", "counts")
	exact(t, v["counts"], "added", "modified", "removed", "unchanged")
	var p sites.RestorePreview
	if json.Unmarshal(w.Body.Bytes(), &p) != nil {
		t.Fatal("preview JSON")
	}
	if p.SiteID != f.site.ID || p.CurrentRevision != f.site.Revision || p.BackupID != b.ID || p.BackupSHA256 != b.SHA256 || p.BackupRevision != b.Revision {
		t.Fatal("preview binding")
	}
	raw, info, e := f.s.ExportBackup(f.site.ID, b.ID)
	if e != nil || info != b || digest(raw) != p.BackupSHA256 {
		t.Fatal("actual ZIP binding")
	}
	after := archiveFiles(t, raw)
	before, err := f.s.Files(f.site.ID)
	if err != nil {
		t.Fatal("current catalog")
	}
	current := map[string]sites.FileInfo{}
	union := map[string]bool{}
	for _, x := range before {
		current[x.Path] = x
		union[x.Path] = true
	}
	for path := range after {
		union[path] = true
	}
	paths := []string{}
	for path := range union {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	if len(paths) != len(p.Files) || len(paths) > 128 {
		t.Fatal("bounded union")
	}
	var entries []json.RawMessage
	if json.Unmarshal(v["files"], &entries) != nil {
		t.Fatal("wire files")
	}
	counts := map[string]int{}
	for i, path := range paths {
		x := p.Files[i]
		keys := exact(t, entries[i], "path", "kind", "before", "after")
		cb, cok := current[path]
		ab, aok := after[path]
		kind := "modified"
		if !cok {
			kind = "added"
		} else if !aok {
			kind = "removed"
		} else if cb == ab {
			kind = "unchanged"
		}
		if x.Path != path || x.Kind != kind {
			t.Fatal("diff classification/order")
		}
		counts[kind]++
		for side, wanted := range map[string]*sites.FileInfo{"before": func() *sites.FileInfo {
			if !cok {
				return nil
			}
			return &cb
		}(), "after": func() *sites.FileInfo {
			if !aok {
				return nil
			}
			return &ab
		}()} {
			var actual *sites.FileInfo
			if json.Unmarshal(keys[side], &actual) != nil || !reflect.DeepEqual(actual, wanted) {
				t.Fatal("actual catalog metadata mismatch")
			}
			if wanted != nil {
				exact(t, keys[side], "path", "bytes", "sha256")
			}
		}
	}
	if p.Counts != (sites.RestorePreviewCounts{Added: counts["added"], Modified: counts["modified"], Removed: counts["removed"], Unchanged: counts["unchanged"]}) {
		t.Fatal("counts do not equal reconstructed classifications")
	}
	for _, private := range []string{f.base, f.csrf, f.cookie.Value, "archived-private-content-marker"} {
		if strings.Contains(w.Body.String(), private) {
			t.Fatal("response exposes contents/private admission")
		}
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("cache boundary")
	}
	return p
}

func TestActualZIPFourKindsWireReadOnlyReopen(t *testing.T) {
	f := isolated(t)
	f.write(t, "stable.txt", "stable")
	a := f.backup(t)
	f.write(t, "Alpha.txt", "archived-private-content-marker")
	f.write(t, "index.html", "archive index")
	b := f.backup(t)
	var e error
	f.site, e = f.s.Restore(f.site.ID, sites.RestoreInput{BackupID: a.ID, ExpectedRevision: f.site.Revision}, "local-operator")
	if e != nil {
		t.Fatal("actual restore setup")
	}
	f.write(t, "removed.txt", "current only")
	off := false
	if _, e = f.s.SetBackupSchedule(f.site.ID, sites.BackupScheduleInput{ExpectedRevision: f.site.Revision, Interval: "daily", Enabled: &off}, "local-operator"); e != nil {
		t.Fatal("paused schedule setup")
	}
	var p sites.RestorePreview
	unchanged(t, f, func() { p = validate(t, f, b, f.req(f.path(), payload(b.ID, f.site.Revision), nil)) })
	if p.Counts != (sites.RestorePreviewCounts{Added: 1, Modified: 1, Removed: 1, Unchanged: 1}) {
		t.Fatal("four categories missing")
	}
	p.Files[0].After.Path = "mutated-return.txt"
	unchanged(t, f, func() { validate(t, f, b, f.req(f.path(), payload(b.ID, f.site.Revision), nil)) })
	if e = f.s.Close(); e != nil {
		t.Fatal("owned reopen close")
	}
	f.s, e = sites.Open(filepath.Join(f.base, "sites"), f.j)
	if e != nil {
		t.Fatal("owned reopen")
	}
	f.bind()
	unchanged(t, f, func() {
		p2, e := f.s.PreviewRestore(f.site.ID, sites.RestoreInput{BackupID: b.ID, ExpectedRevision: f.site.Revision})
		if e != nil || p2.Files[0].Path != "Alpha.txt" {
			t.Fatal("preview reopen/alias")
		}
	})
}

func TestRejectedInputsAndIntegrityAreByteReadOnly(t *testing.T) {
	for _, mode := range []string{"stale", "wrong_site", "missing", "invalid", "unsafe", "zero", "archive_corrupt", "archive_absent", "untracked", "content_conflict", "sealed_content", "pending", "state_corrupt", "closed"} {
		t.Run(mode, func(t *testing.T) {
			f := isolated(t)
			b := f.backup(t)
			id, input, want := f.site.ID, sites.RestoreInput{BackupID: b.ID, ExpectedRevision: f.site.Revision}, sites.ErrUnavailable
			root := filepath.Join(f.base, "sites", "data", id)
			switch mode {
			case "stale":
				input.ExpectedRevision--
				want = sites.ErrConflict
			case "wrong_site":
				v, e := f.s.Create(sites.CreateInput{Name: "Other", Domain: "other-review.test"}, "local-operator")
				if e != nil {
					t.Fatal("other setup")
				}
				id = v.ID
				input.ExpectedRevision = v.Revision
				want = sites.ErrNotFound
			case "missing":
				input.BackupID = strings.Repeat("b", 32)
				want = sites.ErrNotFound
			case "invalid":
				input.BackupID = "../invalid"
				want = sites.ErrInvalid
			case "unsafe":
				input.ExpectedRevision = 9007199254740992
				want = sites.ErrInvalid
			case "zero":
				input.ExpectedRevision = 0
				want = sites.ErrInvalid
			case "archive_corrupt":
				mustWrite(t, filepath.Join(root, "backups", b.ID+".zip"), []byte("corrupt"))
			case "archive_absent":
				if os.Remove(filepath.Join(root, "backups", b.ID+".zip")) != nil {
					t.Fatal("archive removal setup")
				}
			case "untracked":
				mustWrite(t, filepath.Join(root, "content", "untracked.txt"), []byte("external"))
			case "content_conflict":
				mustWrite(t, filepath.Join(root, "content", "index.html"), []byte("external"))
				want = sites.ErrConflict
			case "sealed_content":
				f.write(t, "index.html", "sealed owned content")
				input.ExpectedRevision = f.site.Revision
				mustWrite(t, filepath.Join(root, "content", "index.html"), []byte("external after seal"))
			case "pending":
				editRow(t, f, false, func(r *row) { r.Pending = &pending{Action: "restore", Checkpoints: []string{}} })
			case "state_corrupt":
				mustWrite(t, filepath.Join(root, "state.json"), []byte("{}"))
			case "closed":
				if f.s.Close() != nil {
					t.Fatal("close setup")
				}
			}
			unchanged(t, f, func() {
				_, e := f.s.PreviewRestore(id, input)
				if !errors.Is(e, want) {
					t.Fatalf("classification mismatch mode %s", mode)
				}
			})
		})
	}
}
func mustWrite(t *testing.T, p string, b []byte) {
	t.Helper()
	if os.WriteFile(p, b, 0600) != nil {
		t.Fatal("owned fixture write")
	}
}

func TestStrictWireShapeAndAdmissionBeforeParse(t *testing.T) {
	f := isolated(t)
	b := f.backup(t)
	id := b.ID
	valid := payload(id, f.site.Revision)
	for name, body := range map[string]string{"absent_id": `{"expected_revision":2}`, "absent_revision": `{"backup_id":"` + id + `"}`, "null_id": `{"backup_id":null,"expected_revision":2}`, "null_revision": `{"backup_id":"` + id + `","expected_revision":null}`, "alias_id": `{"Backup_id":"` + id + `","expected_revision":2}`, "alias_revision": `{"backup_id":"` + id + `","Expected_revision":2}`, "duplicate": `{"backup_id":"` + id + `","backup_id":"` + id + `","expected_revision":2}`, "duplicate_revision": `{"backup_id":"` + id + `","expected_revision":2,"expected_revision":2}`, "string_revision": `{"backup_id":"` + id + `","expected_revision":"2"}`, "unknown": `{"backup_id":"` + id + `","expected_revision":2,"content":"private-payload-marker"}`, "fraction": `{"backup_id":"` + id + `","expected_revision":2.0}`, "array": `[]`, "trailing": valid + `{}`} {
		t.Run(name, func(t *testing.T) {
			unchanged(t, f, func() {
				w := f.req(f.path(), body, nil)
				mustStatus(t, w, 400)
				if strings.Contains(w.Body.String(), "private-payload-marker") {
					t.Fatal("input echo")
				}
			})
		})
	}
	for _, tc := range []struct {
		name   string
		adjust func(*http.Request)
		want   int
	}{{"no_session", func(r *http.Request) { r.Header.Del("Cookie") }, 401}, {"no_csrf", func(r *http.Request) { r.Header.Del("X-CSRF-Token") }, 403}, {"wrong_csrf", func(r *http.Request) { r.Header.Set("X-CSRF-Token", "wrong") }, 403}, {"no_origin", func(r *http.Request) { r.Header.Del("Origin") }, 403}, {"wrong_origin", func(r *http.Request) { r.Header.Set("Origin", "http://localhost:8181") }, 403}, {"remote_peer", func(r *http.Request) { r.RemoteAddr = "192.0.2.10:43111" }, 403}, {"remote_host", func(r *http.Request) { r.Host = "remote.invalid" }, 403}, {"cross_site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403}} {
		t.Run(tc.name, func(t *testing.T) {
			reader := &countReader{}
			unchanged(t, f, func() {
				w := f.req(f.path(), "", func(r *http.Request) { r.Body = reader; tc.adjust(r) })
				mustStatus(t, w, tc.want)
			})
			if reader.reads != 0 {
				t.Fatal("body parsed before admission")
			}
		})
	}
	unchanged(t, f, func() {
		mustStatus(t, f.req(f.path(), strings.Repeat(" ", 4097), nil), 413)
		mustStatus(t, f.req(f.path(), valid, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }), 415)
		mustStatus(t, f.req(f.path(), payload(id, 9007199254740992), nil), 422)
	})
	unchanged(t, f, func() { validate(t, f, b, f.req(f.path(), valid+strings.Repeat(" ", 4096-len(valid)), nil)) })
}

type countReader struct{ reads int }

func (r *countReader) Read([]byte) (int, error) { r.reads++; return 0, errors.New("must not read") }
func (*countReader) Close() error               { return nil }

// This canonical metadata editing seam is confined to owned closed TempDir state.
// It constructs explicit synthetic states, not observed crashes or native replay.
type pending struct {
	Action      string   `json:"action"`
	Checkpoints []string `json:"checkpoints"`
}
type row struct {
	Version   int                `json:"version"`
	Site      sites.Site         `json:"site"`
	Owner     string             `json:"owner"`
	Files     []sites.FileInfo   `json:"files"`
	Backups   []sites.BackupInfo `json:"backups"`
	ChangeIDs []string           `json:"change_ids"`
	Pending   *pending           `json:"pending,omitempty"`
}

func editRow(t *testing.T, f *fixture, seal bool, edit func(*row)) {
	t.Helper()
	if f.s.Close() != nil {
		t.Fatal("closed fixture admission")
	}
	f.s = nil
	db, e := bolt.Open(filepath.Join(f.base, "sites", "sites.db"), 0600, &bolt.Options{Timeout: time.Second})
	if e != nil {
		t.Fatal("synthetic DB admission")
	}
	defer func() {
		if db != nil && db.Close() != nil {
			t.Error("synthetic DB cleanup")
		}
	}()
	var r row
	e = db.View(func(tx *bolt.Tx) error {
		return json.Unmarshal(tx.Bucket([]byte("sites-v1")).Get([]byte(f.site.ID)), &r)
	})
	if e != nil {
		t.Fatal("synthetic row read")
	}
	edit(&r)
	cp := ""
	if seal {
		summary, e := f.j.Checkpoint(filepath.Join(f.base, "sites", "data", f.site.ID), []string{"state.json"}, "owned synthetic preview fixture", "local-operator")
		if e != nil {
			t.Fatal("synthetic checkpoint")
		}
		cp = summary.ID
		r.ChangeIDs = []string{cp}
	}
	raw, e := json.Marshal(r)
	if e != nil {
		t.Fatal("synthetic encode")
	}
	if seal {
		mustWrite(t, filepath.Join(f.base, "sites", "data", f.site.ID, "state.json"), raw)
		if _, e = f.j.Seal(cp); e != nil {
			t.Fatal("synthetic seal")
		}
	}
	e = db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("sites-v1")).Put([]byte(f.site.ID), raw) })
	ce := db.Close()
	db = nil
	if e != nil || ce != nil {
		t.Fatal("synthetic row commit/close")
	}
	f.s, e = sites.Open(filepath.Join(f.base, "sites"), f.j)
	if e != nil {
		t.Fatal("synthetic reopen")
	}
	f.site = r.Site
	f.bind()
}
func catalog(data map[string][]byte) []sites.FileInfo {
	out := []sites.FileInfo{}
	for p, b := range data {
		out = append(out, sites.FileInfo{Path: p, Bytes: int64(len(b)), SHA256: digest(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
func syntheticCurrent(t *testing.T, f *fixture, data map[string][]byte) {
	t.Helper()
	root := filepath.Join(f.base, "sites", "data", f.site.ID, "content")
	entries, e := os.ReadDir(root)
	if e != nil {
		t.Fatal("owned content inventory")
	}
	for _, x := range entries {
		if !x.Type().IsRegular() || os.Remove(filepath.Join(root, x.Name())) != nil {
			t.Fatal("owned simple fixture removal")
		}
	}
	for p, b := range data {
		mustWrite(t, filepath.Join(root, p), b)
	}
	editRow(t, f, true, func(r *row) { r.Site.Revision++; r.Files = catalog(data) })
}
func nativeZIP(t *testing.T, data map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	manifest, _ := json.Marshal(struct {
		Version  int              `json:"version"`
		BackupID string           `json:"backup_id"`
		SiteID   string           `json:"site_id"`
		Revision uint64           `json:"revision"`
		Files    []sites.FileInfo `json:"files"`
	}{1, strings.Repeat("a", 32), strings.Repeat("b", 32), 1, catalog(data)})
	add := func(p string, b []byte) {
		h := &zip.FileHeader{Name: p, Method: zip.Deflate}
		h.SetMode(0600)
		w, e := z.CreateHeader(h)
		if e != nil {
			t.Fatal("synthetic ZIP header")
		}
		if _, e = w.Write(b); e != nil {
			t.Fatal("synthetic ZIP write")
		}
	}
	add("manifest.json", manifest)
	for _, v := range catalog(data) {
		add("files/"+v.Path, data[v.Path])
	}
	if z.Close() != nil {
		t.Fatal("synthetic ZIP cleanup")
	}
	return buf.Bytes()
}
func TestFull128UnionCrossSnapshotAliasesAndRevisionCeiling(t *testing.T) {
	t.Run("128_union", func(t *testing.T) {
		f := isolated(t)
		a, c := map[string][]byte{}, map[string][]byte{}
		for i := 0; i < 64; i++ {
			a[fmt.Sprintf("a%02d.txt", i)] = []byte{byte(i)}
			c[fmt.Sprintf("c%02d.txt", i)] = []byte{byte(63 - i)}
		}
		v, e := f.s.ImportArchive(sites.ImportInput{Name: "Union fixture", Domain: "union-review.test", Archive: nativeZIP(t, a)}, "local-operator")
		if e != nil {
			t.Fatal("actual native import")
		}
		f.site = v
		b := f.backup(t)
		syntheticCurrent(t, f, c)
		unchanged(t, f, func() {
			p := validate(t, f, b, f.req(f.path(), payload(b.ID, f.site.Revision), nil))
			if len(p.Files) != 128 || p.Counts != (sites.RestorePreviewCounts{Added: 64, Removed: 64}) {
				t.Fatal("full bounded union")
			}
		})
	})
	t.Run("case_alias", func(t *testing.T) {
		f := isolated(t)
		f.write(t, "Case.txt", "selected archive")
		b := f.backup(t)
		syntheticCurrent(t, f, map[string][]byte{"case.txt": []byte("current")})
		unchanged(t, f, func() {
			_, e := f.s.PreviewRestore(f.site.ID, sites.RestoreInput{BackupID: b.ID, ExpectedRevision: f.site.Revision})
			if !errors.Is(e, sites.ErrUnavailable) {
				t.Fatal("cross-snapshot alias admitted")
			}
		})
	})
	t.Run("max_safe_readable", func(t *testing.T) {
		f := isolated(t)
		b := f.backup(t)
		editRow(t, f, true, func(r *row) { r.Site.Revision = 9007199254740991 })
		unchanged(t, f, func() {
			p := validate(t, f, b, f.req(f.path(), payload(b.ID, f.site.Revision), nil))
			if p.CurrentRevision != 9007199254740991 {
				t.Fatal("MAX_SAFE preview unreadable")
			}
		})
	})
}

func TestConcurrentPreviewAndMutationRemainSerial(t *testing.T) {
	for _, mode := range []string{"write", "backup", "scheduler"} {
		t.Run(mode, func(t *testing.T) {
			f := isolated(t)
			b := f.backup(t)
			beforeRevision := f.site.Revision
			beforeFile, e := f.s.ReadFile(f.site.ID, "index.html")
			if e != nil {
				t.Fatal("current content")
			}
			due := time.Now().UTC().Add(2 * time.Hour)
			if mode == "scheduler" {
				on := true
				if _, e = f.s.SetBackupSchedule(f.site.ID, sites.BackupScheduleInput{ExpectedRevision: beforeRevision, Interval: "hourly", Enabled: &on}, "local-operator"); e != nil {
					t.Fatal("schedule setup")
				}
			}
			start := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(2)
			var p sites.RestorePreview
			var pe, me error
			go func() {
				defer wg.Done()
				<-start
				p, pe = f.s.PreviewRestore(f.site.ID, sites.RestoreInput{BackupID: b.ID, ExpectedRevision: beforeRevision})
			}()
			go func() {
				defer wg.Done()
				<-start
				switch mode {
				case "write":
					_, me = f.s.WriteFile(f.site.ID, sites.WriteInput{Path: "index.html", Content: "serialized new content", ExpectedSHA256: beforeFile.SHA256, ExpectedRevision: beforeRevision}, "local-operator")
				case "backup":
					_, me = f.s.Backup(f.site.ID, beforeRevision, "local-operator")
				case "scheduler":
					_, me = f.s.RunDueBackups(due)
				}
			}()
			close(start)
			wg.Wait()
			if me != nil {
				t.Fatal("concurrent mutation failed")
			}
			if pe != nil && !errors.Is(pe, sites.ErrConflict) {
				t.Fatal("preview crossed serialized boundary")
			}
			if pe == nil && (p.CurrentRevision != beforeRevision || len(p.Files) != 1 || p.Files[0].Before.SHA256 != beforeFile.SHA256) {
				t.Fatal("mixed snapshot")
			}
			f.current(t)
			if f.site.Revision != beforeRevision+1 {
				t.Fatal("mutation count differs")
			}
			unchanged(t, f, func() {
				_, e := f.s.PreviewRestore(f.site.ID, sites.RestoreInput{BackupID: b.ID, ExpectedRevision: beforeRevision})
				if !errors.Is(e, sites.ErrConflict) {
					t.Fatal("stale preview after mutation")
				}
			})
		})
	}
}

func TestRehashedStoredZIPStillRequiresExactNativeMetadata(t *testing.T) {
	f := isolated(t)
	b := f.backup(t)
	// Actual independently constructed native ZIP has valid structure and content
	// hashes but its manifest belongs to another source site and backup identity.
	raw := nativeZIP(t, map[string][]byte{"index.html": []byte("wrong manifest source")})
	mustWrite(t, filepath.Join(f.base, "sites", "data", f.site.ID, "backups", b.ID+".zip"), raw)
	editRow(t, f, true, func(r *row) {
		r.Site.Revision++
		r.Backups[0].Bytes = int64(len(raw))
		r.Backups[0].SHA256 = digest(raw)
		r.Backups[0].Files = 1
	})
	if _, e := f.s.Get(f.site.ID); e != nil {
		t.Fatal("rehash fixture current checkpoint invalid")
	}
	unchanged(t, f, func() { mustStatus(t, f.req(f.path(), payload(b.ID, f.site.Revision), nil), 503) })
}
