//go:build linux

package hostaccounts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"sifruno/internal/sitefiles"
)

// brokerClient is a client wired to the broker's real handler over a real
// connection, so request and answer streams and their bounds are the ones
// the socket carries.
func brokerClient(t *testing.T, s *store) *client {
	t.Helper()
	srv := httptest.NewServer(handler(s))
	t.Cleanup(srv.Close)
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
	}
	h := &http.Client{Timeout: time.Minute, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: dial}}
	return &client{configured: true, http: h, slow: h, long: h}
}

func fileError(t *testing.T, err error, code string) {
	t.Helper()
	var failed *FileError
	if !errors.As(err, &failed) || failed.Code != code || !errors.Is(err, ErrFileFailed) {
		t.Fatalf("got %v, want the helper's %q", err, code)
	}
}

func TestFilesThroughTheBrokerAsTheSiteUser(t *testing.T) {
	s, f := webStore(t)
	a := createFixture(t, s)
	before := recordFor(t, s, a.ID)
	c := brokerClient(t, s)
	ctx := context.Background()
	const actor = "test operator"
	if _, err := c.MakeFolder(ctx, a.ID, "public_html", actor); err != nil {
		t.Fatal(err)
	}
	page := "<?php echo 'hello';\n"
	written, err := c.WriteFile(ctx, a.ID, FileWriteInput{Path: "public_html/index.php", Content: page}, actor)
	if err != nil || written.Size != int64(len(page)) || written.Mode != "0644" {
		t.Fatalf("write %+v %v", written, err)
	}
	text, err := c.ReadFile(ctx, a.ID, "public_html/index.php", actor)
	if err != nil || text.Content != page || text.File.Version != written.Version {
		t.Fatalf("read %+v %v", text, err)
	}
	// A save from a page that loaded an older version is refused.
	if _, err := c.WriteFile(ctx, a.ID, FileWriteInput{Path: "public_html/index.php", Content: "x", ExpectedVersion: strings.Repeat("0", 16)}, actor); err == nil {
		t.Fatal("a stale save must be refused")
	} else {
		fileError(t, err, sitefiles.ErrChanged)
	}

	// An upload and a download stream through the broker, bytes exact.
	data := bytes.Repeat([]byte("sifruno\x00\xff"), 400_000)
	up, err := c.UploadFile(ctx, a.ID, FileUploadInput{Path: "public_html/site.zip", Size: int64(len(data))}, bytes.NewReader(data), actor)
	if err != nil || up.Size != int64(len(data)) {
		t.Fatalf("upload %+v %v", up, err)
	}
	if _, err := c.UploadFile(ctx, a.ID, FileUploadInput{Path: "public_html/site.zip", Size: 1}, strings.NewReader("x"), actor); err == nil {
		t.Fatal("an upload over a file without overwrite must be refused")
	} else {
		fileError(t, err, sitefiles.ErrExists)
	}
	entry, body, err := c.DownloadFile(ctx, a.ID, "public_html/site.zip", actor)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(body)
	body.Close()
	if err != nil || entry.Size != int64(len(data)) || !bytes.Equal(got, data) {
		t.Fatalf("download %+v: %d bytes, %v", entry, len(got), err)
	}

	// A tenant's link to /etc/shadow is listed as a link and never read.
	if err := os.Symlink("/etc/shadow", filepath.Join(a.Home, "public_html", "shadow.txt")); err != nil {
		t.Fatal(err)
	}
	list, err := c.ListFiles(ctx, a.ID, "public_html", actor)
	if err != nil || len(list.Entries) != 3 {
		t.Fatalf("list %+v %v", list, err)
	}
	for _, e := range list.Entries {
		if e.Name == "shadow.txt" && e.Type != "link" {
			t.Fatalf("the link must be listed as a link: %+v", e)
		}
	}
	_, err = c.ReadFile(ctx, a.ID, "public_html/shadow.txt", actor)
	fileError(t, err, sitefiles.ErrIsLink)
	_, _, err = c.DownloadFile(ctx, a.ID, "public_html/shadow.txt", actor)
	fileError(t, err, sitefiles.ErrIsLink)

	// Rename, mode, and a delete of a folder holding a link to a folder
	// outside the home: the link goes, its target stays.
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "keep.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.MakeFolder(ctx, a.ID, "old", actor); err != nil {
		t.Fatal(err)
	}
	os.Symlink(outside, filepath.Join(a.Home, "old", "elsewhere"))
	if moved, err := c.RenameFile(ctx, a.ID, "public_html/site.zip", "old/site.zip", actor); err != nil || moved.Name != "site.zip" {
		t.Fatalf("rename %+v %v", moved, err)
	}
	if e, err := c.SetFileMode(ctx, a.ID, "public_html/index.php", "0600", actor); err != nil || e.Mode != "0600" {
		t.Fatalf("mode %+v %v", e, err)
	}
	if _, err := c.SetFileMode(ctx, a.ID, "public_html/index.php", "4755", actor); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a setuid mode must be refused before it is sent: %v", err)
	}
	if gone, err := c.DeleteFile(ctx, a.ID, "old", actor); err != nil || gone.Type != "folder" {
		t.Fatalf("delete %+v %v", gone, err)
	}
	if b, err := os.ReadFile(filepath.Join(outside, "keep.txt")); err != nil || string(b) != "keep" {
		t.Fatal("a folder delete went through a link")
	}

	// Nothing of this is journaled: the record is as it was.
	if after := recordFor(t, s, a.ID); after != before {
		t.Fatalf("file operations changed the account record: %+v", after.Account)
	}
	if len(s.fileRuns) != 0 || len(s.installing) != 0 {
		t.Fatal("a finished file operation left the account counted as running")
	}
	if f.fileRuns() == 0 {
		t.Fatal("no run reached the helper")
	}
}

func TestFilesRefusalsBeforeTheHelper(t *testing.T) {
	s, f := webStore(t)
	a := createFixture(t, s)
	ctx := context.Background()
	list := sitefiles.Request{Op: sitefiles.OpList}
	write := sitefiles.Request{Op: sitefiles.OpMkdir, Path: "new"}
	run := func(id, actor string, req sitefiles.Request) error {
		_, err := s.runFile(ctx, id, actor, req, nil, nil)
		return err
	}
	for name, tc := range map[string]struct {
		id, actor string
		req       sitefiles.Request
		want      error
	}{
		"bad id":           {"../" + a.ID, "op", list, ErrInvalid},
		"no actor":         {a.ID, "", list, ErrInvalid},
		"absolute path":    {a.ID, "op", sitefiles.Request{Op: sitefiles.OpList, Path: "/etc"}, ErrInvalid},
		"traversal":        {a.ID, "op", sitefiles.Request{Op: sitefiles.OpRead, Path: "public_html/../../x"}, ErrInvalid},
		"NUL":              {a.ID, "op", sitefiles.Request{Op: sitefiles.OpMkdir, Path: "a\x00b"}, ErrInvalid},
		"long name":        {a.ID, "op", sitefiles.Request{Op: sitefiles.OpMkdir, Path: strings.Repeat("n", 256)}, ErrInvalid},
		"unknown op":       {a.ID, "op", sitefiles.Request{Op: "exec", Path: "x"}, ErrInvalid},
		"unknown account":  {strings.Repeat("e", 32), "op", list, ErrNotFound},
		"read with a body": {a.ID, "op", sitefiles.Request{Op: sitefiles.OpUpload, Path: "x", Size: 1}, ErrInvalid},
	} {
		if err := run(tc.id, tc.actor, tc.req); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	if f.fileRuns() != 0 {
		t.Fatal("a refused request reached the helper")
	}

	// Suspended: reads still work, changes wait for a resume.
	suspended, err := s.setState(ctx, a.ID, StateInput{State: "suspended", ExpectedRevision: a.Revision, Reason: "Unpaid"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	if err := run(a.ID, "op", list); err != nil {
		t.Fatalf("a suspended site's files must list: %v", err)
	}
	if err := run(a.ID, "op", write); !errors.Is(err, ErrConflict) {
		t.Fatalf("a change to a suspended site: %v", err)
	}
	if _, err := s.setState(ctx, a.ID, StateInput{State: "active", ExpectedRevision: suspended.Revision, Reason: "Paid"}, "test operator"); err != nil {
		t.Fatal(err)
	}
	// A WordPress install or restore writing into the home holds changes,
	// not reads.
	s.mu.Lock()
	s.installing = map[string]bool{a.ID: true}
	s.mu.Unlock()
	if err := run(a.ID, "op", list); err != nil {
		t.Fatalf("a read during an install: %v", err)
	}
	if err := run(a.ID, "op", write); !errors.Is(err, ErrConflict) {
		t.Fatalf("a change during an install: %v", err)
	}
	s.mu.Lock()
	s.installing = nil
	s.mu.Unlock()

	// The web operation off: no site steps run at all.
	web := s.web
	s.web = nil
	if err := run(a.ID, "op", list); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("files with the web operation off: %v", err)
	}
	s.web = web

	// A helper that fails is unavailable, not a refusal of the helper's.
	f.files.fail = true
	if err := run(a.ID, "op", list); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a failed helper: %v", err)
	}
	f.files.fail = false
}

// Another account's unfinished operation does not stop a file operation;
// the account's own does. A file operation never marks the account busy,
// so a suspend runs while one is in flight.
func TestFilesAndPendingOperations(t *testing.T) {
	s, f := webStore(t)
	ctx := context.Background()
	a := createFixture(t, s)
	other := createFixtureNamed(t, s, "secondacct", "second.test")
	// What a refresh journals when it finds the other account's identity
	// changed: a conflict that stops every mutation of every account.
	r := recordFor(t, s, other.ID)
	before := r.Account
	r.Pending = &pending{Action: "conflict", Target: r.Account.State, Actor: "broker-reconcile", Reason: "Managed operating system identity changed"}
	s.mu.Lock()
	r, err := s.beginOperation(r, &before)
	if err == nil {
		_, err = s.resultEvent(r, *r.Pending, "recovery_required")
	}
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.setPlan(ctx, a.ID, PlanInput{Plan: "larger", ExpectedRevision: a.Revision, Reason: "Plan"}, "test operator"); !errors.Is(err, ErrRecovery) {
		t.Fatalf("the conflict must stop mutations: %v", err)
	}
	list := sitefiles.Request{Op: sitefiles.OpList}
	if _, err := s.runFile(ctx, a.ID, "op", list, nil, nil); err != nil {
		t.Fatalf("another account's unfinished operation stopped a file list: %v", err)
	}
	if _, err := s.runFile(ctx, a.ID, "op", sitefiles.Request{Op: sitefiles.OpMkdir, Path: "made"}, nil, nil); err != nil {
		t.Fatalf("another account's unfinished operation stopped a file change: %v", err)
	}
	if _, err := s.runFile(ctx, other.ID, "op", list, nil, nil); !errors.Is(err, ErrRecovery) {
		t.Fatalf("the account's own unfinished operation: %v", err)
	}

	// Hold runs open: four may run for one account, a fifth waits its turn
	// as a conflict, and another account still runs.
	s2, f2 := webStore(t)
	one := createFixture(t, s2)
	two := createFixtureNamed(t, s2, "secondacct", "second.test")
	f2.files.started = make(chan string, 8)
	f2.files.gate = make(chan struct{})
	errs := make(chan error, maxFileRuns)
	for range maxFileRuns {
		go func() {
			_, err := s2.runFile(ctx, one.ID, "op", list, nil, nil)
			errs <- err
		}()
	}
	for range maxFileRuns {
		<-f2.files.started
	}
	if _, err := s2.runFile(ctx, one.ID, "op", list, nil, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("a fifth run for one account: %v", err)
	}
	// The account is not busy: its suspend goes ahead meanwhile.
	if _, err := s2.setState(ctx, one.ID, StateInput{State: "suspended", ExpectedRevision: one.Revision, Reason: "Unpaid"}, "test operator"); err != nil {
		t.Fatalf("a suspend while file operations run: %v", err)
	}
	other2 := make(chan error, 1)
	go func() {
		_, err := s2.runFile(ctx, two.ID, "op", list, nil, nil)
		other2 <- err
	}()
	if got := <-f2.files.started; got != two.Username {
		t.Fatalf("started %s", got)
	}
	close(f2.files.gate)
	for range maxFileRuns {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if err := <-other2; err != nil {
		t.Fatalf("another account's run: %v", err)
	}
	if len(s2.fileRuns) != 0 {
		t.Fatalf("runs left counted: %v", s2.fileRuns)
	}
	_ = f
}

func TestFilesHTTPContract(t *testing.T) {
	s, _ := webStore(t)
	a := createFixture(t, s)
	h := handler(s)
	post := func(op, contentType, body string, length int64) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "http://unix/v1/accounts/"+a.ID+"/files/"+op, strings.NewReader(body))
		req.Header.Set("Content-Type", contentType)
		req.ContentLength = length
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	jsonPost := func(op, body string) *httptest.ResponseRecorder {
		return post(op, "application/json", body, int64(len(body)))
	}
	if rec := jsonPost("mkdir", `{"input":{"path":"public_html"},"actor":"op"}`); rec.Code != 200 {
		t.Fatalf("mkdir %d %s", rec.Code, rec.Body)
	}
	// Each route takes only its own keys.
	for op, body := range map[string]string{
		"list":   `{"input":{"path":"","mode":"0644"},"actor":"op"}`,
		"rename": `{"input":{"path":"a","to":"b","overwrite":true},"actor":"op"}`,
		"read":   `{"input":{"path":"a"},"actor":"op","extra":1}`,
		"delete": `{"input":{"path":null},"actor":"op"}`,
		"mode":   `{"input":{"path":"a","mode":"0644"}}`,
		"exec":   `{"input":{"path":"a"},"actor":"op"}`,
	} {
		if rec := jsonPost(op, body); rec.Code != 400 && rec.Code != 404 {
			t.Errorf("%s %s: %d", op, body, rec.Code)
		}
	}
	if rec := jsonPost("delete", `{"input":{"path":"public_html"},"actor":"op"}`); rec.Code != 200 {
		t.Fatalf("a files delete must not reach the account delete: %d %s", rec.Code, rec.Body)
	}
	jsonPost("mkdir", `{"input":{"path":"public_html"},"actor":"op"}`)

	// An upload is one JSON line and exactly its size in bytes.
	frame := func(op, input, data string) (string, int64) {
		line := `{"input":` + input + `,"actor":"op"}` + "\n"
		return line + data, int64(len(line) + len(data))
	}
	body, n := frame("upload", `{"path":"public_html/a.txt","size":5,"overwrite":false}`, "hello")
	if rec := post("upload", "application/octet-stream", body, n); rec.Code != 200 {
		t.Fatalf("upload %d %s", rec.Code, rec.Body)
	}
	if b, _ := os.ReadFile(filepath.Join(a.Home, "public_html", "a.txt")); string(b) != "hello" {
		t.Fatalf("uploaded %q", b)
	}
	for name, tc := range map[string]struct {
		contentType, body string
		length            int64
	}{
		"json content type": {"application/json", body, n},
		"length over":       {"application/octet-stream", body, n + 1},
		"length under":      {"application/octet-stream", body, n - 1},
		"unknown key":       {"application/octet-stream", strings.Replace(body, `"overwrite":false`, `"overwrite":false,"mode":"0777"`, 1), n + 14},
		"missing key":       {"application/octet-stream", strings.Replace(body, `,"overwrite":false`, ``, 1), n - 18},
		"over the bound": func() struct {
			contentType, body string
			length            int64
		} {
			b, l := frame("upload", `{"path":"public_html/big","size":`+strconv.Itoa(sitefiles.MaxUploadBytes+1)+`,"overwrite":false}`, "")
			return struct {
				contentType, body string
				length            int64
			}{"application/octet-stream", b, l + sitefiles.MaxUploadBytes + 1}
		}(),
	} {
		if rec := post("upload", tc.contentType, tc.body, tc.length); rec.Code != 400 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	// A refusal of the helper's names its reason.
	body, n = frame("upload", `{"path":"public_html/a.txt","size":5,"overwrite":false}`, "again")
	rec := post("upload", "application/octet-stream", body, n)
	var failure struct{ Error, Reason string }
	if rec.Code != 422 || json.Unmarshal(rec.Body.Bytes(), &failure) != nil || failure.Error != "file_failed" || failure.Reason != sitefiles.ErrExists {
		t.Fatalf("refused upload %d %s", rec.Code, rec.Body)
	}
	// A download is the entry's line, then exactly its bytes.
	rec = jsonPost("download", `{"input":{"path":"public_html/a.txt"},"actor":"op"}`)
	line, rest, _ := strings.Cut(rec.Body.String(), "\n")
	var e FileEntry
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/octet-stream" || json.Unmarshal([]byte(line), &e) != nil || e.Size != 5 || rest != "hello" ||
		rec.Header().Get("Content-Length") != strconv.Itoa(len(line)+1+5) {
		t.Fatalf("download %d %v %q", rec.Code, rec.Header(), rec.Body)
	}
	// A read of a binary file is refused as such, before any bytes.
	os.WriteFile(filepath.Join(a.Home, "public_html", "logo.png"), []byte("\x89PNG\x00"), 0o644)
	rec = jsonPost("read", `{"input":{"path":"public_html/logo.png"},"actor":"op"}`)
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), `"reason":"binary"`) {
		t.Fatalf("binary read %d %s", rec.Code, rec.Body)
	}
}

// The client refuses what the broker would before it connects, and checks
// the broker's answers again.
func TestFilesClientChecks(t *testing.T) {
	c, ok := NewClient("").(FilesService)
	if !ok {
		t.Fatal("the client has no file operations")
	}
	ctx := context.Background()
	id := strings.Repeat("a", 32)
	if _, err := c.ListFiles(ctx, id, "", "operator"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no socket: %v", err)
	}
	for name, err := range map[string]error{
		"bad id":    func() error { _, err := c.ListFiles(ctx, "../x", "", "operator"); return err }(),
		"no actor":  func() error { _, err := c.ListFiles(ctx, id, "", ""); return err }(),
		"traversal": func() error { _, err := c.ReadFile(ctx, id, "../etc/passwd", "operator"); return err }(),
		"absolute":  func() error { _, _, err := c.DownloadFile(ctx, id, "/etc/shadow", "operator"); return err }(),
		"binary": func() error {
			_, err := c.WriteFile(ctx, id, FileWriteInput{Path: "a", Content: "a\x00"}, "operator")
			return err
		}(),
		"setuid": func() error { _, err := c.SetFileMode(ctx, id, "a", "4755", "operator"); return err }(),
		"too large": func() error {
			_, err := c.UploadFile(ctx, id, FileUploadInput{Path: "a", Size: sitefiles.MaxUploadBytes + 1}, strings.NewReader(""), "operator")
			return err
		}(),
		"no body": func() error {
			_, err := c.UploadFile(ctx, id, FileUploadInput{Path: "a", Size: 1}, nil, "operator")
			return err
		}(),
		"into itself": func() error { _, err := c.RenameFile(ctx, id, "a", "a/b", "operator"); return err }(),
	} {
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// A broker answer that breaks the rules is not passed on.
	answer := func(status int, contentType, body string) *client {
		return &client{configured: true, slow: &http.Client{Transport: previewRoundTrip(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {contentType}}, Body: io.NopCloser(strings.NewReader(body)), ContentLength: -1, Request: r}, nil
		})}}
	}
	when := `"modified":"2026-11-24T10:00:00Z"`
	if _, err := answer(200, "application/json", `{"path":"","entries":[{"name":"../x","type":"file","size":1,"mode":"0644",`+when+`,"version":"0123456789abcdef"}],"skipped":0,"truncated":false}`).ListFiles(ctx, id, "", "op"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a bad name in a list: %v", err)
	}
	short := `{"name":"a.txt","type":"file","size":10,"mode":"0644",` + when + `,"version":"0123456789abcdef"}` + "\nabc"
	if _, err := answer(200, "application/octet-stream", short).ReadFile(ctx, id, "a.txt", "op"); err == nil {
		t.Fatal("a read that ends before its size must fail")
	}
	other := `{"name":"b.txt","type":"file","size":3,"mode":"0644",` + when + `,"version":"0123456789abcdef"}` + "\nabc"
	if _, err := answer(200, "application/octet-stream", other).ReadFile(ctx, id, "a.txt", "op"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("an answer about another file: %v", err)
	}
	if _, err := answer(422, "application/json", `{"error":"file_failed","reason":"quota"}`).MakeFolder(ctx, id, "a", "op"); err == nil {
		t.Fatal("a refusal must be an error")
	} else {
		fileError(t, err, sitefiles.ErrQuota)
	}
	if _, err := answer(422, "application/json", `{"error":"file_failed","reason":"something new"}`).MakeFolder(ctx, id, "a", "op"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("an unknown reason: %v", err)
	}
}
