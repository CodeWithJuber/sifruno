package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"

	"sifruno/internal/hostaccounts"
	"sifruno/internal/operator"
	"sifruno/internal/sitefiles"
	"sifruno/internal/wizard"
)

// filesBroker is the sites broker with the file operations. Each account's
// home is a temporary folder, and each operation runs the real helper code
// (sitefiles.Serve) there, as the broker runs it as the site's user.
// fileErr, when set, is the answer instead; uploaded counts the bytes an
// upload read from the panel's stream.
type filesBroker struct {
	*sitesBroker
	t        *testing.T
	fmu      sync.Mutex
	homes    map[string]string
	calls    []string
	fileErr  error
	uploaded int64
}

func (b *filesBroker) home(id string) string {
	b.fmu.Lock()
	defer b.fmu.Unlock()
	if b.homes == nil {
		b.homes = map[string]string{}
	}
	if b.homes[id] == "" {
		b.homes[id] = b.t.TempDir()
	}
	return b.homes[id]
}

func (b *filesBroker) serve(id, actor string, req sitefiles.Request, body io.Reader) (sitefiles.Answer, *bufio.Reader, error) {
	b.fmu.Lock()
	b.calls = append(b.calls, req.Op+" "+req.Path+" actor="+actor)
	failure := b.fileErr
	b.fmu.Unlock()
	if failure != nil {
		return sitefiles.Answer{}, nil, failure
	}
	line, err := sitefiles.EncodeLine(req)
	if err != nil {
		return sitefiles.Answer{}, nil, hostaccounts.ErrInvalid
	}
	in := io.Reader(bytes.NewReader(line))
	if body != nil {
		in = io.MultiReader(in, body)
	}
	home, err := os.OpenFile(b.home(id), os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return sitefiles.Answer{}, nil, hostaccounts.ErrUnavailable
	}
	defer home.Close()
	var out bytes.Buffer
	if sitefiles.Serve(home, in, &out) != nil {
		return sitefiles.Answer{}, nil, hostaccounts.ErrUnavailable
	}
	br := bufio.NewReader(&out)
	answer, err := sitefiles.ReadLine(br, sitefiles.MaxAnswerLine)
	if err != nil {
		return sitefiles.Answer{}, nil, hostaccounts.ErrUnavailable
	}
	a, err := sitefiles.ParseAnswer(req, answer)
	if err != nil {
		return sitefiles.Answer{}, nil, hostaccounts.ErrUnavailable
	}
	if a.Error != "" {
		return sitefiles.Answer{}, nil, &hostaccounts.FileError{Code: a.Error}
	}
	return a, br, nil
}

func (b *filesBroker) ListFiles(_ context.Context, id, path, actor string) (hostaccounts.FileList, error) {
	a, _, err := b.serve(id, actor, sitefiles.Request{Op: sitefiles.OpList, Path: path}, nil)
	if err != nil {
		return hostaccounts.FileList{}, err
	}
	if a.Entries == nil {
		a.Entries = []hostaccounts.FileEntry{}
	}
	return hostaccounts.FileList{Path: path, Entries: a.Entries, Skipped: a.Skipped, Truncated: a.Truncated}, nil
}
func (b *filesBroker) ReadFile(_ context.Context, id, path, actor string) (hostaccounts.FileText, error) {
	a, rest, err := b.serve(id, actor, sitefiles.Request{Op: sitefiles.OpRead, Path: path}, nil)
	if err != nil {
		return hostaccounts.FileText{}, err
	}
	data, _ := io.ReadAll(rest)
	return hostaccounts.FileText{File: *a.File, Content: string(data)}, nil
}
func (b *filesBroker) WriteFile(_ context.Context, id string, in hostaccounts.FileWriteInput, actor string) (hostaccounts.FileEntry, error) {
	a, _, err := b.serve(id, actor, sitefiles.Request{Op: sitefiles.OpWrite, Path: in.Path, Size: int64(len(in.Content)), ExpectedVersion: in.ExpectedVersion}, strings.NewReader(in.Content))
	if err != nil {
		return hostaccounts.FileEntry{}, err
	}
	return *a.File, nil
}
func (b *filesBroker) UploadFile(_ context.Context, id string, in hostaccounts.FileUploadInput, body io.Reader, actor string) (hostaccounts.FileEntry, error) {
	counted := &countingBody{r: body}
	a, _, err := b.serve(id, actor, sitefiles.Request{Op: sitefiles.OpUpload, Path: in.Path, Size: in.Size, Overwrite: in.Overwrite}, counted)
	b.fmu.Lock()
	b.uploaded += counted.n
	b.fmu.Unlock()
	if err != nil {
		return hostaccounts.FileEntry{}, err
	}
	return *a.File, nil
}
func (b *filesBroker) DownloadFile(_ context.Context, id, path, actor string) (hostaccounts.FileEntry, io.ReadCloser, error) {
	a, rest, err := b.serve(id, actor, sitefiles.Request{Op: sitefiles.OpDownload, Path: path}, nil)
	if err != nil {
		return hostaccounts.FileEntry{}, nil, err
	}
	return *a.File, io.NopCloser(rest), nil
}
func (b *filesBroker) MakeFolder(_ context.Context, id, path, actor string) (hostaccounts.FileEntry, error) {
	return b.entry(id, actor, sitefiles.Request{Op: sitefiles.OpMkdir, Path: path})
}
func (b *filesBroker) RenameFile(_ context.Context, id, from, to, actor string) (hostaccounts.FileEntry, error) {
	return b.entry(id, actor, sitefiles.Request{Op: sitefiles.OpRename, Path: from, To: to})
}
func (b *filesBroker) DeleteFile(_ context.Context, id, path, actor string) (hostaccounts.FileEntry, error) {
	return b.entry(id, actor, sitefiles.Request{Op: sitefiles.OpDelete, Path: path})
}
func (b *filesBroker) SetFileMode(_ context.Context, id, path, mode, actor string) (hostaccounts.FileEntry, error) {
	return b.entry(id, actor, sitefiles.Request{Op: sitefiles.OpMode, Path: path, Mode: mode})
}
func (b *filesBroker) entry(id, actor string, req sitefiles.Request) (hostaccounts.FileEntry, error) {
	a, _, err := b.serve(id, actor, req, nil)
	if err != nil {
		return hostaccounts.FileEntry{}, err
	}
	return *a.File, nil
}

type countingBody struct {
	r io.Reader
	n int64
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// filesFixture is a panel with one website, example.com, whose home is a
// temporary folder.
func filesFixture(t *testing.T) (siteFixture, *filesBroker, Website) {
	t.Helper()
	f := websiteFixture(t)
	store, err := wizard.OpenStore(filepath.Join(realTempDir(t), "wizard"))
	if err != nil {
		t.Fatal(err)
	}
	broker := &filesBroker{sitesBroker: &sitesBroker{}, t: t}
	runner := wizard.New(broker.sitesBroker, wizardDatabaseSpy{}, store, nil)
	t.Cleanup(runner.Wait)
	f.handler = New(Options{Operator: f.manager, Accounts: broker, Wizard: runner, AllowedOrigins: []string{"http://127.0.0.1:8080"}})
	job := makeSite(t, runner, "example.com", "8.3")
	broker.mu.Lock()
	account := broker.accounts[0]
	broker.mu.Unlock()
	return f, broker, website(account, job)
}

func filesURL(site Website, rest string) string {
	return "/api/v1/websites/sites/" + site.AccountID + "/files" + rest
}

// rawRequest sends body as it is, with its own content type and length.
func rawRequest(h http.Handler, method, path, contentType string, body io.Reader, length int64, cookie *http.Cookie, csrf, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, body)
	r.RemoteAddr = "127.0.0.1:14000"
	r.ContentLength = length
	if token == "" {
		r.Header.Set("Origin", "http://127.0.0.1:8080")
	} else {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func decodeFile(t *testing.T, w *httptest.ResponseRecorder) WebsiteFile {
	t.Helper()
	var e WebsiteFile
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &e) != nil || e.Name == "" {
		t.Fatalf("file answer %d: %s", w.Code, w.Body.String())
	}
	return e
}

func TestWebsiteFilesWorkOnTheHome(t *testing.T) {
	f, broker, site := filesFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	get := func(rest string) *httptest.ResponseRecorder {
		return websiteRequest(f.handler, "GET", filesURL(site, rest), nil, cookie, "")
	}
	post := func(action string, body any) *httptest.ResponseRecorder {
		return websiteRequest(f.handler, "POST", filesURL(site, "/"+action), body, cookie, csrf)
	}
	var folder WebsiteFolder
	if w := get(""); w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &folder) != nil || folder.Path != "" || folder.Entries == nil || len(folder.Entries) != 0 {
		t.Fatalf("empty home: %d %s", w.Code, w.Body.String())
	}
	if e := decodeFile(t, post("folder", map[string]string{"path": "public_html"})); e.Type != "folder" {
		t.Fatalf("folder %+v", e)
	}
	page := "<?php echo 'héllo';\n"
	saved := decodeFile(t, post("save", map[string]string{"path": "public_html/index.php", "content": page, "expected_version": ""}))
	if saved.Size != int64(len(page)) || saved.Mode != "0644" || len(saved.Version) != 16 {
		t.Fatalf("saved %+v", saved)
	}
	var text WebsiteFileText
	if w := get("/content?path=public_html%2Findex.php"); w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &text) != nil || text.Content != page || text.File.Version != saved.Version {
		t.Fatalf("read %d %s", w.Code, w.Body.String())
	}
	again := decodeFile(t, post("save", map[string]string{"path": "public_html/index.php", "content": "<?php echo 2;", "expected_version": saved.Version}))
	if w := post("save", map[string]string{"path": "public_html/index.php", "content": "lost", "expected_version": saved.Version}); w.Code != 409 || problemDetail(t, w) != filesChanged {
		t.Fatalf("stale save %d %s", w.Code, w.Body.String())
	}
	if b, _ := os.ReadFile(filepath.Join(broker.home(site.AccountID), "public_html", "index.php")); string(b) != "<?php echo 2;" {
		t.Fatalf("on disk %q", b)
	}
	_ = again

	// Upload streams the request's own bytes; download streams them back.
	data := bytes.Repeat([]byte("zip\x00\xff"), 200_000)
	upload := func(path, overwrite string, body []byte) *httptest.ResponseRecorder {
		return rawRequest(f.handler, "POST", filesURL(site, "/upload?path="+path+"&overwrite="+overwrite), "application/octet-stream", bytes.NewReader(body), int64(len(body)), cookie, csrf, "")
	}
	if e := decodeFile(t, upload("public_html%2Fs%C3%A9t%C3%A9.zip", "false", data)); e.Size != int64(len(data)) || e.Name != "sété.zip" {
		t.Fatalf("upload %+v", e)
	}
	if broker.uploaded != int64(len(data)) {
		t.Fatalf("the broker read %d of %d bytes", broker.uploaded, len(data))
	}
	if w := upload("public_html%2Fs%C3%A9t%C3%A9.zip", "false", []byte("x")); w.Code != 409 || !strings.Contains(problemDetail(t, w), "already there") {
		t.Fatalf("upload over a file %d %s", w.Code, w.Body.String())
	}
	if w := upload("public_html%2Fs%C3%A9t%C3%A9.zip", "true", data); w.Code != 200 {
		t.Fatalf("overwrite %d %s", w.Code, w.Body.String())
	}
	w := get("/download?path=public_html%2Fs%C3%A9t%C3%A9.zip")
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), data) || w.Header().Get("Content-Length") != strconv.Itoa(len(data)) ||
		w.Header().Get("Content-Type") != "application/octet-stream" || w.Header().Get("Content-Disposition") != `attachment; filename*=utf-8''s%C3%A9t%C3%A9.zip` {
		t.Fatalf("download %d %v (%d bytes)", w.Code, w.Header(), w.Body.Len())
	}

	// A tenant's link to /etc/shadow is listed as a link and never read.
	os.Symlink("/etc/shadow", filepath.Join(broker.home(site.AccountID), "public_html", "shadow"))
	if w := get("/content?path=public_html%2Fshadow"); w.Code != 422 || !strings.Contains(problemDetail(t, w), "never follows links") || problemTechnical(t, w) != "account service: file operation failed: is_link" {
		t.Fatalf("link read %d %s", w.Code, w.Body.String())
	}
	if w := get("/download?path=public_html%2Fshadow"); w.Code != 422 || w.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("link download %d %s", w.Code, w.Body.String())
	}
	folder = WebsiteFolder{}
	if w := get("?path=public_html"); w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &folder) != nil || len(folder.Entries) != 3 {
		t.Fatalf("list %d %s", w.Code, w.Body.String())
	}
	for _, e := range folder.Entries {
		if e.Name == "shadow" && (e.Type != "link" || e.Size != 0) {
			t.Fatalf("link listed as %+v", e)
		}
	}

	// Rename, mode and delete; the site's own folder is kept.
	if e := decodeFile(t, post("rename", map[string]string{"path": "public_html/sété.zip", "to": "backup.zip"})); e.Name != "backup.zip" {
		t.Fatalf("rename %+v", e)
	}
	if e := decodeFile(t, post("mode", map[string]string{"path": "public_html/index.php", "mode": "0600"})); e.Mode != "0600" {
		t.Fatalf("mode %+v", e)
	}
	for action, body := range map[string]map[string]string{
		"delete": {"path": "public_html"},
		"rename": {"path": "public_html", "to": "old_html"},
		"mode":   {"path": "public_html", "mode": "0700"},
	} {
		if w := post(action, body); w.Code != 409 || problemDetail(t, w) != filesSiteFolder {
			t.Fatalf("%s of public_html: %d %s", action, w.Code, w.Body.String())
		}
	}
	if e := decodeFile(t, post("delete", map[string]string{"path": "backup.zip"})); e.Type != "file" {
		t.Fatalf("delete %+v", e)
	}
	broker.fmu.Lock()
	defer broker.fmu.Unlock()
	if !strings.HasSuffix(broker.calls[0], "actor=local-operator") {
		t.Fatalf("calls %q", broker.calls)
	}
}

func TestWebsiteFilesRefuseBadRequests(t *testing.T) {
	f, broker, site := filesFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	post := func(action string, body any) *httptest.ResponseRecorder {
		return websiteRequest(f.handler, "POST", filesURL(site, "/"+action), body, cookie, csrf)
	}
	before := len(broker.calls)
	for name, tc := range map[string]struct {
		w      *httptest.ResponseRecorder
		status int
	}{
		"absolute path":       {websiteRequest(f.handler, "GET", filesURL(site, "?path=%2Fetc"), nil, cookie, ""), 422},
		"traversal":           {websiteRequest(f.handler, "GET", filesURL(site, "/content?path=public_html%2F..%2F..%2Fetc%2Fpasswd"), nil, cookie, ""), 422},
		"NUL":                 {post("folder", map[string]string{"path": "a\x00b"}), 422},
		"long name":           {post("folder", map[string]string{"path": strings.Repeat("n", 256)}), 422},
		"control character":   {post("folder", map[string]string{"path": "a\nb"}), 422},
		"empty path":          {post("delete", map[string]string{"path": ""}), 422},
		"unknown key":         {post("delete", map[string]string{"path": "a", "recursive": "yes"}), 422},
		"number as path":      {post("delete", map[string]any{"path": 1}), 422},
		"setuid mode":         {post("mode", map[string]string{"path": "a", "mode": "4755"}), 422},
		"rename into itself":  {post("rename", map[string]string{"path": "a", "to": "a/b"}), 422},
		"bad version":         {post("save", map[string]string{"path": "a", "content": "x", "expected_version": "yesterday"}), 422},
		"binary text":         {post("save", map[string]string{"path": "a", "content": "a\x00b", "expected_version": ""}), 422},
		"text over 1 MiB":     {post("save", map[string]string{"path": "a", "content": strings.Repeat("a", sitefiles.MaxTextBytes+1), "expected_version": ""}), 413},
		"body over 6 MiB":     {post("save", `{"path":"a","content":"`+strings.Repeat("a", maxSaveBody)+`","expected_version":""}`), 413},
		"download extra key":  {websiteRequest(f.handler, "GET", filesURL(site, "/download?path=a&as=b"), nil, cookie, ""), 422},
		"upload as a form":    {rawRequest(f.handler, "POST", filesURL(site, "/upload?path=a&overwrite=false"), "multipart/form-data; boundary=x", strings.NewReader("--x--"), 5, cookie, csrf, ""), 415},
		"upload over 64 MiB":  {rawRequest(f.handler, "POST", filesURL(site, "/upload?path=a&overwrite=false"), "application/octet-stream", strings.NewReader("x"), sitefiles.MaxUploadBytes+1, cookie, csrf, ""), 413},
		"upload no overwrite": {rawRequest(f.handler, "POST", filesURL(site, "/upload?path=a"), "application/octet-stream", strings.NewReader("x"), 1, cookie, csrf, ""), 422},
		"upload bad path":     {rawRequest(f.handler, "POST", filesURL(site, "/upload?path=..%2Fx&overwrite=false"), "application/octet-stream", strings.NewReader("x"), 1, cookie, csrf, ""), 422},
		"unknown site":        {websiteRequest(f.handler, "GET", "/api/v1/websites/sites/"+strings.Repeat("e", 32)+"/files", nil, cookie, ""), 404},
	} {
		if tc.w.Code != tc.status {
			t.Errorf("%s: %d, want %d: %s", name, tc.w.Code, tc.status, tc.w.Body.String())
		}
	}
	if len(broker.calls) != before {
		t.Fatalf("a refused request reached the account service: %q", broker.calls[before:])
	}
	// An upload whose body is shorter than its Content-Length makes nothing.
	short := rawRequest(f.handler, "POST", filesURL(site, "/upload?path=short.bin&overwrite=false"), "application/octet-stream", strings.NewReader("abc"), 10, cookie, csrf, "")
	if short.Code == 200 {
		t.Fatal("a short upload must fail")
	}
	if _, err := os.Stat(filepath.Join(broker.home(site.AccountID), "short.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a short upload left a file")
	}
}

func TestWebsiteFilesAdmission(t *testing.T) {
	f, broker, site := filesFixture(t)
	if w := websiteRequest(f.handler, "GET", filesURL(site, ""), nil, nil, ""); w.Code != 401 {
		t.Fatalf("unauthenticated list: %d", w.Code)
	}
	cookie, csrf := websiteSignIn(t, f)
	if w := websiteRequest(f.handler, "POST", filesURL(site, "/folder"), map[string]string{"path": "x"}, cookie, ""); w.Code != 403 {
		t.Fatalf("change without CSRF: %d", w.Code)
	}
	if w := rawRequest(f.handler, "POST", filesURL(site, "/upload?path=x&overwrite=false"), "application/octet-stream", strings.NewReader("x"), 1, cookie, "", ""); w.Code != 403 {
		t.Fatalf("upload without CSRF: %d", w.Code)
	}
	for _, method := range []string{"PUT", "DELETE", "PATCH"} {
		if w := websiteRequest(f.handler, method, filesURL(site, "/delete"), map[string]string{"path": "x"}, cookie, csrf); w.Code != 405 {
			t.Fatalf("%s: %d", method, w.Code)
		}
	}

	// An API token reads and downloads, and changes nothing.
	w := websiteRequest(f.handler, "POST", "/api/v1/session/tokens", map[string]any{"name": "Billing", "expires_in_days": 30}, cookie, csrf)
	var created operator.CreatedToken
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &created) != nil {
		t.Fatalf("token: %d %s", w.Code, w.Body.String())
	}
	os.WriteFile(filepath.Join(broker.home(site.AccountID), "a.txt"), []byte("hello"), 0o644)
	for _, rest := range []string{"", "/content?path=a.txt", "/download?path=a.txt"} {
		if w := rawRequest(f.handler, "GET", filesURL(site, rest), "", nil, 0, nil, "", created.Token); w.Code != 200 {
			t.Fatalf("token GET %s: %d %s", rest, w.Code, w.Body.String())
		}
	}
	calls := len(broker.calls)
	for _, action := range tokenRefusedSiteFiles {
		body := `{"path":"b.txt"}`
		w := rawRequest(f.handler, "POST", filesURL(site, "/"+action), "application/json", strings.NewReader(body), int64(len(body)), nil, "", created.Token)
		if w.Code != 403 || problemError(t, w) != "token_not_allowed" {
			t.Fatalf("token POST %s: %d %s", action, w.Code, w.Body.String())
		}
	}
	if w := rawRequest(f.handler, "POST", filesURL(site, "/upload?path=b.txt&overwrite=false"), "application/octet-stream", strings.NewReader("x"), 1, nil, "", created.Token); w.Code != 403 {
		t.Fatalf("token upload: %d", w.Code)
	}
	if len(broker.calls) != calls {
		t.Fatal("a token's change reached the account service")
	}
}

func TestWebsiteFilesExplainTheAccountService(t *testing.T) {
	f, broker, site := filesFixture(t)
	cookie, csrf := websiteSignIn(t, f)
	mkdir := func() *httptest.ResponseRecorder {
		return websiteRequest(f.handler, "POST", filesURL(site, "/folder"), map[string]string{"path": "new"}, cookie, csrf)
	}
	list := func() *httptest.ResponseRecorder {
		return websiteRequest(f.handler, "GET", filesURL(site, ""), nil, cookie, "")
	}
	for err, want := range map[error]struct {
		status int
		detail string
		w      func() *httptest.ResponseRecorder
	}{
		hostaccounts.ErrConflict:                 {409, filesBusy, mkdir},
		hostaccounts.ErrRecovery:                 {503, filesNeedsCheck, mkdir},
		hostaccounts.ErrUnavailable:              {503, filesNotAnswered, mkdir},
		&hostaccounts.FileError{Code: "quota"}:   {507, fileErrorText[sitefiles.ErrQuota].detail, mkdir},
		&hostaccounts.FileError{Code: "newcode"}: {503, fileErrorText[sitefiles.ErrFailed].detail, mkdir},
		errors.Join(hostaccounts.ErrUnavailable): {503, filesReadFailed, list},
	} {
		broker.fmu.Lock()
		broker.fileErr = err
		broker.fmu.Unlock()
		w := want.w()
		if w.Code != want.status || problemDetail(t, w) != want.detail || !strings.HasPrefix(problemTechnical(t, w), "account service: ") {
			t.Fatalf("%v: %d %s", err, w.Code, w.Body.String())
		}
	}
	broker.fmu.Lock()
	broker.fileErr = nil
	broker.fmu.Unlock()

	// Suspended: the files can be looked at, not changed.
	broker.change(site.AccountID, func(a *hostaccounts.Account) { a.State = "suspended" })
	if w := list(); w.Code != 200 {
		t.Fatalf("suspended list: %d", w.Code)
	}
	calls := len(broker.calls)
	if w := mkdir(); w.Code != 409 || problemDetail(t, w) != filesSuspended {
		t.Fatalf("suspended change: %d %s", w.Code, w.Body.String())
	}
	if w := rawRequest(f.handler, "POST", filesURL(site, "/upload?path=x&overwrite=false"), "application/octet-stream", strings.NewReader("x"), 1, cookie, csrf, ""); w.Code != 409 {
		t.Fatalf("suspended upload: %d", w.Code)
	}
	if len(broker.calls) != calls {
		t.Fatal("a change to a suspended site reached the account service")
	}
}
