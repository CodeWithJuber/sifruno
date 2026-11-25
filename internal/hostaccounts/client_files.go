package hostaccounts

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"

	"sifruno/internal/sitefiles"
)

// The file manager's client side; files_http.go has the routes. The client
// refuses what the broker would before it connects, and checks the
// broker's answers again: names, types, sizes, and for a read or download
// that exactly the promised bytes arrive.

var _ FilesService = (*client)(nil)

func (c *client) ListFiles(ctx context.Context, id, path, actor string) (FileList, error) {
	var out FileList
	req := sitefiles.Request{Op: sitefiles.OpList, Path: path}
	if err := c.fileCall(ctx, id, actor, req, &out, sitefiles.MaxAnswerLine); err != nil {
		return FileList{}, err
	}
	seen := map[string]bool{}
	for _, e := range out.Entries {
		if !sitefiles.ValidEntry(e) || seen[e.Name] {
			return FileList{}, ErrUnavailable
		}
		seen[e.Name] = true
	}
	if out.Path != path || len(out.Entries) > sitefiles.MaxEntries || out.Skipped < 0 {
		return FileList{}, ErrUnavailable
	}
	if out.Entries == nil {
		out.Entries = []FileEntry{}
	}
	return out, nil
}

func (c *client) MakeFolder(ctx context.Context, id, path, actor string) (FileEntry, error) {
	return c.fileEntryCall(ctx, id, actor, sitefiles.Request{Op: sitefiles.OpMkdir, Path: path})
}

func (c *client) RenameFile(ctx context.Context, id, from, to, actor string) (FileEntry, error) {
	return c.fileEntryCall(ctx, id, actor, sitefiles.Request{Op: sitefiles.OpRename, Path: from, To: to})
}

func (c *client) DeleteFile(ctx context.Context, id, path, actor string) (FileEntry, error) {
	return c.fileEntryCall(ctx, id, actor, sitefiles.Request{Op: sitefiles.OpDelete, Path: path})
}

func (c *client) SetFileMode(ctx context.Context, id, path, mode, actor string) (FileEntry, error) {
	return c.fileEntryCall(ctx, id, actor, sitefiles.Request{Op: sitefiles.OpMode, Path: path, Mode: mode})
}

func (c *client) ReadFile(ctx context.Context, id, path, actor string) (FileText, error) {
	e, body, err := c.fileStream(ctx, c.slow, id, actor, sitefiles.Request{Op: sitefiles.OpRead, Path: path})
	if err != nil {
		return FileText{}, err
	}
	defer body.Close()
	data, err := io.ReadAll(body)
	if err != nil || !sitefiles.Text(data) {
		return FileText{}, ErrUnavailable
	}
	return FileText{File: e, Content: string(data)}, nil
}

func (c *client) DownloadFile(ctx context.Context, id, path, actor string) (FileEntry, io.ReadCloser, error) {
	return c.fileStream(ctx, c.long, id, actor, sitefiles.Request{Op: sitefiles.OpDownload, Path: path})
}

func (c *client) WriteFile(ctx context.Context, id string, in FileWriteInput, actor string) (FileEntry, error) {
	req := sitefiles.Request{Op: sitefiles.OpWrite, Path: in.Path, Size: int64(len(in.Content)), ExpectedVersion: in.ExpectedVersion}
	if !sitefiles.Text([]byte(in.Content)) {
		return FileEntry{}, ErrInvalid
	}
	return c.filePut(ctx, c.slow, id, actor, req, map[string]any{"path": in.Path, "size": req.Size, "expected_version": in.ExpectedVersion}, bytes.NewReader([]byte(in.Content)))
}

func (c *client) UploadFile(ctx context.Context, id string, in FileUploadInput, body io.Reader, actor string) (FileEntry, error) {
	if body == nil {
		return FileEntry{}, ErrInvalid
	}
	req := sitefiles.Request{Op: sitefiles.OpUpload, Path: in.Path, Size: in.Size, Overwrite: in.Overwrite}
	return c.filePut(ctx, c.long, id, actor, req, map[string]any{"path": in.Path, "size": in.Size, "overwrite": in.Overwrite}, body)
}

// fileInputFor is a JSON route's input: exactly the operation's keys.
func fileInputFor(req sitefiles.Request) map[string]any {
	in := map[string]any{}
	for _, k := range fileInputKeys[req.Op] {
		switch k {
		case "path":
			in[k] = req.Path
		case "to":
			in[k] = req.To
		case "mode":
			in[k] = req.Mode
		}
	}
	return in
}

func (c *client) fileEntryCall(ctx context.Context, id, actor string, req sitefiles.Request) (FileEntry, error) {
	var e FileEntry
	if err := c.fileCall(ctx, id, actor, req, &e, 64<<10); err != nil {
		return FileEntry{}, err
	}
	if !answeredEntry(req, e) {
		return FileEntry{}, ErrUnavailable
	}
	return e, nil
}

// answeredEntry checks the entry a broker answered with against the
// request, as sitefiles.ParseAnswer checks the helper's.
func answeredEntry(req sitefiles.Request, e FileEntry) bool {
	line, err := sitefiles.EncodeLine(sitefiles.Answer{File: &e})
	if err != nil {
		return false
	}
	_, err = sitefiles.ParseAnswer(req, bytes.TrimSuffix(line, []byte("\n")))
	return err == nil
}

func (c *client) fileCall(ctx context.Context, id, actor string, req sitefiles.Request, out any, limit int64) error {
	if !validFileCall(id, actor, req) || sitefiles.Sends(req.Op) || sitefiles.Streams(req.Op) {
		return ErrInvalid
	}
	b, err := json.Marshal(struct {
		Input map[string]any `json:"input"`
		Actor string         `json:"actor"`
	}{fileInputFor(req), actor})
	if err != nil || len(b) > MaxRequestBytes {
		return ErrInvalid
	}
	resp, err := c.filePost(ctx, c.slow, id, req.Op, "application/json", bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(data)) > limit || json.Unmarshal(data, out) != nil {
		return ErrUnavailable
	}
	return nil
}

// fileStream asks for a read or download and returns the checked entry and
// a reader of exactly its bytes; a stream that ends early is an error.
func (c *client) fileStream(ctx context.Context, h *http.Client, id, actor string, req sitefiles.Request) (FileEntry, io.ReadCloser, error) {
	if !validFileCall(id, actor, req) || !sitefiles.Streams(req.Op) {
		return FileEntry{}, nil, ErrInvalid
	}
	b, err := json.Marshal(struct {
		Input map[string]any `json:"input"`
		Actor string         `json:"actor"`
	}{fileInputFor(req), actor})
	if err != nil || len(b) > MaxRequestBytes {
		return FileEntry{}, nil, ErrInvalid
	}
	resp, err := c.filePost(ctx, h, id, req.Op, "application/json", bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return FileEntry{}, nil, err
	}
	fail := func() (FileEntry, io.ReadCloser, error) {
		resp.Body.Close()
		return FileEntry{}, nil, ErrUnavailable
	}
	if media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || media != "application/octet-stream" {
		return fail()
	}
	br := bufio.NewReaderSize(resp.Body, 64<<10)
	line, err := sitefiles.ReadLine(br, 64<<10)
	if err != nil {
		return fail()
	}
	var e FileEntry
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if d.Decode(&e) != nil || d.More() || !answeredEntry(req, e) {
		return fail()
	}
	if resp.ContentLength >= 0 && resp.ContentLength != int64(len(line))+1+e.Size {
		return fail()
	}
	return e, struct {
		io.Reader
		io.Closer
	}{&exactReader{r: br, left: e.Size}, resp.Body}, nil
}

// filePut sends a write or upload: one JSON line with the input, then
// exactly req.Size bytes from body.
func (c *client) filePut(ctx context.Context, h *http.Client, id, actor string, req sitefiles.Request, input map[string]any, body io.Reader) (FileEntry, error) {
	if !validFileCall(id, actor, req) || !sitefiles.Sends(req.Op) {
		return FileEntry{}, ErrInvalid
	}
	head, err := json.Marshal(struct {
		Input map[string]any `json:"input"`
		Actor string         `json:"actor"`
	}{input, actor})
	if err != nil || len(head)+1 > MaxRequestBytes {
		return FileEntry{}, ErrInvalid
	}
	head = append(head, '\n')
	stream := io.MultiReader(bytes.NewReader(head), &exactReader{r: body, left: req.Size})
	resp, err := c.filePost(ctx, h, id, req.Op, "application/octet-stream", stream, int64(len(head))+req.Size)
	if err != nil {
		return FileEntry{}, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10+1))
	var e FileEntry
	if err != nil || len(data) > 64<<10 || json.Unmarshal(data, &e) != nil || !answeredEntry(req, e) {
		return FileEntry{}, ErrUnavailable
	}
	return e, nil
}

func (c *client) filePost(ctx context.Context, h *http.Client, id, op, contentType string, body io.Reader, length int64) (*http.Response, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	if !c.configured {
		return nil, ErrUnavailable
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/accounts/"+id+"/files/"+op, body)
	if err != nil {
		return nil, ErrInvalid
	}
	req.Header.Set("Content-Type", contentType)
	req.ContentLength = length
	resp, err := h.Do(req)
	if err != nil {
		return nil, ErrUnavailable
	}
	if resp.StatusCode == http.StatusOK {
		return resp, nil
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if err != nil {
		return nil, ErrUnavailable
	}
	return nil, fileFailure(data)
}

// fileFailure reads a file route's error answer.
func fileFailure(data []byte) error {
	var failure struct {
		Error  string `json:"error"`
		Reason string `json:"reason"`
	}
	if json.Unmarshal(data, &failure) != nil {
		return ErrUnavailable
	}
	switch failure.Error {
	case "file_failed":
		if sitefiles.ErrorCode(failure.Reason) {
			return &FileError{Code: failure.Reason}
		}
	case "invalid":
		return ErrInvalid
	case "conflict":
		return ErrConflict
	case "not_found":
		return ErrNotFound
	case "recovery":
		return ErrRecovery
	}
	return ErrUnavailable
}

// exactReader gives exactly left bytes of r and fails if r ends sooner.
type exactReader struct {
	r    io.Reader
	left int64
}

func (x *exactReader) Read(p []byte) (int, error) {
	if x.left <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > x.left {
		p = p[:x.left]
	}
	n, err := x.r.Read(p)
	x.left -= int64(n)
	if err == io.EOF {
		if x.left > 0 {
			return n, io.ErrUnexpectedEOF
		}
		err = nil
	}
	return n, err
}
