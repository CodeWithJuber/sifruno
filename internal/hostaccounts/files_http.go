package hostaccounts

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"

	"sifruno/internal/sitefiles"
)

// The file routes, one per operation: POST /v1/accounts/{id}/files/{op}.
//
//   - list, mkdir, rename, delete, mode: a JSON body {"input": {...},
//     "actor": "..."} with exactly the operation's keys; a JSON answer (a
//     FileList for list, a FileEntry for the rest).
//   - read, download: the same JSON body; the answer is
//     application/octet-stream: the FileEntry as one JSON line, then
//     exactly its size in bytes.
//   - write, upload: application/octet-stream with a Content-Length: one
//     JSON line {"input": {...}, "actor": "..."} holding the size, then
//     exactly that many bytes; a JSON FileEntry answer.
//
// A refusal from the helper answers 422 {"error": "file_failed",
// "reason": "<code>"}; everything else answers as the other routes do.
var fileRoutePattern = regexp.MustCompile(`^/v1/accounts/([a-f0-9]{32})/files/(list|read|download|write|upload|mkdir|rename|delete|mode)$`)

// fileInputKeys are each operation's input keys, all required.
var fileInputKeys = map[string][]string{
	sitefiles.OpList:     {"path"},
	sitefiles.OpRead:     {"path"},
	sitefiles.OpDownload: {"path"},
	sitefiles.OpMkdir:    {"path"},
	sitefiles.OpDelete:   {"path"},
	sitefiles.OpRename:   {"path", "to"},
	sitefiles.OpMode:     {"path", "mode"},
	sitefiles.OpWrite:    {"path", "size", "expected_version"},
	sitefiles.OpUpload:   {"path", "size", "overwrite"},
}

// fileInput is every file operation's input; each route takes only its own
// keys (fileInputKeys), and sitefiles.Validate checks the request built
// from them.
type fileInput struct {
	Path            string `json:"path"`
	To              string `json:"to"`
	Mode            string `json:"mode"`
	Size            int64  `json:"size"`
	Overwrite       bool   `json:"overwrite"`
	ExpectedVersion string `json:"expected_version"`
}

func (in fileInput) request(op string) sitefiles.Request {
	return sitefiles.Request{Op: op, Path: in.Path, To: in.To, Mode: in.Mode, Size: in.Size, Overwrite: in.Overwrite, ExpectedVersion: in.ExpectedVersion}
}

func serveFiles(w http.ResponseWriter, r *http.Request, s *store) {
	m := fileRoutePattern.FindStringSubmatch(r.URL.Path)
	if m == nil || r.Method != http.MethodPost {
		writeError(w, ErrNotFound)
		return
	}
	id, op := m[1], m[2]
	// A transfer moves its bytes at the caller's pace; every file operation
	// runs on its own limit, longer than the server's default deadlines.
	rc := http.NewResponseController(w)
	until := time.Now().Add(fileLimit(op) + time.Minute)
	for _, set := range []func(time.Time) error{rc.SetReadDeadline, rc.SetWriteDeadline} {
		if e := set(until); e != nil && !errors.Is(e, http.ErrNotSupported) {
			writeError(w, ErrUnavailable)
			return
		}
	}
	var in struct {
		Input fileInput `json:"input"`
		Actor string    `json:"actor"`
	}
	var body io.Reader
	if sitefiles.Sends(op) {
		var err error
		if body, err = decodeFramed(r, &in, fileInputKeys[op]); err != nil {
			writeError(w, ErrInvalid)
			return
		}
	} else if decodeBody(w, r, &in, fileInputKeys[op]) != nil {
		writeError(w, ErrInvalid)
		return
	}
	req := in.Input.request(op)
	if sitefiles.Streams(op) {
		started := false
		_, err := s.runFile(r.Context(), id, in.Actor, req, nil, func(a sitefiles.Answer) (io.Writer, error) {
			line, err := sitefiles.EncodeLine(a.File)
			if err != nil {
				return nil, ErrUnavailable
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", strconv.FormatInt(int64(len(line))+a.File.Size, 10))
			w.WriteHeader(http.StatusOK)
			started = true
			if _, err := w.Write(line); err != nil {
				return nil, err
			}
			return w, nil
		})
		if err != nil && !started {
			writeFileError(w, err)
		}
		return
	}
	a, err := s.runFile(r.Context(), id, in.Actor, req, body, nil)
	if err != nil {
		writeFileError(w, err)
		return
	}
	if op == sitefiles.OpList {
		list := FileList{Path: req.Path, Entries: a.Entries, Skipped: a.Skipped, Truncated: a.Truncated}
		if list.Entries == nil {
			list.Entries = []FileEntry{}
		}
		json.NewEncoder(w).Encode(list)
		return
	}
	json.NewEncoder(w).Encode(a.File)
}

// decodeFramed reads a write or upload: application/octet-stream, a
// Content-Length, one strict JSON line with exactly the operation's keys,
// then the bytes, which must be exactly the line's size. It returns a
// reader of those bytes.
func decodeFramed(r *http.Request, out any, keys []string) (io.Reader, error) {
	media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/octet-stream" || len(params) != 0 || r.ContentLength <= 0 || len(r.TransferEncoding) != 0 {
		return nil, ErrInvalid
	}
	br := bufio.NewReaderSize(r.Body, 16<<10)
	line, err := sitefiles.ReadLine(br, MaxRequestBytes)
	if err != nil || !utf8.Valid(line) {
		return nil, ErrInvalid
	}
	allowed := map[string]bool{}
	for _, k := range keys {
		allowed[k] = true
	}
	d := json.NewDecoder(bytes.NewReader(line))
	if strictObject(d, map[string]bool{"input": true, "actor": true}, true, allowed, true) != nil {
		return nil, ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	d = json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return nil, ErrInvalid
	}
	var size struct {
		Input struct {
			Size int64 `json:"size"`
		} `json:"input"`
	}
	if json.Unmarshal(line, &size) != nil || size.Input.Size < 0 || r.ContentLength != int64(len(line))+1+size.Input.Size {
		return nil, ErrInvalid
	}
	return io.LimitReader(br, size.Input.Size), nil
}

// writeFileError answers a helper's refusal as 422 file_failed with its
// code, and anything else as the other routes do.
func writeFileError(w http.ResponseWriter, err error) {
	var failed *FileError
	if errors.As(err, &failed) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(struct {
			Error  string `json:"error"`
			Reason string `json:"reason"`
		}{"file_failed", failed.Code})
		return
	}
	writeError(w, err)
}
