// Package sitefiles is the file manager's helper. The broker runs it as a
// website's own user, in that user's home, inside a transient unit in the
// account's slice; root never opens a path inside a tenant's home for it.
//
// One request goes in on stdin: a JSON line, then for write and upload
// exactly Size bytes. One answer comes out on stdout: a JSON line, then for
// read and download exactly the answered file's Size bytes. The broker
// treats the answer as the tenant's data: the helper runs with the tenant's
// rights, and the tenant's own processes may trace it, so every answer is
// bounded and checked again by ParseAnswer.
package sitefiles

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// The operations, by the name the request carries.
const (
	OpList     = "list"
	OpRead     = "read"
	OpWrite    = "write"
	OpUpload   = "upload"
	OpDownload = "download"
	OpMkdir    = "mkdir"
	OpRename   = "rename"
	OpDelete   = "delete"
	OpMode     = "mode"
)

// Bounds. A path is relative to the home, at most MaxPathBytes long and
// MaxDepth names deep; each name is at most MaxNameBytes. The editor reads
// and writes text up to MaxTextBytes; an upload is at most MaxUploadBytes,
// a download at most MaxDownloadBytes. A list shows at most MaxEntries.
const (
	MaxPathBytes     = 1024
	MaxNameBytes     = 255
	MaxDepth         = 64
	MaxTextBytes     = 1 << 20
	MaxUploadBytes   = 64 << 20
	MaxDownloadBytes = 1 << 30
	MaxEntries       = 5000
	// MaxRequestLine bounds the JSON request line; MaxAnswerLine the JSON
	// answer line, which holds up to MaxEntries entries.
	MaxRequestLine = 8 << 10
	MaxAnswerLine  = 4 << 20
)

// Request is one operation. Path names the file or folder, relative to the
// home ("" is the home itself, for list only). To is a rename's new path.
// Size is how many bytes follow the line for write and upload. Mode is the
// permission bits for mode, as three or four octal digits ("0644");
// setuid, setgid and sticky are refused. Overwrite lets an upload replace a
// file. ExpectedVersion makes a write fail with "changed" unless the file
// still has this Version (or, for a new file, when one appeared meanwhile).
type Request struct {
	Op              string `json:"op"`
	Path            string `json:"path"`
	To              string `json:"to,omitempty"`
	Size            int64  `json:"size,omitempty"`
	Mode            string `json:"mode,omitempty"`
	Overwrite       bool   `json:"overwrite,omitempty"`
	ExpectedVersion string `json:"expected_version,omitempty"`
}

// Entry is one name in a folder, or the file an operation read, wrote or
// made. Type is "file", "folder", "link" or "other" (a device, socket or
// pipe), from lstat: a link is shown as a link and never followed. Size is
// a file's length (0 for the rest). Mode is the permission bits as four
// octal digits. Modified is the modified time, RFC 3339 in UTC with
// nanoseconds. Version, for a file only, is 16 hex digits that change when
// the file is replaced or changed: a hash of its device, inode, size and
// modified and change times. The kernel stamps times at a coarse tick, so
// the modified time alone can stay the same across two quick writes.
type Entry struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Size     int64  `json:"size"`
	Mode     string `json:"mode"`
	Modified string `json:"modified"`
	Version  string `json:"version,omitempty"`
}

// Answer is the helper's reply. Error is empty on success, or one of the
// codes below. A list fills Entries (sorted by name), Skipped (names the
// file manager cannot show: not UTF-8, control characters, too long) and
// Truncated (more than MaxEntries names). Every other success fills File.
type Answer struct {
	Error     string  `json:"error,omitempty"`
	Entries   []Entry `json:"entries,omitempty"`
	Skipped   int     `json:"skipped,omitempty"`
	Truncated bool    `json:"truncated,omitempty"`
	File      *Entry  `json:"file,omitempty"`
}

// The error codes an answer can carry.
const (
	ErrInvalid     = "invalid"      // the request breaks a rule above
	ErrNotFound    = "not_found"    // the path, or a folder on it, is not there
	ErrExists      = "exists"       // the new name is taken
	ErrNotAFolder  = "not_a_folder" // a name on the path is not a folder
	ErrIsAFolder   = "is_a_folder"  // a folder where a file was asked for
	ErrNotAFile    = "not_a_file"   // a device, socket or pipe
	ErrIsLink      = "is_link"      // the path is, or goes through, a link
	ErrTooLarge    = "too_large"    // over the operation's size bound
	ErrBinary      = "binary"       // not UTF-8 text, or holds a NUL byte
	ErrChanged     = "changed"      // modified since ExpectedVersion
	ErrPermission  = "permission"   // the user's own permissions refused it
	ErrQuota       = "quota"        // the account's disk quota is full
	ErrNoSpace     = "no_space"     // the disk is full
	ErrTooDeep     = "too_deep"     // a folder too deep to delete
	ErrFailed      = "failed"       // anything else
	ErrUnsupported = "unsupported"  // the filesystem cannot do it
)

var errorCodes = map[string]bool{ErrInvalid: true, ErrNotFound: true, ErrExists: true, ErrNotAFolder: true, ErrIsAFolder: true, ErrNotAFile: true, ErrIsLink: true, ErrTooLarge: true, ErrBinary: true, ErrChanged: true, ErrPermission: true, ErrQuota: true, ErrNoSpace: true, ErrTooDeep: true, ErrFailed: true, ErrUnsupported: true}

// ErrorCode reports whether code is one an answer may carry.
func ErrorCode(code string) bool { return errorCodes[code] }

var modePattern = regexp.MustCompile(`^0?[0-7]{3}$`)

// ValidName accepts one name in a folder: 1 to MaxNameBytes bytes of
// UTF-8, no slash, no control character, and not "." or "..".
func ValidName(name string) bool {
	if name == "" || len(name) > MaxNameBytes || name == "." || name == ".." || !utf8.ValidString(name) || strings.ContainsRune(name, '/') {
		return false
	}
	return !strings.ContainsFunc(name, unicode.IsControl)
}

// SplitPath checks a path relative to the home and returns its names; ""
// is the home itself and returns none. An absolute path, an empty name
// ("a//b", a leading or trailing slash), ".", "..", a NUL or other control
// character, or a path over the bounds is refused.
func SplitPath(p string) ([]string, bool) {
	if p == "" {
		return nil, true
	}
	if len(p) > MaxPathBytes {
		return nil, false
	}
	names := strings.Split(p, "/")
	if len(names) > MaxDepth {
		return nil, false
	}
	for _, n := range names {
		if !ValidName(n) {
			return nil, false
		}
	}
	return names, true
}

// ParseMode reads a mode request's permission bits.
func ParseMode(s string) (uint32, bool) {
	if !modePattern.MatchString(s) {
		return 0, false
	}
	var m uint32
	for _, c := range s {
		m = m*8 + uint32(c-'0')
	}
	return m, m <= 0o777
}

// Validate checks a request against its operation: each operation takes
// exactly its own fields.
func Validate(r Request) error {
	names, ok := SplitPath(r.Path)
	if !ok {
		return errInvalid
	}
	modified := r.ExpectedVersion == "" || versionPattern.MatchString(r.ExpectedVersion)
	plain := r.To == "" && r.Size == 0 && r.Mode == "" && !r.Overwrite && r.ExpectedVersion == ""
	target := len(names) > 0
	switch r.Op {
	case OpList:
		ok = plain
	case OpRead, OpDownload, OpMkdir, OpDelete:
		ok = plain && target
	case OpWrite:
		ok = target && r.To == "" && r.Mode == "" && !r.Overwrite && modified && r.Size >= 0 && r.Size <= MaxTextBytes
	case OpUpload:
		ok = target && r.To == "" && r.Mode == "" && r.ExpectedVersion == "" && r.Size >= 0 && r.Size <= MaxUploadBytes
	case OpRename:
		to, valid := SplitPath(r.To)
		ok = target && valid && len(to) > 0 && r.Size == 0 && r.Mode == "" && !r.Overwrite && r.ExpectedVersion == "" &&
			r.To != r.Path && !strings.HasPrefix(r.To, r.Path+"/")
	case OpMode:
		_, valid := ParseMode(r.Mode)
		ok = target && valid && r.To == "" && r.Size == 0 && !r.Overwrite && r.ExpectedVersion == ""
	default:
		ok = false
	}
	if !ok {
		return errInvalid
	}
	return nil
}

var errInvalid = errors.New("invalid file request")

// validModified accepts a time as an Entry shows it.
func validModified(s string) bool {
	if len(s) > 40 {
		return false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	return err == nil && FormatModified(t) == s
}

// FormatModified is the one form a modified time takes in an Entry.
func FormatModified(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// EncodeLine is a request or answer as its line, newline included.
func EncodeLine(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// ReadLine reads one line of at most limit bytes, newline included, and
// returns it without the newline. A longer line, or input that ends before
// the newline, is an error.
func ReadLine(r *bufio.Reader, limit int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(line)+len(chunk) > limit {
			return nil, errInvalid
		}
		line = append(line, chunk...)
		if err == nil {
			return line[:len(line)-1], nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
	}
}

// decodeStrict decodes exactly one JSON object with no unknown field.
func decodeStrict(line []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return errInvalid
	}
	if d.More() {
		return errInvalid
	}
	return nil
}

// ParseRequest reads a request line and checks it.
func ParseRequest(line []byte) (Request, error) {
	var r Request
	if !utf8.Valid(line) || decodeStrict(line, &r) != nil || Validate(r) != nil {
		return Request{}, errInvalid
	}
	return r, nil
}

// ValidEntry checks an entry as an answer may carry it.
func ValidEntry(e Entry) bool {
	if !ValidName(e.Name) || !validModified(e.Modified) || !modePattern4.MatchString(e.Mode) || e.Size < 0 {
		return false
	}
	switch e.Type {
	case "file":
		return versionPattern.MatchString(e.Version)
	case "folder", "link", "other":
		return e.Size == 0 && e.Version == ""
	}
	return false
}

// A listed mode is four octal digits and may carry setuid, setgid or sticky
// bits; a mode request may not set them.
var modePattern4 = regexp.MustCompile(`^[0-7]{4}$`)

var versionPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

// ParseAnswer reads the helper's answer line for a request and checks that
// it has the shape that operation answers with. The answer comes from a
// process that runs as the tenant, so nothing in it is trusted: every name,
// count and size is checked against the bounds.
func ParseAnswer(r Request, line []byte) (Answer, error) {
	var a Answer
	if !utf8.Valid(line) || decodeStrict(line, &a) != nil {
		return Answer{}, errInvalid
	}
	if a.Error != "" {
		if !ErrorCode(a.Error) || a.Entries != nil || a.Skipped != 0 || a.Truncated || a.File != nil {
			return Answer{}, errInvalid
		}
		return a, nil
	}
	if r.Op == OpList {
		if a.File != nil || len(a.Entries) > MaxEntries || a.Skipped < 0 || a.Skipped > 1<<30 {
			return Answer{}, errInvalid
		}
		seen := map[string]bool{}
		for _, e := range a.Entries {
			if !ValidEntry(e) || seen[e.Name] {
				return Answer{}, errInvalid
			}
			seen[e.Name] = true
		}
		return a, nil
	}
	if a.Entries != nil || a.Skipped != 0 || a.Truncated || a.File == nil || !ValidEntry(*a.File) {
		return Answer{}, errInvalid
	}
	names, _ := SplitPath(r.Path)
	want := names[len(names)-1]
	if r.Op == OpRename {
		to, _ := SplitPath(r.To)
		want = to[len(to)-1]
	}
	f := *a.File
	if f.Name != want {
		return Answer{}, errInvalid
	}
	switch r.Op {
	case OpRead:
		if f.Type != "file" || f.Size > MaxTextBytes {
			return Answer{}, errInvalid
		}
	case OpDownload:
		if f.Type != "file" || f.Size > MaxDownloadBytes {
			return Answer{}, errInvalid
		}
	case OpWrite, OpUpload:
		if f.Type != "file" || f.Size != r.Size {
			return Answer{}, errInvalid
		}
	case OpMkdir:
		if f.Type != "folder" {
			return Answer{}, errInvalid
		}
	case OpMode:
		if m, _ := ParseMode(r.Mode); f.Mode != formatMode(m) || f.Type == "link" {
			return Answer{}, errInvalid
		}
	}
	return a, nil
}

func formatMode(m uint32) string {
	const digits = "01234567"
	return string([]byte{digits[(m>>9)&7], digits[(m>>6)&7], digits[(m>>3)&7], digits[m&7]})
}

// Streams reports whether an answer to this operation is followed by the
// file's bytes.
func Streams(op string) bool { return op == OpRead || op == OpDownload }

// Sends reports whether a request for this operation is followed by Size
// bytes.
func Sends(op string) bool { return op == OpWrite || op == OpUpload }

// Text reports whether b is text the editor may show and save: UTF-8 with
// no NUL byte.
func Text(b []byte) bool { return utf8.Valid(b) && bytes.IndexByte(b, 0) < 0 }
