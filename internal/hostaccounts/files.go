package hostaccounts

import (
	"context"
	"errors"
	"io"
	"time"

	"sifruno/internal/sitefiles"
)

// The file manager. Every file operation runs the file helper,
// FilesHelper (internal/sitefiles), as the account's own user in its home,
// in a transient unit in the account's user slice: the same site-step
// mechanism as the WordPress install (runSiteProgram), started in the home
// instead of public_html. Root never opens a path inside the home for it,
// so a tenant's links and permissions can only ever affect that tenant.
//
// File operations change no record, so nothing is journaled and the
// account is never marked busy: a suspend or delete ends a running helper
// with the account's other processes. They are refused while the account
// has its own unfinished operation, but another account's does not stop
// them, as for backups (see store.fileReady).

// FilesHelper is where the release installs the helper (root, 0755). The
// broker checks it before every run as it checks its other fixed tools: a
// regular root-owned file with one link, in root-owned folders no one else
// may write, and executable by the site user.
const FilesHelper = "/usr/local/lib/sifruno/bin/sifruno-files"

// fileTimeout bounds a list, read, write, new folder, rename, delete or
// mode change; fileTransferTimeout an upload or a download, whose bytes
// arrive or leave at the caller's pace. Neither follows the caller, so a
// client that gives up does not cut a delete in half.
const (
	fileTimeout         = 2 * time.Minute
	fileTransferTimeout = 15 * time.Minute
)

// maxFileRuns is how many file operations may run at once for one account.
// It keeps one site's transfers from tying up the broker; other accounts
// are not counted against it.
const maxFileRuns = 4

// FileEntry is one name in a folder, or the file an operation read, wrote
// or made (sitefiles.Entry).
type FileEntry = sitefiles.Entry

// FileList is a folder's names, sorted. Skipped counts names the file
// manager cannot show (not UTF-8, control characters, over 255 bytes);
// Truncated says there were more than sitefiles.MaxEntries.
type FileList struct {
	Path      string      `json:"path"`
	Entries   []FileEntry `json:"entries"`
	Skipped   int         `json:"skipped"`
	Truncated bool        `json:"truncated"`
}

// FileText is a text file the editor opened: at most sitefiles.MaxTextBytes
// of UTF-8 with no NUL byte.
type FileText struct {
	File    FileEntry `json:"file"`
	Content string    `json:"content"`
}

// FileWriteInput saves a text file whole. ExpectedVersion is the Version
// the editor loaded: a file changed since answers "changed". Empty makes a
// new file only: a name that is taken answers "exists".
type FileWriteInput struct {
	Path            string `json:"path"`
	Content         string `json:"content"`
	ExpectedVersion string `json:"expected_version"`
}

// FileUploadInput is an upload of Size bytes to Path; Overwrite lets it
// replace an existing file.
type FileUploadInput struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	Overwrite bool   `json:"overwrite"`
}

// ErrFileFailed is a file operation the helper refused or could not do.
var ErrFileFailed = errors.New("file operation failed")

// FileError says why a file operation failed, as one of sitefiles' codes
// (for example "is_link", "exists", "quota", "changed"). A write or upload
// that fails leaves the file as it was; a folder delete that fails part way
// leaves what it had not reached.
type FileError struct {
	Code string
}

func (e *FileError) Error() string        { return "file operation failed: " + e.Code }
func (e *FileError) Is(target error) bool { return target == ErrFileFailed }

// FilesService is implemented by the client; the broker serves it from the
// store. Paths are relative to the account's home ("" is the home).
type FilesService interface {
	ListFiles(ctx context.Context, id, path, actor string) (FileList, error)
	ReadFile(ctx context.Context, id, path, actor string) (FileText, error)
	WriteFile(ctx context.Context, id string, in FileWriteInput, actor string) (FileEntry, error)
	// UploadFile sends exactly in.Size bytes from body.
	UploadFile(ctx context.Context, id string, in FileUploadInput, body io.Reader, actor string) (FileEntry, error)
	// DownloadFile answers the file and its bytes, exactly FileEntry.Size of
	// them; the caller closes the reader.
	DownloadFile(ctx context.Context, id, path, actor string) (FileEntry, io.ReadCloser, error)
	MakeFolder(ctx context.Context, id, path, actor string) (FileEntry, error)
	RenameFile(ctx context.Context, id, from, to, actor string) (FileEntry, error)
	// DeleteFile removes a file, a link (never its target) or a folder with
	// everything in it, without following links.
	DeleteFile(ctx context.Context, id, path, actor string) (FileEntry, error)
	// SetFileMode sets the permission bits only ("0644"); setuid, setgid
	// and sticky are refused.
	SetFileMode(ctx context.Context, id, path, mode, actor string) (FileEntry, error)
}

// fileWrites are the operations that change the tenant's files: refused
// for a suspended account and while a WordPress install or restore runs.
func fileWrites(op string) bool {
	switch op {
	case sitefiles.OpWrite, sitefiles.OpUpload, sitefiles.OpMkdir, sitefiles.OpRename, sitefiles.OpDelete, sitefiles.OpMode:
		return true
	}
	return false
}

// fileLimit is the operation's own time limit.
func fileLimit(op string) time.Duration {
	if op == sitefiles.OpUpload || op == sitefiles.OpDownload {
		return fileTransferTimeout
	}
	return fileTimeout
}

// validFileCall checks what every file operation takes besides the
// request: the account ID, the actor and the request itself.
func validFileCall(id, actor string, req sitefiles.Request) bool {
	return idPattern.MatchString(id) && validText(actor, 120) && sitefiles.Validate(req) == nil
}
