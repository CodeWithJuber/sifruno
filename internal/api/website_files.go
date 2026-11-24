package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/sitefiles"
)

// A website's Files page: the hosting account's real home folder. Every
// operation goes to the account service, which runs the file helper as the
// site's own user in its home (hostaccounts, "File manager"); the panel
// checks the request and explains the answer. The routes sit under
// /api/v1/websites/, so the wizard's admission applies: an admin session,
// and for a POST also Origin and CSRF. An API token may list, read and
// download, but not change files (tokenRefusedSiteFile).

// WebsiteFile is one name in a folder, or the file a change made.
type WebsiteFile struct {
	Name     string `json:"name" doc:"The name in its folder."`
	Type     string `json:"type" enum:"file,folder,link,other" doc:"link: a symbolic link, shown as itself and never followed. other: a device, socket or pipe."`
	Size     int64  `json:"size" doc:"A file's size in bytes; 0 for the rest."`
	Mode     string `json:"mode" doc:"The permission bits as four octal digits, such as 0644."`
	Modified string `json:"modified" doc:"When it last changed, RFC 3339 in UTC."`
	Version  string `json:"version,omitempty" doc:"For a file: changes whenever the file is replaced or changed. A save sends it back as expected_version."`
}

// WebsiteFolder is one folder of the home.
type WebsiteFolder struct {
	Path      string        `json:"path" doc:"The folder, relative to the home; empty for the home itself."`
	Entries   []WebsiteFile `json:"entries"`
	Skipped   int           `json:"skipped" doc:"Names the file manager cannot show: not UTF-8 text, a control character, or longer than 255 bytes. Use SFTP for them."`
	Truncated bool          `json:"truncated" doc:"The folder holds more than 5000 names; only the first 5000 by name are listed."`
}

// WebsiteFileText is a text file the editor opened.
type WebsiteFileText struct {
	Path    string      `json:"path"`
	File    WebsiteFile `json:"file"`
	Content string      `json:"content"`
}

// WebsiteFileSave saves a text file whole.
type WebsiteFileSave struct {
	Path            string `json:"path" maxLength:"1024"`
	Content         string `json:"content" doc:"The whole file, UTF-8 text without NUL, at most 1 MiB."`
	ExpectedVersion string `json:"expected_version" doc:"The version the editor opened, or empty for a new file. A file changed since is refused (409)."`
}

// WebsiteFilePath names one file or folder; WebsiteFileRename moves one.
type WebsiteFilePath struct {
	Path string `json:"path" maxLength:"1024"`
}
type WebsiteFileRename struct {
	Path string `json:"path" maxLength:"1024"`
	To   string `json:"to" maxLength:"1024" doc:"The new path, relative to the home. A name that is taken is refused."`
}
type WebsiteFileMode struct {
	Path string `json:"path" maxLength:"1024"`
	Mode string `json:"mode" doc:"Permission bits as three or four octal digits, such as 644 or 0755. setuid, setgid and sticky are refused."`
}

type websiteFilesInput struct {
	AccountID string `path:"account_id"`
	Path      string `query:"path"`
}
type websiteFolderOutput struct{ Body WebsiteFolder }
type websiteFileTextOutput struct{ Body WebsiteFileText }
type websiteFileOutput struct{ Body WebsiteFile }
type websiteFileSaveInput struct {
	AccountID string `path:"account_id"`
	Body      WebsiteFileSave
}
type websiteFilePathInput struct {
	AccountID string `path:"account_id"`
	Body      WebsiteFilePath
}
type websiteFileRenameInput struct {
	AccountID string `path:"account_id"`
	Body      WebsiteFileRename
}
type websiteFileModeInput struct {
	AccountID string `path:"account_id"`
	Body      WebsiteFileMode
}

const (
	filesBase = "/api/v1/websites/sites/{account_id}/files"
	// The site's own folder: deleting, renaming or changing its mode here
	// would take the site offline, so the file manager refuses it.
	siteFolder = "public_html"
	// A save carries up to 1 MiB of text, which JSON can grow to six times
	// that (a control character becomes \u0001).
	maxSaveBody = 6*sitefiles.MaxTextBytes + 16<<10
	filesWait   = 3 * time.Minute  // the broker allows a file operation 2
	transfer    = 16 * time.Minute // and an upload or download 15
)

// What the file routes say. Each says what happened, why, and what to do.
const (
	filesNotSetUp      = "The file manager is not set up on this server: it needs the account service. Nothing was changed."
	filesSuspended     = "This website is suspended, so its files can be looked at and downloaded but not changed. Resume the website on its page to change its files."
	filesBadPath       = "That path cannot be used. A path is relative to the website's home folder; it cannot start with / or hold .., an empty name, or a control character, and each name is at most 255 bytes. Choose another name."
	filesSiteFolder    = "public_html is the folder the website serves, so the file manager does not delete, rename or change the permissions of it. Change what is inside it instead."
	filesTooLargeText  = "The file is larger than 1 MiB, the most the editor opens or saves. Download it to change it on your computer, then upload it."
	filesTooLargeUp    = "The file is larger than 64 MiB, the most one upload can be. Use SFTP for large files."
	filesUploadNeeds   = "The upload must be sent as the file's own bytes with its size (Content-Length), not as a form. Upload it from the Files page."
	filesChanged       = "The file changed after you opened it, so your version was not saved and the newer one is kept. Copy your changes, open the file again, and save them there."
	filesBusy          = "The website is busy: a WordPress install or a restore is writing its files, or four file operations are already running. Nothing was changed. Wait for them to finish, then try again."
	filesNotAnswered   = "The account service did not answer, so the panel cannot tell whether the change was made. Reload the folder to see it as it is now."
	filesReadFailed    = "The account service did not answer, so the folder or file could not be read. Try again in a minute; if it keeps failing, check the Sifruno services on this server."
	filesNeedsCheck    = "The account service has an unfinished change for this website's hosting account and runs nothing as its user until someone has checked it. Nothing was changed. Ask whoever runs this server to check the hosting account."
	filesRefusedByAcct = "The account service refused the request as invalid, so nothing was changed. Reload the page; if it happens again, the panel and the account service may be different versions."
)

// fileErrorText explains the helper's refusal: why, and what to do next.
var fileErrorText = map[string]struct {
	status int
	detail string
}{
	sitefiles.ErrNotFound:    {404, "That file or folder is not there: it may have been moved or deleted meanwhile. Reload the folder and choose it again."},
	sitefiles.ErrExists:      {409, "A file or folder with that name is already there, so nothing was replaced. Choose another name, or delete the other one first."},
	sitefiles.ErrNotAFolder:  {422, "A name on that path is a file, not a folder. Reload the folder and choose it again."},
	sitefiles.ErrIsAFolder:   {422, "That is a folder, not a file. Open it to see what is inside."},
	sitefiles.ErrNotAFile:    {422, "That is not an ordinary file (it is a device, socket or pipe), so the file manager does not open it. Use SFTP if you need it."},
	sitefiles.ErrIsLink:      {422, "That path is, or goes through, a link. The file manager never follows links, so it does not open, change or write through them. Open the folder the link points to inside the home instead, or delete the link itself."},
	sitefiles.ErrTooLarge:    {413, "The file is larger than the file manager allows: 1 MiB for the editor, 1 GiB for a download. Use SFTP for it."},
	sitefiles.ErrBinary:      {422, "This file is not plain text (it is not UTF-8, or it holds NUL bytes), so the editor does not open it. Download it instead."},
	sitefiles.ErrChanged:     {409, filesChanged},
	sitefiles.ErrPermission:  {403, "The website's own permissions do not allow this: the file or folder is not readable or writable by the website's user. Change its permissions in the file manager, then try again."},
	sitefiles.ErrQuota:       {507, "The website's disk quota is full, so nothing was written. Delete files the site does not need, or raise the website's quota, then try again."},
	sitefiles.ErrNoSpace:     {507, "The server's disk is full, so nothing was written. Ask whoever runs this server to free space."},
	sitefiles.ErrTooDeep:     {422, "The folder is nested too deeply to delete from the panel. Delete the deepest folders first, or use SFTP."},
	sitefiles.ErrUnsupported: {422, "The server's filesystem cannot do this here (for example a move between two disks). Copy the file instead: download it and upload it in the new place."},
	sitefiles.ErrInvalid:     {422, filesBadPath},
	sitefiles.ErrFailed:      {503, "The file manager could not finish this for a reason the server did not name. Reload the folder to see what changed, then try again."},
}

// websiteFileError explains an answer of the account service. write says
// whether the request could have changed something.
func websiteFileError(err error, write bool) error {
	technical := errors.New("account service: " + err.Error())
	var failed *hostaccounts.FileError
	if errors.As(err, &failed) {
		known, ok := fileErrorText[failed.Code]
		if !ok {
			known = fileErrorText[sitefiles.ErrFailed]
		}
		return huma.NewError(known.status, known.detail, technical)
	}
	switch {
	case errors.Is(err, hostaccounts.ErrConflict):
		return huma.Error409Conflict(filesBusy, technical)
	case errors.Is(err, hostaccounts.ErrNotFound):
		return huma.Error404NotFound(websiteNotFound, technical)
	case errors.Is(err, hostaccounts.ErrInvalid):
		return huma.Error422UnprocessableEntity(filesRefusedByAcct, technical)
	case errors.Is(err, hostaccounts.ErrRecovery):
		return huma.Error503ServiceUnavailable(filesNeedsCheck, technical)
	case write:
		return huma.Error503ServiceUnavailable(filesNotAnswered, technical)
	default:
		return huma.Error503ServiceUnavailable(filesReadFailed, technical)
	}
}

// filesFor finds the website and its account service. A change needs the
// site to be active; a read works for a suspended site too.
func filesFor(ctx context.Context, o Options, id string, write bool) (hostaccounts.FilesService, hostaccounts.Account, error) {
	site, account, err := findWebsite(ctx, o, id)
	if err != nil {
		return nil, hostaccounts.Account{}, err
	}
	files, ok := o.Accounts.(hostaccounts.FilesService)
	switch {
	case !ok:
		return nil, hostaccounts.Account{}, huma.Error503ServiceUnavailable(filesNotSetUp)
	case site.State == partlyDeleted:
		return nil, hostaccounts.Account{}, huma.Error409Conflict(websitePartly)
	case account.State == "recovery_required":
		return nil, hostaccounts.Account{}, huma.Error503ServiceUnavailable(filesNeedsCheck)
	case write && account.State == "suspended":
		return nil, hostaccounts.Account{}, huma.Error409Conflict(filesSuspended)
	}
	return files, account, nil
}

func checkFilePath(p string, target bool) error {
	names, ok := sitefiles.SplitPath(p)
	if !ok || (target && len(names) == 0) {
		return huma.Error422UnprocessableEntity(filesBadPath)
	}
	return nil
}

func webFile(e hostaccounts.FileEntry) WebsiteFile {
	return WebsiteFile{Name: e.Name, Type: e.Type, Size: e.Size, Mode: e.Mode, Modified: e.Modified, Version: e.Version}
}

// fileRoutes are the file POSTs that take a JSON body, by their last path
// element, with their fields; upload takes the file's bytes instead.
var fileRoutes = map[string][]wizardField{
	"save":   {{name: "path"}, {name: "content"}, {name: "expected_version"}},
	"folder": {{name: "path"}},
	"rename": {{name: "path"}, {name: "to"}},
	"delete": {{name: "path"}},
	"mode":   {{name: "path"}, {name: "mode"}},
}

// fileRoute names a file POST: "save", "folder", "rename", "delete", "mode"
// or "upload", or "" for any other request.
func fileRoute(r *http.Request) string {
	if r.Method != http.MethodPost {
		return ""
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/api/v1/websites/sites/")
	parts := strings.Split(rest, "/")
	if !ok || len(parts) != 3 || !websiteAccountID.MatchString(parts[0]) || parts[1] != "files" {
		return ""
	}
	if _, known := fileRoutes[parts[2]]; known || parts[2] == "upload" {
		return parts[2]
	}
	return ""
}

func allowedFileMutation(r *http.Request) bool { return fileRoute(r) != "" }

// prepareFileJSON applies the wizard's strict body rules with this route's
// fields; a save may be up to maxSaveBody. An upload is the file's bytes,
// which its handler reads as a stream.
func prepareFileJSON(w http.ResponseWriter, r *http.Request) bool {
	route := fileRoute(r)
	if route == "upload" {
		return true
	}
	limit := int64(4096)
	if route == "save" {
		limit = maxSaveBody
	}
	return prepareStrictJSONWithin(w, r, fileRoutes[route], limit)
}

// fileRouteWait is how long a files request may take to answer, or 0 for
// any other request.
func fileRouteWait(r *http.Request) time.Duration {
	rest, ok := strings.CutPrefix(r.URL.Path, "/api/v1/websites/sites/")
	parts := strings.Split(rest, "/")
	if !ok || len(parts) < 2 || parts[1] != "files" {
		return 0
	}
	if len(parts) == 3 && (parts[2] == "upload" || parts[2] == "download") {
		return transfer
	}
	return filesWait
}

// tokenRefusedSiteFiles are a website's file routes a token may not use:
// every change. Listing, reading and downloading stay open to tokens, as
// backup lists do; a script that writes a site's files could plant code
// the site then runs, which a billing system never needs.
var tokenRefusedSiteFiles = []string{"save", "upload", "folder", "rename", "delete", "mode"}

func tokenRefusedSiteFile(p string) bool {
	rest, ok := strings.CutPrefix(p, "/api/v1/websites/sites/")
	if !ok {
		return false
	}
	parts := strings.Split(rest, "/")
	return len(parts) >= 3 && parts[1] == "files" && slices.Contains(tokenRefusedSiteFiles, parts[2])
}

// registerWebsiteFiles adds a website's Files page: list, read and save
// through Huma, and upload and download as streams on the mux.
func registerWebsiteFiles(mux *routeMux, a huma.API, o Options) {
	read := func(id, path string) huma.Operation {
		return huma.Operation{OperationID: id, Method: http.MethodGet, Path: path, SkipValidateParams: true}
	}
	change := func(id, action string, maxBody int64) huma.Operation {
		return huma.Operation{OperationID: id, Method: http.MethodPost, Path: filesBase + "/" + action, MaxBodyBytes: maxBody, BodyReadTimeout: 30 * time.Second, SkipValidateBody: true, SkipValidateParams: true}
	}
	huma.Register(a, read("list-website-files", filesBase), func(ctx context.Context, in *websiteFilesInput) (*websiteFolderOutput, error) {
		files, account, err := filesFor(ctx, o, in.AccountID, false)
		if err != nil {
			return nil, err
		}
		if err := checkFilePath(in.Path, false); err != nil {
			return nil, err
		}
		list, err := files.ListFiles(ctx, account.ID, in.Path, siteActor(ctx))
		if err != nil {
			return nil, websiteFileError(err, false)
		}
		out := WebsiteFolder{Path: list.Path, Entries: make([]WebsiteFile, 0, len(list.Entries)), Skipped: list.Skipped, Truncated: list.Truncated}
		for _, e := range list.Entries {
			out.Entries = append(out.Entries, webFile(e))
		}
		return &websiteFolderOutput{Body: out}, nil
	})
	huma.Register(a, read("read-website-file", filesBase+"/content"), func(ctx context.Context, in *websiteFilesInput) (*websiteFileTextOutput, error) {
		files, account, err := filesFor(ctx, o, in.AccountID, false)
		if err != nil {
			return nil, err
		}
		if err := checkFilePath(in.Path, true); err != nil {
			return nil, err
		}
		text, err := files.ReadFile(ctx, account.ID, in.Path, siteActor(ctx))
		if err != nil {
			return nil, websiteFileError(err, false)
		}
		return &websiteFileTextOutput{Body: WebsiteFileText{Path: in.Path, File: webFile(text.File), Content: text.Content}}, nil
	})
	huma.Register(a, change("save-website-file", "save", maxSaveBody), func(ctx context.Context, in *websiteFileSaveInput) (*websiteFileOutput, error) {
		b := in.Body
		if err := checkFilePath(b.Path, true); err != nil {
			return nil, err
		}
		if len(b.Content) > sitefiles.MaxTextBytes {
			return nil, huma.Error413RequestEntityTooLarge(filesTooLargeText)
		}
		if !sitefiles.Text([]byte(b.Content)) {
			return nil, huma.Error422UnprocessableEntity(fileErrorText[sitefiles.ErrBinary].detail)
		}
		if b.ExpectedVersion != "" && !versionForm(b.ExpectedVersion) {
			return nil, huma.Error422UnprocessableEntity("expected_version must be the version the editor opened (16 hexadecimal digits), or empty for a new file. Open the file again, then save.")
		}
		files, account, err := filesFor(ctx, o, in.AccountID, true)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(ctx, filesWait)
		defer cancel()
		e, err := files.WriteFile(ctx, account.ID, hostaccounts.FileWriteInput{Path: b.Path, Content: b.Content, ExpectedVersion: b.ExpectedVersion}, siteActor(ctx))
		if err != nil {
			return nil, websiteFileError(err, true)
		}
		return &websiteFileOutput{Body: webFile(e)}, nil
	})
	simple := func(action string, call func(context.Context, hostaccounts.FilesService, string, string) (hostaccounts.FileEntry, error)) func(context.Context, string, string, ...string) (*websiteFileOutput, error) {
		return func(ctx context.Context, accountID, path string, more ...string) (*websiteFileOutput, error) {
			if err := checkFilePath(path, true); err != nil {
				return nil, err
			}
			for _, p := range more {
				if err := checkFilePath(p, true); err != nil {
					return nil, err
				}
			}
			if action != "folder" && path == siteFolder {
				return nil, huma.Error409Conflict(filesSiteFolder)
			}
			files, account, err := filesFor(ctx, o, accountID, true)
			if err != nil {
				return nil, err
			}
			ctx, cancel := context.WithTimeout(ctx, filesWait)
			defer cancel()
			e, err := call(ctx, files, account.ID, siteActor(ctx))
			if err != nil {
				return nil, websiteFileError(err, true)
			}
			return &websiteFileOutput{Body: webFile(e)}, nil
		}
	}
	huma.Register(a, change("create-website-folder", "folder", 4096), func(ctx context.Context, in *websiteFilePathInput) (*websiteFileOutput, error) {
		return simple("folder", func(ctx context.Context, f hostaccounts.FilesService, id, actor string) (hostaccounts.FileEntry, error) {
			return f.MakeFolder(ctx, id, in.Body.Path, actor)
		})(ctx, in.AccountID, in.Body.Path)
	})
	huma.Register(a, change("rename-website-file", "rename", 4096), func(ctx context.Context, in *websiteFileRenameInput) (*websiteFileOutput, error) {
		if in.Body.To == in.Body.Path || strings.HasPrefix(in.Body.To, in.Body.Path+"/") {
			return nil, huma.Error422UnprocessableEntity("The new path is the same as the old one, or inside it. Choose another place.")
		}
		return simple("rename", func(ctx context.Context, f hostaccounts.FilesService, id, actor string) (hostaccounts.FileEntry, error) {
			return f.RenameFile(ctx, id, in.Body.Path, in.Body.To, actor)
		})(ctx, in.AccountID, in.Body.Path, in.Body.To)
	})
	huma.Register(a, change("delete-website-file", "delete", 4096), func(ctx context.Context, in *websiteFilePathInput) (*websiteFileOutput, error) {
		return simple("delete", func(ctx context.Context, f hostaccounts.FilesService, id, actor string) (hostaccounts.FileEntry, error) {
			return f.DeleteFile(ctx, id, in.Body.Path, actor)
		})(ctx, in.AccountID, in.Body.Path)
	})
	huma.Register(a, change("set-website-file-mode", "mode", 4096), func(ctx context.Context, in *websiteFileModeInput) (*websiteFileOutput, error) {
		if _, ok := sitefiles.ParseMode(in.Body.Mode); !ok {
			return nil, huma.Error422UnprocessableEntity("mode must be three or four octal digits from 000 to 0777, such as 644 or 0755. setuid, setgid and sticky cannot be set here.")
		}
		return simple("mode", func(ctx context.Context, f hostaccounts.FilesService, id, actor string) (hostaccounts.FileEntry, error) {
			return f.SetFileMode(ctx, id, in.Body.Path, in.Body.Mode, actor)
		})(ctx, in.AccountID, in.Body.Path)
	})

	mux.HandleFunc("GET "+filesBase+"/download", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		q, ok := fileQuery(r.URL.RawQuery, "path")
		if !ok {
			writeFileProblem(w, huma.Error422UnprocessableEntity(filesBadPath))
			return
		}
		if err := checkFilePath(q["path"], true); err != nil {
			writeFileProblem(w, err)
			return
		}
		files, account, err := filesFor(ctx, o, r.PathValue("account_id"), false)
		if err != nil {
			writeFileProblem(w, err)
			return
		}
		extendDeadlines(w, transfer)
		ctx, cancel := context.WithTimeout(ctx, transfer)
		defer cancel()
		e, body, err := files.DownloadFile(ctx, account.ID, q["path"], siteActor(ctx))
		if err != nil {
			writeFileProblem(w, websiteFileError(err, false))
			return
		}
		defer body.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": e.Name}))
		w.Header().Set("Content-Length", strconv.FormatInt(e.Size, 10))
		w.WriteHeader(http.StatusOK)
		// A stream that breaks after the headers ends the response short,
		// which the browser reports as a failed download.
		_, _ = io.CopyN(w, body, e.Size)
	})
	mux.HandleFunc("POST "+filesBase+"/upload", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		q, ok := fileQuery(r.URL.RawQuery, "path", "overwrite")
		overwrite := q["overwrite"] == "true"
		if !ok || (q["overwrite"] != "true" && q["overwrite"] != "false") {
			writeFileProblem(w, huma.Error422UnprocessableEntity("The upload needs path and overwrite (true or false) in its address, and nothing else."))
			return
		}
		if err := checkFilePath(q["path"], true); err != nil {
			writeFileProblem(w, err)
			return
		}
		media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/octet-stream" || len(params) != 0 || r.ContentLength < 0 || len(r.TransferEncoding) != 0 {
			writeFileProblem(w, huma.NewError(http.StatusUnsupportedMediaType, filesUploadNeeds))
			return
		}
		if r.ContentLength > sitefiles.MaxUploadBytes {
			writeFileProblem(w, huma.Error413RequestEntityTooLarge(filesTooLargeUp))
			return
		}
		files, account, err := filesFor(ctx, o, r.PathValue("account_id"), true)
		if err != nil {
			writeFileProblem(w, err)
			return
		}
		extendDeadlines(w, transfer)
		ctx, cancel := context.WithTimeout(ctx, transfer)
		defer cancel()
		body := http.MaxBytesReader(w, r.Body, r.ContentLength)
		e, err := files.UploadFile(ctx, account.ID, hostaccounts.FileUploadInput{Path: q["path"], Size: r.ContentLength, Overwrite: overwrite}, body, siteActor(ctx))
		if err != nil {
			writeFileProblem(w, websiteFileError(err, true))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(webFile(e))
	})
	documentFileTransfers(a)
}

func versionForm(s string) bool {
	if len(s) != 16 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// fileQuery reads a query that holds exactly these keys, each once.
func fileQuery(raw string, keys ...string) (map[string]string, bool) {
	values, err := url.ParseQuery(raw)
	if err != nil || len(values) != len(keys) {
		return nil, false
	}
	out := map[string]string{}
	for _, k := range keys {
		v, ok := values[k]
		if !ok || len(v) != 1 {
			return nil, false
		}
		out[k] = v[0]
	}
	return out, true
}

// extendDeadlines lets a transfer run past the listener's own read and
// write deadlines, up to the transfer's limit.
func extendDeadlines(w http.ResponseWriter, limit time.Duration) {
	rc := http.NewResponseController(w)
	until := time.Now().Add(limit)
	_ = rc.SetReadDeadline(until)
	_ = rc.SetWriteDeadline(until)
}

// writeFileProblem writes a Huma error from a mux handler in the same
// problem form the Huma routes answer with.
func writeFileProblem(w http.ResponseWriter, err error) {
	status, body := http.StatusInternalServerError, any(huma.ErrorModel{Title: "Internal Server Error", Status: 500, Detail: "The panel could not answer."})
	var se huma.StatusError
	if errors.As(err, &se) {
		status, body = se.GetStatus(), se
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// documentFileTransfers describes the two stream routes in the API
// description, as the Huma routes are.
func documentFileTransfers(a huma.API) {
	path := &huma.Param{Name: "path", In: "query", Required: true, Schema: &huma.Schema{Type: "string", MaxLength: intPtr(sitefiles.MaxPathBytes)}, Description: "The file, relative to the website's home folder."}
	id := &huma.Param{Name: "account_id", In: "path", Required: true, Schema: &huma.Schema{Type: "string", Pattern: websiteAccountForm}}
	problem := map[string]*huma.MediaType{"application/problem+json": {Schema: &huma.Schema{Type: "object"}}}
	errorsFor := func(codes ...string) map[string]*huma.Response {
		out := map[string]*huma.Response{}
		for _, c := range codes {
			out[c] = &huma.Response{Description: "A problem: what happened, why and what to do; the account service's own word is in errors[0].message.", Content: problem}
		}
		return out
	}
	download := &huma.Operation{OperationID: "download-website-file", Method: http.MethodGet, Path: filesBase + "/download", Summary: "Download one file of a website's home folder", Description: "Streams the file's bytes as an attachment, at most 1 GiB. Runs as the website's own user; a link is refused, never followed. Admin session or API token.", Parameters: []*huma.Param{id, path}, Responses: errorsFor("403", "404", "409", "413", "422", "503")}
	download.Responses["200"] = &huma.Response{Description: "The file's bytes.", Content: map[string]*huma.MediaType{"application/octet-stream": {Schema: &huma.Schema{Type: "string", Format: "binary"}}}}
	a.OpenAPI().AddOperation(download)
	overwrite := &huma.Param{Name: "overwrite", In: "query", Required: true, Schema: &huma.Schema{Type: "string", Enum: []any{"true", "false"}}, Description: "true replaces a file of that name; false refuses (409)."}
	upload := &huma.Operation{OperationID: "upload-website-file", Method: http.MethodPost, Path: filesBase + "/upload", Summary: "Upload one file into a website's home folder", Description: "The body is the file's own bytes (application/octet-stream) with a Content-Length of at most 64 MiB, streamed to the website's user, so its disk quota applies. The file appears whole or not at all. Admin session with Origin and CSRF; not an API token.", Parameters: []*huma.Param{id, path, overwrite}, RequestBody: &huma.RequestBody{Required: true, Content: map[string]*huma.MediaType{"application/octet-stream": {Schema: &huma.Schema{Type: "string", Format: "binary", MaxLength: intPtr(sitefiles.MaxUploadBytes)}}}}, Responses: errorsFor("403", "404", "409", "413", "415", "422", "503", "507")}
	upload.Responses["200"] = &huma.Response{Description: "The uploaded file.", Content: map[string]*huma.MediaType{"application/json": {Schema: &huma.Schema{Type: "object"}}}}
	a.OpenAPI().AddOperation(upload)
}

func intPtr(n int) *int { return &n }
