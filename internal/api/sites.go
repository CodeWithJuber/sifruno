package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"sifruno/internal/operator"
	"sifruno/internal/sites"
)

type actorKey struct{}

func siteActor(ctx context.Context) string { actor, _ := ctx.Value(actorKey{}).(string); return actor }

// principalKey carries who an admitted request acts for (operator.Principal).
type principalKey struct{}

// requestPrincipal is the admitted request's principal. ok is false when
// none was admitted, which a handler must treat as a refusal.
func requestPrincipal(ctx context.Context) (operator.Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(operator.Principal)
	return p, ok
}

// mayNameOthers reports whether an answer may name another website: an
// admin's may, a customer's must not.
func mayNameOthers(ctx context.Context) bool {
	p, ok := requestPrincipal(ctx)
	return ok && !p.Restricted()
}

type siteIDInput struct {
	ID string `path:"id"`
}
type createSiteInput struct{ Body sites.CreateInput }
type writeSiteInput struct {
	ID   string `path:"id"`
	Body sites.WriteInput
}
type uploadSiteInput struct {
	ID   string `path:"id"`
	Body sites.UploadInput
}
type replaceSiteInput struct {
	ID   string `path:"id"`
	Body sites.ReplaceInput
}
type deleteSiteInput struct {
	ID   string `path:"id"`
	Body sites.DeleteInput
}
type renameSiteInput struct {
	ID   string `path:"id"`
	Body sites.RenameInput
}
type stateSiteInput struct {
	ID   string `path:"id"`
	Body sites.StateInput
}
type domainSiteInput struct {
	ID   string `path:"id"`
	Body sites.DomainInput
}
type nameSiteInput struct {
	ID   string `path:"id"`
	Body sites.NameInput
}
type backupBody struct {
	ExpectedRevision uint64 `json:"expected_revision"`
}
type backupSiteInput struct {
	ID   string `path:"id"`
	Body backupBody
}
type restoreSiteInput struct {
	ID   string `path:"id"`
	Body sites.RestoreInput
}
type removeSiteInput struct {
	ID   string `path:"id"`
	Body sites.RemoveInput
}
type removedSiteOutput struct{ Body sites.RemovedSite }

type removeBackupInput struct {
	ID   string `path:"id"`
	Body sites.RemoveBackupInput
}
type siteFileInput struct {
	ID   string `path:"id"`
	Path string `query:"path"`
}
type siteOutput struct{ Body sites.Site }
type siteFileOutput struct{ Body sites.FileContent }
type siteBackupOutput struct{ Body sites.BackupInfo }
type sitesBody struct {
	Items []sites.Site `json:"items"`
}
type siteFilesBody struct {
	Items []sites.FileInfo `json:"items"`
}
type siteBackupsBody struct {
	Items []sites.BackupInfo `json:"items"`
}
type sitesOutput struct{ Body sitesBody }
type siteFilesOutput struct{ Body siteFilesBody }
type siteBackupsOutput struct{ Body siteBackupsBody }

func websiteError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, sites.ErrNotFound):
		return huma.Error404NotFound("Website resource not found")
	case errors.Is(err, sites.ErrConflict):
		return huma.Error409Conflict("Website revision or file content changed; refresh before retrying")
	case errors.Is(err, sites.ErrInvalid):
		return huma.Error422UnprocessableEntity("Invalid website request")
	default:
		return huma.Error503ServiceUnavailable("Website storage or recovery unavailable")
	}
}

func siteOperation(id, method, path string) huma.Operation {
	// The middleware strictly decodes bounded bodies first. Skipping Huma's
	// duplicate validation prevents invalid payloads from being echoed in errors.
	return huma.Operation{OperationID: id, Method: method, Path: path, MaxBodyBytes: sites.MaxFileBytes*6 + 8192, BodyReadTimeout: 5 * time.Second, SkipValidateBody: true, SkipValidateParams: true}
}

func registerSites(a huma.API, o Options) {
	registerFileRestore(a, o)
	remove := siteOperation("remove-native-site", "DELETE", "/api/v1/sites/{id}")
	remove.MaxBodyBytes = 4096
	remove.Summary = "Confirm permanent removal of one native static website"
	remove.Description = "Exact expected_revision, confirmation_domain and confirmed:true required. Removes owned static files, native ZIPs, schedule and local routing only after signed bounded cleanup. Unknown files or recovery refuse. Interrupted committed cleanup remains unavailable until exact recovery on reopen. Signed audit remains; this is not a host or cPanel operation."
	huma.Register(a, remove, func(ctx context.Context, in *removeSiteInput) (*removedSiteOutput, error) {
		v, err := o.Sites.Remove(in.ID, in.Body, siteActor(ctx))
		if err != nil {
			return nil, websiteError(err)
		}
		return &removedSiteOutput{Body: v}, nil
	})
	nameOp := siteOperation("change-site-name", "PUT", "/api/v1/sites/{id}/name")
	nameOp.MaxBodyBytes = 4096
	nameOp.Summary = "Edit one website display name at its expected revision"
	huma.Register(a, nameOp, func(ctx context.Context, in *nameSiteInput) (*siteOutput, error) {
		v, err := o.Sites.ChangeName(in.ID, in.Body, siteActor(ctx))
		if err != nil {
			return nil, websiteError(err)
		}
		return &siteOutput{Body: v}, nil
	})
	op := siteOperation("remove-native-site-backup", "POST", "/api/v1/sites/{id}/remove-backup")
	op.MaxBodyBytes = 4096
	op.Summary = "Confirm removal of one exact saved native static-site ZIP"
	op.Description = "Requires exactly backup_id, expected_backup_sha256, expected_revision and confirmed:true. Commits signed catalog removal before exact ZIP unlink. Retains current static files, routing, other archives and schedule intent; no automatic retention or schedule re-enable. Unresolved cleanup returns 503 and blocks site operations until reopen resolves the exact signed transition. Origin, CSRF and session are checked before and after bounded JSON reading."
	huma.Register(a, op, func(ctx context.Context, in *removeBackupInput) (*siteOutput, error) {
		v, err := o.Sites.RemoveBackup(in.ID, in.Body, siteActor(ctx))
		if err != nil {
			return nil, websiteError(err)
		}
		return &siteOutput{Body: v}, nil
	})
	huma.Register(a, siteOperation("rename-site-file", "POST", "/api/v1/sites/{id}/rename"), func(ctx context.Context, in *renameSiteInput) (*siteOutput, error) {
		v, err := o.Sites.RenameFile(in.ID, in.Body, siteActor(ctx))
		if err != nil {
			return nil, websiteError(err)
		}
		return &siteOutput{Body: v}, nil
	})
	huma.Register(a, siteOperation("replace-site-file", "PUT", "/api/v1/sites/{id}/upload"), func(ctx context.Context, in *replaceSiteInput) (*siteOutput, error) {
		v, err := o.Sites.ReplaceFile(in.ID, in.Body, siteActor(ctx))
		if err != nil {
			return nil, websiteError(err)
		}
		return &siteOutput{Body: v}, nil
	})
	huma.Register(a, siteOperation("upload-site-file", "POST", "/api/v1/sites/{id}/upload"), func(ctx context.Context, in *uploadSiteInput) (*siteOutput, error) {
		v, err := o.Sites.UploadFile(in.ID, in.Body, siteActor(ctx))
		if err != nil {
			return nil, websiteError(err)
		}
		return &siteOutput{Body: v}, nil
	})
	huma.Register(a, siteOperation("list-sites", "GET", "/api/v1/sites"), func(ctx context.Context, in *struct{}) (*sitesOutput, error) {
		v, err := o.Sites.List()
		if err != nil {
			return nil, websiteError(err)
		}
		if v == nil {
			v = []sites.Site{}
		}
		return &sitesOutput{Body: sitesBody{Items: v}}, nil
	})
	huma.Register(a, siteOperation("create-site", "POST", "/api/v1/sites"), func(ctx context.Context, in *createSiteInput) (*siteOutput, error) {
		v, err := o.Sites.Create(in.Body, siteActor(ctx))
		if err != nil {
			return nil, websiteError(err)
		}
		return &siteOutput{Body: v}, nil
	})
	huma.Register(a, siteOperation("get-site", "GET", "/api/v1/sites/{id}"), func(ctx context.Context, in *siteIDInput) (*siteOutput, error) {
		v, err := o.Sites.Get(in.ID)
		if err != nil {
			return nil, websiteError(err)
		}
		return &siteOutput{Body: v}, nil
	})
	huma.Register(a, siteOperation("list-site-files", "GET", "/api/v1/sites/{id}/files"), func(ctx context.Context, in *siteIDInput) (*siteFilesOutput, error) {
		v, err := o.Sites.Files(in.ID)
		if err != nil {
			return nil, websiteError(err)
		}
		if v == nil {
			v = []sites.FileInfo{}
		}
		return &siteFilesOutput{Body: siteFilesBody{Items: v}}, nil
	})
	huma.Register(a, siteOperation("read-site-file", "GET", "/api/v1/sites/{id}/file"), func(ctx context.Context, in *siteFileInput) (*siteFileOutput, error) {
		if len(in.Path) > 512 {
			return nil, websiteError(sites.ErrInvalid)
		}
		v, err := o.Sites.ReadFile(in.ID, in.Path)
		if err != nil {
			return nil, websiteError(err)
		}
		return &siteFileOutput{Body: v}, nil
	})
	huma.Register(a, siteOperation("write-site-file", "PUT", "/api/v1/sites/{id}/file"), func(ctx context.Context, in *writeSiteInput) (*siteOutput, error) {
		v, err := o.Sites.WriteFile(in.ID, in.Body, siteActor(ctx))
		if err != nil {
			return nil, websiteError(err)
		}
		return &siteOutput{Body: v}, nil
	})
	huma.Register(a, siteOperation("delete-site-file", "DELETE", "/api/v1/sites/{id}/file"), func(ctx context.Context, in *deleteSiteInput) (*siteOutput, error) {
		v, err := o.Sites.DeleteFile(in.ID, in.Body, siteActor(ctx))
		if err != nil {
			return nil, websiteError(err)
		}
		return &siteOutput{Body: v}, nil
	})
	huma.Register(a, siteOperation("change-site-domain", "PUT", "/api/v1/sites/{id}/domain"), func(ctx context.Context, in *domainSiteInput) (*siteOutput, error) {
		v, err := o.Sites.ChangeDomain(in.ID, in.Body, siteActor(ctx))
		if err != nil {
			return nil, websiteError(err)
		}
		return &siteOutput{Body: v}, nil
	})
	huma.Register(a, siteOperation("set-site-state", "POST", "/api/v1/sites/{id}/state"), func(ctx context.Context, in *stateSiteInput) (*siteOutput, error) {
		v, err := o.Sites.SetState(in.ID, in.Body, siteActor(ctx))
		if err != nil {
			return nil, websiteError(err)
		}
		return &siteOutput{Body: v}, nil
	})
	huma.Register(a, siteOperation("list-site-backups", "GET", "/api/v1/sites/{id}/backups"), func(ctx context.Context, in *siteIDInput) (*siteBackupsOutput, error) {
		v, err := o.Sites.Backups(in.ID)
		if err != nil {
			return nil, websiteError(err)
		}
		if v == nil {
			v = []sites.BackupInfo{}
		}
		return &siteBackupsOutput{Body: siteBackupsBody{Items: v}}, nil
	})
	huma.Register(a, siteOperation("backup-site", "POST", "/api/v1/sites/{id}/backups"), func(ctx context.Context, in *backupSiteInput) (*siteBackupOutput, error) {
		v, err := o.Sites.Backup(in.ID, in.Body.ExpectedRevision, siteActor(ctx))
		if err != nil {
			return nil, websiteError(err)
		}
		return &siteBackupOutput{Body: v}, nil
	})
	huma.Register(a, siteOperation("restore-site", "POST", "/api/v1/sites/{id}/restore"), func(ctx context.Context, in *restoreSiteInput) (*siteOutput, error) {
		v, err := o.Sites.Restore(in.ID, in.Body, siteActor(ctx))
		if err != nil {
			return nil, websiteError(err)
		}
		return &siteOutput{Body: v}, nil
	})
}

func isSitePath(path string) bool {
	return path == "/api/v1/sites" || strings.HasPrefix(path, "/api/v1/sites/")
}
func isSessionPath(path string) bool {
	return path == "/api/v1/session" || strings.HasPrefix(path, "/api/v1/session/")
}

// tokenAreas are the parts of the API an API token may use: the hosting work
// a script such as the WHMCS module does, and the API description. It is an
// allow list, so a route added later anywhere else, a credential route
// included, refuses tokens until it is named here.
var tokenAreas = []string{"/api/v1/accounts", "/api/v1/server", "/api/v1/services", "/api/v1/sites", "/api/v1/status", "/api/v1/websites"}

// tokenRefused are routes inside those areas that set up credentials: backup
// storage holds the storage server's details and shows the repository
// password until it is saved. They are for a signed-in admin only.
var tokenRefused = []string{"/api/v1/websites/backup-storage"}

// tokenRefusedSiteBackups are a website's backup routes a token may not
// use: a restore overwrites the site's files and database, and a drill
// stages a whole copy of the site. Backing up now and the backup list stay
// open to tokens. The site's id sits in the middle of the path, so these
// cannot be prefixes in tokenRefused.
var tokenRefusedSiteBackups = []string{"restore", "drill"}

func tokenRefusedSiteBackup(p string) bool {
	rest, ok := strings.CutPrefix(p, "/api/v1/websites/sites/")
	if !ok {
		return false
	}
	parts := strings.Split(rest, "/")
	return len(parts) >= 3 && parts[1] == "backups" && slices.Contains(tokenRefusedSiteBackups, parts[2])
}

// tokenRefusedOldSiteBackups are the older ZIP backup routes under
// /api/v1/sites/{id} that overwrite a site, remove a backup or hand out its
// contents. Taking a backup and listing them stay open to tokens.
var tokenRefusedOldSiteBackups = []string{"restore", "restore-preview", "restore-file", "restore-file-preview", "archive-restore", "remove-backup"}

func tokenRefusedOldSiteBackup(p string) bool {
	rest, ok := strings.CutPrefix(p, "/api/v1/sites/")
	if !ok {
		return false
	}
	parts := strings.Split(rest, "/")
	if len(parts) >= 2 && slices.Contains(tokenRefusedOldSiteBackups, parts[1]) {
		return true
	}
	// /api/v1/sites/{id}/backups/{backupID}/download
	return len(parts) >= 4 && parts[1] == "backups" && parts[3] == "download"
}

func tokenArea(p string) bool {
	if path.Clean(p) != p {
		return false
	}
	if p == "/openapi.json" {
		return true
	}
	for _, refused := range tokenRefused {
		if p == refused || strings.HasPrefix(p, refused+"/") {
			return false
		}
	}
	if tokenRefusedSiteBackup(p) || tokenRefusedOldSiteBackup(p) || tokenRefusedSiteFile(p) {
		return false
	}
	for _, area := range tokenAreas {
		if p == area || strings.HasPrefix(p, area+"/") {
			return true
		}
	}
	return false
}

func isSiteTransferMutation(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	if r.URL.Path == "/api/v1/sites/import" {
		return true
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/sites/"), "/")
	return len(parts) == 2 && parts[0] != "" && (parts[1] == "archive-restore-preview" || parts[1] == "archive-restore")
}

func allowedSiteMutation(r *http.Request) bool {
	if isSiteTransferMutation(r) {
		return r.Method == http.MethodPost
	}
	if r.URL.Path == "/api/v1/sites" {
		return r.Method == http.MethodPost
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/sites/"), "/")
	if len(parts) == 1 && parts[0] != "" {
		return r.Method == http.MethodDelete
	}
	if len(parts) != 2 || parts[0] == "" {
		return false
	}
	return (r.Method == http.MethodDelete && parts[1] == "file") || (r.Method == http.MethodPut && (parts[1] == "file" || parts[1] == "upload" || parts[1] == "domain" || parts[1] == "name" || parts[1] == "backup-schedule")) || (r.Method == http.MethodPost && (parts[1] == "rename" || parts[1] == "upload" || parts[1] == "state" || parts[1] == "backups" || parts[1] == "restore" || parts[1] == "restore-preview" || parts[1] == "restore-file-preview" || parts[1] == "restore-file" || parts[1] == "remove-backup"))
}

func prepareSiteJSON(w http.ResponseWriter, r *http.Request) bool {
	ct, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || ct != "application/json" || (params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8")) {
		operator.WriteError(w, 415, "invalid_request", "JSON content type required")
		return false
	}
	limit := int64(4096)
	var target any
	switch {
	case r.URL.Path == "/api/v1/sites":
		target = &sites.CreateInput{}
	case isRemoveSiteRequest(r):
		target = &sites.RemoveInput{}
	case strings.HasSuffix(r.URL.Path, "/upload"):
		if r.Method == http.MethodPut {
			target = &sites.ReplaceInput{}
		} else {
			target = &sites.UploadInput{}
		}
		limit = ((sites.MaxFileBytes+2)/3)*4 + 8192
	case strings.HasSuffix(r.URL.Path, "/file"):
		if r.Method == http.MethodDelete {
			target = &sites.DeleteInput{}
		} else {
			target = &sites.WriteInput{}
			limit = sites.MaxFileBytes*6 + 8192
		}
	case strings.HasSuffix(r.URL.Path, "/state"):
		target = &sites.StateInput{}
	case strings.HasSuffix(r.URL.Path, "/rename"):
		target = &sites.RenameInput{}
	case strings.HasSuffix(r.URL.Path, "/domain"):
		target = &sites.DomainInput{}
	case strings.HasSuffix(r.URL.Path, "/name"):
		target = &sites.NameInput{}
	case strings.HasSuffix(r.URL.Path, "/backups"):
		target = &backupBody{}
	case strings.HasSuffix(r.URL.Path, "/restore-file-preview"):
		target = &sites.FileRestoreInput{}
	case strings.HasSuffix(r.URL.Path, "/restore-file"):
		target = &sites.ConfirmFileRestoreInput{}
	case strings.HasSuffix(r.URL.Path, "/restore"):
		target = &sites.RestoreInput{}
	case strings.HasSuffix(r.URL.Path, "/restore-preview"):
		target = &sites.RestoreInput{}
	case strings.HasSuffix(r.URL.Path, "/backup-schedule"):
		target = &sites.BackupScheduleInput{}
	case strings.HasSuffix(r.URL.Path, "/remove-backup"):
		target = &sites.RemoveBackupInput{}
	default:
		operator.WriteError(w, 400, "invalid_request", "Invalid website request")
		return false
	}
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(5 * time.Second))
	defer http.NewResponseController(w).SetReadDeadline(time.Time{})
	b, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		operator.WriteError(w, 400, "invalid_request", "Invalid JSON request")
		return false
	}
	if int64(len(b)) > limit {
		operator.WriteError(w, 413, "invalid_request", "Request body too large")
		return false
	}
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		operator.WriteError(w, 400, "invalid_request", "JSON object required")
		return false
	}
	if operator.DecodeObject(b, target) != nil || (strings.HasSuffix(r.URL.Path, "/name") && !nameShape(b)) || (isRemoveSiteRequest(r) && !removeSiteShape(b)) || (strings.HasSuffix(r.URL.Path, "/restore-file-preview") && !fileRestoreShape(b, false)) || (strings.HasSuffix(r.URL.Path, "/restore-file") && !fileRestoreShape(b, true)) || (strings.HasSuffix(r.URL.Path, "/rename") && !renameShape(b)) || (strings.HasSuffix(r.URL.Path, "/upload") && !uploadShape(b, r.Method == http.MethodPut)) || (strings.HasSuffix(r.URL.Path, "/backup-schedule") && !backupScheduleShape(b)) || (strings.HasSuffix(r.URL.Path, "/restore-preview") && !restorePreviewShape(b)) || (strings.HasSuffix(r.URL.Path, "/remove-backup") && !removeBackupShape(b)) {
		operator.WriteError(w, 400, "invalid_request", "Invalid JSON request")
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	r.ContentLength = int64(len(b))
	return true
}

func nameShape(raw []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 2 {
		return false
	}
	for _, key := range []string{"name", "expected_revision"} {
		v, ok := fields[key]
		v = bytes.TrimSpace(v)
		if !ok || len(v) == 0 || bytes.Equal(v, []byte("null")) || (key == "name" && v[0] != '"') {
			return false
		}
	}
	return true
}

func removeBackupShape(raw []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 4 {
		return false
	}
	for _, key := range []string{"backup_id", "expected_backup_sha256", "expected_revision", "confirmed"} {
		v, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return false
		}
	}
	return true
}

func renameShape(raw []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 4 {
		return false
	}
	for _, key := range []string{"path", "destination", "expected_sha256", "expected_revision"} {
		value, ok := fields[key]
		value = bytes.TrimSpace(value)
		if !ok || len(value) == 0 || bytes.Equal(value, []byte("null")) || (key != "expected_revision" && value[0] != '"') {
			return false
		}
	}
	return true
}

// Require exact keys and types, including a present (possibly empty) base64
// string. encoding/json also accepts byte arrays for []byte; this API does not.
func uploadShape(raw []byte, replacement bool) bool {
	keys := []string{"path", "content", "expected_revision"}
	if replacement {
		keys = append(keys, "expected_sha256")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != len(keys) {
		return false
	}
	for _, key := range keys {
		value, ok := fields[key]
		value = bytes.TrimSpace(value)
		if !ok || len(value) == 0 || bytes.Equal(value, []byte("null")) {
			return false
		}
		if key != "expected_revision" && value[0] != '"' {
			return false
		}
	}
	return true
}

func isRemoveSiteRequest(r *http.Request) bool {
	return r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/sites/") && len(strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/sites/"), "/")) == 1
}
func removeSiteShape(raw []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 3 {
		return false
	}
	for _, key := range []string{"expected_revision", "confirmation_domain", "confirmed"} {
		v, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return false
		}
	}
	return true
}
