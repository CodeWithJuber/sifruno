package api

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"sifruno/internal/operator"
	"sifruno/internal/sites"
)

type actorKey struct{}

func siteActor(ctx context.Context) string { actor, _ := ctx.Value(actorKey{}).(string); return actor }

type siteIDInput struct {
	ID string `path:"id"`
}
type createSiteInput struct{ Body sites.CreateInput }
type writeSiteInput struct {
	ID   string `path:"id"`
	Body sites.WriteInput
}
type stateSiteInput struct {
	ID   string `path:"id"`
	Body sites.StateInput
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

func allowedSiteMutation(r *http.Request) bool {
	if r.URL.Path == "/api/v1/sites/import" {
		return r.Method == http.MethodPost
	}
	if r.URL.Path == "/api/v1/sites" {
		return r.Method == http.MethodPost
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/sites/"), "/")
	if len(parts) != 2 || parts[0] == "" {
		return false
	}
	return (r.Method == http.MethodPut && (parts[1] == "file" || parts[1] == "backup-schedule")) || (r.Method == http.MethodPost && (parts[1] == "state" || parts[1] == "backups" || parts[1] == "restore"))
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
	case strings.HasSuffix(r.URL.Path, "/file"):
		target = &sites.WriteInput{}
		limit = sites.MaxFileBytes*6 + 8192
	case strings.HasSuffix(r.URL.Path, "/state"):
		target = &sites.StateInput{}
	case strings.HasSuffix(r.URL.Path, "/backups"):
		target = &backupBody{}
	case strings.HasSuffix(r.URL.Path, "/restore"):
		target = &sites.RestoreInput{}
	case strings.HasSuffix(r.URL.Path, "/backup-schedule"):
		target = &sites.BackupScheduleInput{}
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
	if operator.DecodeObject(b, target) != nil || (strings.HasSuffix(r.URL.Path, "/backup-schedule") && !backupScheduleShape(b)) {
		operator.WriteError(w, 400, "invalid_request", "Invalid JSON request")
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	r.ContentLength = int64(len(b))
	return true
}
