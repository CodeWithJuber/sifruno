package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"sifruno/internal/operator"
	"sifruno/internal/sites"
)

func restorePreviewShape(raw []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 2 {
		return false
	}
	for _, key := range []string{"backup_id", "expected_revision"} {
		value, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	return true
}

func registerRestorePreview(mux *routeMux, a huma.API, o Options) {
	// Outer middleware admits the local session, exact origin and CSRF token
	// before bounded strict JSON parsing. A raw response preserves the exact DTO.
	mux.HandleFunc("POST /api/v1/sites/{id}/restore-preview", func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		var input sites.RestoreInput
		if err != nil || len(raw) > 4096 || operator.DecodeObject(raw, &input) != nil || !restorePreviewShape(raw) {
			operator.WriteError(w, 400, "invalid_request", "Invalid JSON request")
			return
		}
		preview, err := o.Sites.PreviewRestore(r.PathValue("id"), input)
		if err != nil {
			status, detail := 503, "Native restore preview storage or recovery unavailable"
			switch {
			case errors.Is(err, sites.ErrNotFound):
				status, detail = 404, "Website resource not found"
			case errors.Is(err, sites.ErrConflict):
				status, detail = 409, "Website revision or file content changed; refresh before retrying"
			case errors.Is(err, sites.ErrInvalid):
				status, detail = 422, "Invalid native restore preview"
			}
			operator.WriteError(w, status, "restore_preview_failed", detail)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(preview)
	})
	documentRestorePreview(a)
}

func documentRestorePreview(a huma.API) {
	spec := a.OpenAPI()
	schemas := spec.Components.Schemas.Map()
	ref := func(name string) *huma.Schema { return &huma.Schema{Ref: "#/components/schemas/" + name} }
	one, zero, ceiling := float64(1), float64(0), float64(9007199254740991)
	fileBytes, countMax := float64(sites.MaxFileBytes), float64(2*sites.MaxFiles)
	idLength, hashLength, pathMin, pathLength, maxFiles := 32, 64, 1, 200, 2*sites.MaxFiles
	id := func() *huma.Schema {
		return &huma.Schema{Type: "string", Pattern: "^[0-9a-f]{32}$", MinLength: &idLength, MaxLength: &idLength}
	}
	hash := func() *huma.Schema {
		return &huma.Schema{Type: "string", Pattern: "^[0-9a-f]{64}$", MinLength: &hashLength, MaxLength: &hashLength}
	}
	revision := func() *huma.Schema { return &huma.Schema{Type: "integer", Minimum: &one, Maximum: &ceiling} }
	pathSchema := func() *huma.Schema {
		return &huma.Schema{Type: "string", MinLength: &pathMin, MaxLength: &pathLength, Description: "Validated ASCII relative managed file path; never an operator filesystem path"}
	}
	count := func() *huma.Schema { return &huma.Schema{Type: "integer", Minimum: &zero, Maximum: &countMax} }
	schemas["NativeRestorePreviewInput"] = &huma.Schema{Type: "object", AdditionalProperties: false, Required: []string{"backup_id", "expected_revision"}, Properties: map[string]*huma.Schema{"backup_id": id(), "expected_revision": revision()}}
	schemas["NativeRestorePreviewFileInfo"] = &huma.Schema{Type: "object", AdditionalProperties: false, Required: []string{"path", "bytes", "sha256"}, Properties: map[string]*huma.Schema{"path": pathSchema(), "bytes": {Type: "integer", Minimum: &zero, Maximum: &fileBytes}, "sha256": hash()}}
	nullableFile := func() *huma.Schema {
		return &huma.Schema{OneOf: []*huma.Schema{ref("NativeRestorePreviewFileInfo"), {Type: "null"}}}
	}
	schemas["NativeRestorePreviewFile"] = &huma.Schema{Type: "object", AdditionalProperties: false, Required: []string{"path", "kind", "before", "after"}, Properties: map[string]*huma.Schema{"path": pathSchema(), "kind": {Type: "string", Enum: []any{"added", "modified", "removed", "unchanged"}}, "before": nullableFile(), "after": nullableFile()}}
	schemas["NativeRestorePreviewCounts"] = &huma.Schema{Type: "object", AdditionalProperties: false, Required: []string{"added", "modified", "removed", "unchanged"}, Properties: map[string]*huma.Schema{"added": count(), "modified": count(), "removed": count(), "unchanged": count()}}
	schemas["NativeRestorePreview"] = &huma.Schema{Type: "object", AdditionalProperties: false, Required: []string{"site_id", "current_revision", "backup_id", "backup_sha256", "backup_revision", "files", "counts"}, Properties: map[string]*huma.Schema{"site_id": id(), "current_revision": revision(), "backup_id": id(), "backup_sha256": hash(), "backup_revision": revision(), "files": {Type: "array", MaxItems: &maxFiles, Items: ref("NativeRestorePreviewFile"), Description: "ASCII path-sorted union; before/after path equals entry path. Unchanged requires equal bytes and SHA256."}, "counts": {Ref: "#/components/schemas/NativeRestorePreviewCounts", Description: "Exact category counts; their sum equals files length"}}}
	responses := map[string]*huma.Response{"200": {Description: "Verified read-only native static-site restore preview", Content: map[string]*huma.MediaType{"application/json": {Schema: ref("NativeRestorePreview")}}}}
	for _, code := range []int{400, 401, 403, 404, 409, 413, 415, 422, 503} {
		responses[httpCode(code)] = &huma.Response{Description: http.StatusText(code), Content: map[string]*huma.MediaType{"application/problem+json": {Schema: ref("OperatorProblem")}}}
	}
	endpoint := "/api/v1/sites/{id}/restore-preview"
	spec.Paths[endpoint] = &huma.PathItem{Post: &huma.Operation{OperationID: "preview-native-site-restore", Method: "POST", Path: endpoint, Summary: "Preview a verified native static-site restore without changing state", Description: "Native Sifruno ZIP only. Exact two lowercase non-null keys, no duplicate or unknown keys; maximum 4 KiB JSON body. Requires a local operator session, matching Origin and CSRF before body parsing. Missing site/backup returns 404; stale revision or snapshot/current-content conflict 409; invalid IDs/revision 422; sealed checkpoint/storage integrity, recovery, corrupt archive or ambiguous case-alias union 503. No contents or private paths. Preview never changes site metadata, revisions, files, journal or backup schedule; a subsequent restore must revalidate the current revision.", MaxBodyBytes: 4096, Security: []map[string][]string{{"operatorSession": {}, "sessionCSRF": {}}}, Parameters: []*huma.Param{{Name: "id", In: "path", Required: true, Schema: id()}, {Name: "Origin", In: "header", Required: true, Schema: &huma.Schema{Type: "string"}}, {Name: "X-CSRF-Token", In: "header", Required: true, Schema: &huma.Schema{Type: "string"}}}, RequestBody: &huma.RequestBody{Required: true, Content: map[string]*huma.MediaType{"application/json": {Schema: ref("NativeRestorePreviewInput")}}}, Responses: responses}}
}
