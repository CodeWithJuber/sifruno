package api

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/danielgtaylor/huma/v2"
	"sifruno/internal/operator"
	"sifruno/internal/sites"
)

const maxTransferArchive = 34 << 20
const maxTransferBody = maxTransferArchive + 16384

// Native handlers deliberately parse only after the outer operator admission.
// The semaphore spans parsing and storage to bound simultaneous archive memory.
func registerSiteTransfers(mux *http.ServeMux, a huma.API, o Options) {
	slots := make(chan struct{}, 2)
	admit := func(w http.ResponseWriter) bool {
		select {
		case slots <- struct{}{}:
			return true
		default:
			operator.WriteError(w, 503, "unavailable", "Website transfer capacity unavailable")
			return false
		}
	}
	mux.HandleFunc("GET /api/v1/sites/{id}/backups/{backupID}/download", func(w http.ResponseWriter, r *http.Request) {
		if !admit(w) {
			return
		}
		defer func() { <-slots }()
		b, _, err := o.Sites.ExportBackup(r.PathValue("id"), r.PathValue("backupID"))
		if err != nil {
			transferError(w, err)
			return
		}
		if len(b) == 0 || len(b) > maxTransferArchive {
			transferError(w, sites.ErrUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", `attachment; filename="sifruno-site.zip"`)
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		if r.Method != http.MethodHead {
			_, _ = w.Write(b)
		}
	})
	mux.HandleFunc("POST /api/v1/sites/import", func(w http.ResponseWriter, r *http.Request) {
		if !admit(w) {
			return
		}
		defer func() { <-slots }()
		input, status := readSiteImport(w, r)
		if status != 0 {
			operator.WriteError(w, status, "invalid_request", "Invalid website archive request")
			return
		}
		// Multipart parsing includes the bounded epilogue. Revalidate before
		// storage while retaining the transfer slot through every return path.
		actor, ok := o.Operator.Authorize(w, r, true)
		if !ok {
			return
		}
		site, err := o.Sites.ImportArchive(input, actor)
		if err != nil {
			transferError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(site)
	})
	documentSiteTransfers(a)
}

func transferError(w http.ResponseWriter, err error) {
	code := 503
	if errors.Is(err, sites.ErrNotFound) {
		code = 404
	} else if errors.Is(err, sites.ErrConflict) {
		code = 409
	} else if errors.Is(err, sites.ErrInvalid) {
		code = 422
	}
	operator.WriteError(w, code, "website_transfer_failed", "Website transfer could not be completed")
}

func readSiteImport(w http.ResponseWriter, r *http.Request) (sites.ImportInput, int) {
	var in sites.ImportInput
	ct, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || ct != "multipart/form-data" || params["boundary"] == "" || len(params["boundary"]) > 70 || len(params) != 1 {
		return in, 415
	}
	if r.ContentLength > maxTransferBody {
		return in, 413
	}
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(15 * time.Second))
	defer http.NewResponseController(w).SetReadDeadline(time.Time{})
	r.Body = http.MaxBytesReader(w, r.Body, maxTransferBody)
	reader, err := r.MultipartReader()
	if err != nil {
		return in, 400
	}
	seen := map[string]bool{}
	for {
		part, err := reader.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return in, importReadStatus(err)
		}
		name := part.FormName()
		if seen[name] || len(seen) >= 3 || (name != "name" && name != "domain" && name != "archive") || len(part.Header) > 2 {
			return in, 400
		}
		seen[name] = true
		for key, values := range part.Header {
			if len(values) != 1 || (key != "Content-Disposition" && key != "Content-Type") {
				return in, 400
			}
		}
		disp, dp, err := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		if err != nil || disp != "form-data" || dp["name"] != name || len(dp) > 2 || part.Header.Get("Content-Transfer-Encoding") != "" {
			return in, 400
		}
		limit := int64(80)
		if name == "domain" {
			limit = 253
		}
		if name == "archive" {
			if part.FileName() == "" || dp["filename"] == "" {
				return in, 400
			}
			media, mp, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
			if err != nil || len(mp) != 0 || (media != "application/zip" && media != "application/octet-stream") {
				return in, 415
			}
			limit = maxTransferArchive
		} else if len(dp) != 1 || part.Header.Get("Content-Type") != "" {
			return in, 400
		}
		data, err := io.ReadAll(io.LimitReader(part, limit+1))
		if err != nil {
			return in, importReadStatus(err)
		}
		if int64(len(data)) > limit {
			return in, 413
		}
		if len(data) == 0 {
			return in, 400
		}
		switch name {
		case "archive":
			in.Archive = data
		case "name":
			if !utf8.Valid(data) {
				return in, 400
			}
			in.Name = string(data)
		case "domain":
			if !utf8.Valid(data) {
				return in, 400
			}
			in.Domain = string(data)
		}
	}
	if len(seen) != 3 {
		return in, 400
	}
	// Multipart's closing boundary can be followed by an epilogue. Consume it
	// under the same cap so a chunked body cannot bypass total admission limits.
	if _, err := io.Copy(io.Discard, r.Body); err != nil {
		return in, importReadStatus(err)
	}
	return in, 0
}
func importReadStatus(err error) int {
	var large *http.MaxBytesError
	if errors.As(err, &large) {
		return 413
	}
	return 400
}

func documentSiteTransfers(a huma.API) {
	spec := a.OpenAPI()
	problem := &huma.Schema{Ref: "#/components/schemas/OperatorProblem"}
	responses := func() map[string]*huma.Response {
		out := map[string]*huma.Response{}
		for _, code := range []int{400, 401, 403, 404, 409, 413, 415, 422, 503} {
			out[strconv.Itoa(code)] = &huma.Response{Description: http.StatusText(code), Content: map[string]*huma.MediaType{"application/problem+json": {Schema: problem}}}
		}
		return out
	}
	max := maxTransferArchive
	download := &huma.Operation{OperationID: "download-site-backup", Method: "GET", Path: "/api/v1/sites/{id}/backups/{backupID}/download", Summary: "Download a verified native Sifruno v1 static-site ZIP", Parameters: []*huma.Param{{Name: "id", In: "path", Required: true, Schema: &huma.Schema{Type: "string"}}, {Name: "backupID", In: "path", Required: true, Schema: &huma.Schema{Type: "string"}}}, Responses: responses()}
	download.Responses["200"] = &huma.Response{Description: "Hash-verified native site ZIP; fixed safe attachment filename sifruno-site.zip", Content: map[string]*huma.MediaType{"application/zip": {Schema: &huma.Schema{Type: "string", Format: "binary", MaxLength: &max}}}}
	spec.Paths[download.Path] = &huma.PathItem{Get: download}
	nameMax, domainMax := 80, 253
	imp := &huma.Operation{OperationID: "import-site-archive", Method: "POST", Path: "/api/v1/sites/import", Summary: "Import a native Sifruno v1 ZIP into a new static website", RequestBody: &huma.RequestBody{Required: true, Content: map[string]*huma.MediaType{"multipart/form-data": {Schema: &huma.Schema{Type: "object", AdditionalProperties: false, Required: []string{"name", "domain", "archive"}, Properties: map[string]*huma.Schema{"name": {Type: "string", MaxLength: &nameMax, Description: "UTF-8, maximum 80 bytes"}, "domain": {Type: "string", MaxLength: &domainMax}, "archive": {Type: "string", Format: "binary", MaxLength: &max, Description: "Nonempty application/zip or application/octet-stream file; maximum 34 MiB. Native Sifruno v1 only; no cPanel host migration."}}}}}}, Responses: responses()}
	imp.Responses["200"] = &huma.Response{Description: "Actual persisted new website", Content: map[string]*huma.MediaType{"application/json": {Schema: &huma.Schema{Ref: "#/components/schemas/Site"}}}}
	spec.Paths[imp.Path] = &huma.PathItem{Post: imp}
}
