package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/operator"
)

const webPreviewPath = "/api/v1/accounts/web-preview"

func registerWebPreview(mux *http.ServeMux, a huma.API, o Options) {
	mux.HandleFunc(webPreviewPath, func(w http.ResponseWriter, r *http.Request) {
		// Account middleware admits a local operator before any broker contact.
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			operator.WriteError(w, 405, "method_not_allowed", "Use GET for native web preview")
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			operator.WriteError(w, 400, "invalid_request", "Web preview accepts no query or body")
			return
		}
		if r.Body != nil && r.Body != http.NoBody {
			_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(5 * time.Second))
			b, err := io.ReadAll(io.LimitReader(r.Body, 1))
			_ = http.NewResponseController(w).SetReadDeadline(time.Time{})
			if err != nil || len(b) != 0 {
				operator.WriteError(w, 400, "invalid_request", "Web preview accepts no query or body")
				return
			}
		}
		if _, ok := o.Operator.Authorize(w, r, false); !ok {
			return
		}
		if o.WebPreview == nil || r.Context().Err() != nil {
			operator.WriteError(w, 503, "web_preview_unavailable", "Native web preview unavailable")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), hostaccounts.MaxSnapshotDuration)
		defer cancel()
		preview, err := o.WebPreview.Preview(ctx)
		if err != nil || ctx.Err() != nil {
			status := http.StatusServiceUnavailable
			if errors.Is(err, hostaccounts.ErrConflict) {
				status = http.StatusConflict
			}
			operator.WriteError(w, status, "web_preview_unavailable", "Native web preview unavailable; inspect broker configuration and recovery status")
			return
		}
		// Buffer before the final session check; a slow broker must not disclose
		// a finished preview to an operator whose session was revoked meanwhile.
		raw, err := json.Marshal(preview)
		if err != nil || ctx.Err() != nil {
			operator.WriteError(w, 503, "web_preview_unavailable", "Native web preview unavailable")
			return
		}
		if _, ok := o.Operator.Authorize(w, r, false); !ok {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(append(raw, '\n'))
	})
	spec := a.OpenAPI()
	schema := spec.Components.Schemas.Schema(reflect.TypeOf(hostaccounts.WebPreview{}), true, "NativeWebPreview")
	responses := map[string]*huma.Response{"200": {Description: "Native configuration metadata preview; no activation", Content: map[string]*huma.MediaType{"application/json": {Schema: schema}}}}
	for _, code := range []int{400, 401, 403, 405, 409, 503} {
		responses[httpCode(code)] = &huma.Response{Description: http.StatusText(code), Content: map[string]*huma.MediaType{"application/problem+json": {Schema: &huma.Schema{Ref: "#/components/schemas/OperatorProblem"}}}}
	}
	spec.Paths[webPreviewPath] = &huma.PathItem{Get: &huma.Operation{
		OperationID: "preview-native-web", Method: http.MethodGet, Path: webPreviewPath,
		Summary:     "Inspect native web configuration metadata without activation",
		Description: "Local operator session required, rechecked before output. GET only, no query or body. The opted-in broker compiles its trusted startup profile under an authoritative account snapshot and returns only digests, counts and file metadata after final verification. No generated files, daemon actions or apply authority. Existing broker recovery bookkeeping can persist when native drift is detected. This is not current serving status, syntax validation, tenant authorization or cPanel compatibility.",
		Security:    []map[string][]string{{"operatorSession": {}}}, Responses: responses,
	}}
}
