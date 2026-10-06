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

type backupScheduleEnvelope struct {
	Schedule      *sites.BackupSchedule `json:"schedule"`
	Intervals     []string              `json:"intervals"`
	MaxArchives   int                   `json:"max_archives"`
	RunnerEnabled bool                  `json:"runner_enabled"`
}

// Go's scalar decoder accepts null/missing fields and case aliases. These four
// exact non-null keys are required in addition to DecodeObject's duplicate gate.
func backupScheduleShape(raw []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 4 {
		return false
	}
	for _, key := range []string{"expected_revision", "expected_schedule_revision", "interval", "enabled"} {
		value, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	return true
}

func backupScheduleError(w http.ResponseWriter, err error) {
	status, detail := 503, "Native backup schedule storage or recovery unavailable"
	switch {
	case errors.Is(err, sites.ErrNotFound):
		status, detail = 404, "Website resource not found"
	case errors.Is(err, sites.ErrConflict):
		status, detail = 409, "Website or schedule changed; refresh both revisions before retrying"
	case errors.Is(err, sites.ErrInvalid):
		status, detail = 422, "Invalid native backup schedule"
	}
	operator.WriteError(w, status, "backup_schedule_failed", detail)
}

func registerBackupSchedules(mux *http.ServeMux, a huma.API, o Options) {
	respond := func(w http.ResponseWriter, schedule *sites.BackupSchedule) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(backupScheduleEnvelope{schedule, []string{"hourly", "daily", "weekly"}, sites.MaxBackups, o.BackupSchedulerEnabled})
	}
	mux.HandleFunc("GET /api/v1/sites/{id}/backup-schedule", func(w http.ResponseWriter, r *http.Request) {
		job, err := o.Sites.BackupSchedule(r.PathValue("id"))
		if err != nil {
			backupScheduleError(w, err)
			return
		}
		respond(w, job)
	})
	mux.HandleFunc("PUT /api/v1/sites/{id}/backup-schedule", func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		var input sites.BackupScheduleInput
		if err != nil || len(raw) > 4096 || operator.DecodeObject(raw, &input) != nil || !backupScheduleShape(raw) {
			operator.WriteError(w, 400, "invalid_request", "Invalid JSON request")
			return
		}
		if input.Enabled != nil && *input.Enabled && !o.BackupSchedulerEnabled {
			operator.WriteError(w, 503, "backup_scheduler_disabled", "Start the native backup scheduler before enabling a schedule")
			return
		}
		job, err := o.Sites.SetBackupSchedule(r.PathValue("id"), input, siteActor(r.Context()))
		if err != nil {
			backupScheduleError(w, err)
			return
		}
		respond(w, &job)
	})
	documentBackupSchedules(a)
}

func documentBackupSchedules(a huma.API) {
	spec := a.OpenAPI()
	schemas := spec.Components.Schemas.Map()
	ref := func(name string) *huma.Schema { return &huma.Schema{Ref: "#/components/schemas/" + name} }
	zero, one, ceiling := float64(0), float64(1), float64(9007199254740991)
	revision := func(minimum *float64) *huma.Schema {
		return &huma.Schema{Type: "integer", Minimum: minimum, Maximum: &ceiling}
	}
	id := func() *huma.Schema { return &huma.Schema{Type: "string", Pattern: "^[0-9a-f]{32}$"} }
	stamp := func() *huma.Schema {
		return &huma.Schema{Type: "string", Format: "date-time", Pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"}
	}
	interval := func() *huma.Schema { return &huma.Schema{Type: "string", Enum: []any{"hourly", "daily", "weekly"}} }
	schemas["NativeBackupScheduleInput"] = &huma.Schema{Type: "object", AdditionalProperties: false, Required: []string{"expected_revision", "expected_schedule_revision", "interval", "enabled"}, Properties: map[string]*huma.Schema{
		"expected_revision": revision(&one), "expected_schedule_revision": revision(&zero), "interval": interval(), "enabled": {Type: "boolean"},
	}}
	properties := map[string]*huma.Schema{
		"site_id": id(), "revision": revision(&one), "interval": interval(), "enabled": {Type: "boolean"},
		"created_at": stamp(), "updated_at": stamp(), "next_run_at": stamp(), "last_run_at": {OneOf: []*huma.Schema{stamp(), {Type: "null"}}},
		"last_status":    {Type: "string", Enum: []any{"never", "completed", "failed", "interrupted"}},
		"last_backup_id": {Type: "string", Pattern: "^([0-9a-f]{32})?$"}, "last_error": {Type: "string", Enum: []any{"", "archive_capacity", "backup_failed", "interrupted"}}, "pending": {Type: "boolean"},
	}
	schemas["NativeBackupSchedule"] = &huma.Schema{Type: "object", AdditionalProperties: false, Required: []string{"site_id", "revision", "interval", "enabled", "created_at", "updated_at", "next_run_at", "last_run_at", "last_status", "last_backup_id", "last_error", "pending"}, Properties: properties}
	schemas["NativeBackupScheduleEnvelope"] = &huma.Schema{Type: "object", AdditionalProperties: false, Required: []string{"schedule", "intervals", "max_archives", "runner_enabled"}, Properties: map[string]*huma.Schema{
		"schedule":  {OneOf: []*huma.Schema{ref("NativeBackupSchedule"), {Type: "null"}}},
		"intervals": {Type: "array", Items: interval(), Description: "Exactly hourly, daily, weekly in this order"}, "max_archives": {Type: "integer", Enum: []any{8}}, "runner_enabled": {Type: "boolean"},
	}}
	responses := func() map[string]*huma.Response {
		out := map[string]*huma.Response{"200": {Description: "Native static-site schedule; null until configured", Content: map[string]*huma.MediaType{"application/json": {Schema: ref("NativeBackupScheduleEnvelope")}}}}
		for _, code := range []int{400, 401, 403, 404, 409, 413, 415, 422, 503} {
			out[httpCode(code)] = &huma.Response{Description: http.StatusText(code), Content: map[string]*huma.MediaType{"application/problem+json": {Schema: ref("OperatorProblem")}}}
		}
		return out
	}
	path := "/api/v1/sites/{id}/backup-schedule"
	parameter := &huma.Param{Name: "id", In: "path", Required: true, Schema: id()}
	description := "App-owned static-site ZIP schedule only. One per site, hourly/daily/weekly UTC duration, at most 100 sites. Process flag --backup-scheduler is opt-in. Four sequential jobs per 30-second cycle; no catch-up burst. Manual and scheduled archives share eight slots and 128 MiB per site; no automatic rotation. Interrupted uncertainty is paused and retained for explicit review. Configuration does not advance site revision; archive creation does."
	spec.Paths[path] = &huma.PathItem{
		Get: &huma.Operation{OperationID: "get-native-backup-schedule", Method: "GET", Path: path, Summary: "Read a native website backup schedule", Description: description, Security: []map[string][]string{{"operatorSession": {}}}, Parameters: []*huma.Param{parameter}, Responses: responses()},
		Put: &huma.Operation{OperationID: "set-native-backup-schedule", Method: "PUT", Path: path, Summary: "Explicitly configure or pause a native backup schedule", Description: description + " Both current revisions and all four exact non-null input keys are required; enabling with the runner disabled returns 503.", Security: []map[string][]string{{"operatorSession": {}, "sessionCSRF": {}}}, Parameters: []*huma.Param{parameter, {Name: "Origin", In: "header", Required: true, Schema: &huma.Schema{Type: "string"}}, {Name: "X-CSRF-Token", In: "header", Required: true, Schema: &huma.Schema{Type: "string"}}}, RequestBody: &huma.RequestBody{Required: true, Content: map[string]*huma.MediaType{"application/json": {Schema: ref("NativeBackupScheduleInput")}}}, Responses: responses()},
	}
}
