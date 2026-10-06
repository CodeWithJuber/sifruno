package api

import (
	"encoding/json"
	"testing"
)

func TestBackupScheduleSpecUsesExactNativeContract(t *testing.T) {
	f := websiteFixture(t)
	w := websiteRequest(f.handler, "GET", "/openapi.json", nil, nil, "")
	if w.Code != 200 {
		t.Fatal("OpenAPI unavailable")
	}
	var spec struct {
		Paths      map[string]map[string]json.RawMessage `json:"paths"`
		Components struct {
			Schemas map[string]struct {
				Required             []string                  `json:"required"`
				AdditionalProperties *bool                     `json:"additionalProperties"`
				Properties           map[string]map[string]any `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if json.Unmarshal(w.Body.Bytes(), &spec) != nil {
		t.Fatal("spec JSON")
	}
	path := spec.Paths["/api/v1/sites/{id}/backup-schedule"]
	if path["get"] == nil || path["put"] == nil {
		t.Fatal("native routes absent from spec")
	}
	input := spec.Components.Schemas["NativeBackupScheduleInput"]
	exact := func(actual, wanted []string) bool {
		if len(actual) != len(wanted) {
			return false
		}
		seen := map[string]bool{}
		for _, name := range actual {
			if seen[name] {
				return false
			}
			seen[name] = true
		}
		for _, name := range wanted {
			if !seen[name] {
				return false
			}
		}
		return true
	}
	inputFields := []string{"expected_revision", "expected_schedule_revision", "interval", "enabled"}
	propertyKeys := []string{}
	for name := range input.Properties {
		propertyKeys = append(propertyKeys, name)
	}
	if input.AdditionalProperties == nil || *input.AdditionalProperties || !exact(input.Required, inputFields) || !exact(propertyKeys, inputFields) {
		t.Fatal("input is not exact")
	}
	for _, field := range []string{"expected_revision", "expected_schedule_revision"} {
		if input.Properties[field]["maximum"] != float64(9007199254740991) {
			t.Fatal("unsafe JSON revision advertised")
		}
	}
	for name, wanted := range map[string][]string{
		"NativeBackupSchedule":         {"site_id", "revision", "interval", "enabled", "created_at", "updated_at", "next_run_at", "last_run_at", "last_status", "last_backup_id", "last_error", "pending"},
		"NativeBackupScheduleEnvelope": {"schedule", "intervals", "max_archives", "runner_enabled"},
	} {
		schema := spec.Components.Schemas[name]
		keys := []string{}
		for name := range schema.Properties {
			keys = append(keys, name)
		}
		if schema.AdditionalProperties == nil || *schema.AdditionalProperties || !exact(schema.Required, wanted) || !exact(keys, wanted) {
			t.Fatal("response schema is not exact")
		}
	}
}
