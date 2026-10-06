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
				AdditionalProperties bool                      `json:"additionalProperties"`
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
	if input.AdditionalProperties || len(input.Required) != 4 {
		t.Fatal("input is not exact")
	}
	for _, field := range []string{"expected_revision", "expected_schedule_revision"} {
		if input.Properties[field]["maximum"] != float64(9007199254740991) {
			t.Fatal("unsafe JSON revision advertised")
		}
	}
	if len(spec.Components.Schemas["NativeBackupSchedule"].Required) != 12 || len(spec.Components.Schemas["NativeBackupScheduleEnvelope"].Required) != 4 {
		t.Fatal("response fields not required")
	}
}
