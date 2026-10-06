package api

import (
	"encoding/json"
	"testing"
)

// The advertised client contract must admit the exact native wire DTO rather
// than silently hiding unknown fields or promising unsafe JSON integers.
func TestRestorePreviewSpecUsesBoundedExactNativeContract(t *testing.T) {
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
	for name, wanted := range map[string][]string{
		"NativeRestorePreviewInput":    {"backup_id", "expected_revision"},
		"NativeRestorePreview":         {"site_id", "current_revision", "backup_id", "backup_sha256", "backup_revision", "files", "counts"},
		"NativeRestorePreviewFile":     {"path", "kind", "before", "after"},
		"NativeRestorePreviewFileInfo": {"path", "bytes", "sha256"},
		"NativeRestorePreviewCounts":   {"added", "modified", "removed", "unchanged"},
	} {
		schema, present := spec.Components.Schemas[name]
		keys := []string{}
		for key := range schema.Properties {
			keys = append(keys, key)
		}
		if !present || schema.AdditionalProperties == nil || *schema.AdditionalProperties || !exact(schema.Required, wanted) || !exact(keys, wanted) {
			t.Fatalf("exact object contract absent: %s", name)
		}
	}
	for name, fields := range map[string][]string{
		"NativeRestorePreviewInput": {"expected_revision"},
		"NativeRestorePreview":      {"current_revision", "backup_revision"},
	} {
		for _, field := range fields {
			property := spec.Components.Schemas[name].Properties[field]
			if property["type"] != "integer" || property["minimum"] != float64(1) || property["maximum"] != float64(9007199254740991) {
				t.Fatal("unsafe revision advertised")
			}
		}
	}
	files := spec.Components.Schemas["NativeRestorePreview"].Properties["files"]
	if files["type"] != "array" || files["maxItems"] != float64(128) {
		t.Fatal("preview union is not bounded")
	}
	for _, field := range []string{"before", "after"} {
		property := spec.Components.Schemas["NativeRestorePreviewFile"].Properties[field]
		branches, ok := property["oneOf"].([]any)
		if !ok || len(branches) != 2 {
			t.Fatal("file side nullability absent")
		}
		foundNull, foundFile := false, false
		for _, branch := range branches {
			item, ok := branch.(map[string]any)
			if !ok {
				t.Fatal("invalid nullable schema")
			}
			foundNull = foundNull || item["type"] == "null"
			foundFile = foundFile || item["$ref"] == "#/components/schemas/NativeRestorePreviewFileInfo"
		}
		if !foundNull || !foundFile {
			t.Fatal("nullable native file side not represented")
		}
	}
	path := spec.Paths["/api/v1/sites/{id}/restore-preview"]
	if path["post"] == nil || path["get"] != nil {
		t.Fatal("read-only POST route not advertised")
	}
	var operation struct {
		Security   []map[string][]string      `json:"security"`
		Responses  map[string]json.RawMessage `json:"responses"`
		Parameters []struct {
			Name     string `json:"name"`
			In       string `json:"in"`
			Required bool   `json:"required"`
		} `json:"parameters"`
		RequestBody struct {
			Required bool `json:"required"`
		} `json:"requestBody"`
	}
	if json.Unmarshal(path["post"], &operation) != nil || !operation.RequestBody.Required {
		t.Fatal("preview input admission absent")
	}
	secured := false
	for _, requirement := range operation.Security {
		_, session := requirement["operatorSession"]
		_, csrf := requirement["sessionCSRF"]
		secured = secured || (session && csrf)
	}
	if !secured {
		t.Fatal("operator and CSRF requirements absent")
	}
	for _, expected := range []struct{ name, where string }{{"id", "path"}, {"Origin", "header"}, {"X-CSRF-Token", "header"}} {
		present := false
		for _, parameter := range operation.Parameters {
			present = present || (parameter.Name == expected.name && parameter.In == expected.where && parameter.Required)
		}
		if !present {
			t.Fatal("required admission parameter absent")
		}
	}
	for _, code := range []string{"200", "400", "401", "403", "404", "409", "413", "415", "422", "503"} {
		if operation.Responses[code] == nil {
			t.Fatalf("advertised outcome absent: %s", code)
		}
	}
}
