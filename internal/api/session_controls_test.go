package api

import (
	"encoding/json"
	"testing"
)

func TestSessionManagementOpenAPIContract(t *testing.T) {
	f := websiteFixture(t)
	w := websiteRequest(f.handler, "GET", "/openapi.json", nil, nil, "")
	if w.Code != 200 {
		t.Fatal("OpenAPI unavailable")
	}
	var spec struct {
		Paths map[string]map[string]struct {
			Security   []map[string][]string
			Parameters []struct {
				Name, In string
				Required bool
				Schema   map[string]any
			}
			RequestBody struct {
				Required bool
				Content  map[string]struct{ Schema map[string]any }
			}
			Responses map[string]struct {
				Content map[string]struct{ Schema map[string]any }
			}
		}
		Components struct {
			Schemas map[string]struct {
				AdditionalProperties bool
				Required             []string
				Properties           map[string]map[string]any
			}
		}
	}
	if json.Unmarshal(w.Body.Bytes(), &spec) != nil {
		t.Fatal("OpenAPI malformed")
	}
	for _, route := range []struct {
		path, method, result string
		mutation             bool
	}{
		{"/api/v1/session/sessions", "get", "OperatorSessionInventory", false},
		{"/api/v1/session/sessions/{id}/revoke", "post", "OperatorSessionRevocation", true},
		{"/api/v1/session/revoke-others", "post", "OperatorSessionRevocation", true},
	} {
		t.Run(route.path, func(t *testing.T) {
			op, ok := spec.Paths[route.path][route.method]
			if !ok || len(op.Security) != 1 {
				t.Fatal("management route or auth missing")
			}
			if _, ok := op.Security[0]["operatorSession"]; !ok {
				t.Fatal("cookie auth missing")
			}
			if op.Responses["200"].Content["application/json"].Schema["$ref"] != "#/components/schemas/"+route.result {
				t.Fatal("management response schema missing")
			}
			if route.mutation {
				if _, ok := op.Security[0]["sessionCSRF"]; !ok {
					t.Fatal("CSRF must combine with cookie")
				}
				if !op.RequestBody.Required || op.RequestBody.Content["application/json"].Schema["$ref"] != "#/components/schemas/OperatorLogout" {
					t.Fatal("strict empty body missing")
				}
				headers := map[string]bool{}
				for _, p := range op.Parameters {
					if p.In == "header" && p.Required {
						headers[p.Name] = true
					}
				}
				if !headers["Origin"] || !headers["X-CSRF-Token"] {
					t.Fatal("mutation admission headers missing")
				}
			}
		})
	}
	item := spec.Components.Schemas["OperatorManagedSession"]
	if item.AdditionalProperties || len(item.Required) != 4 || len(item.Properties) != 4 {
		t.Fatal("session metadata fields not exact")
	}
	id := item.Properties["id"]
	if id["pattern"] != "^[0-9a-f]{32}$" || id["minLength"] != float64(32) || id["maxLength"] != float64(32) {
		t.Fatal("management handle schema mismatch")
	}
	inventory := spec.Components.Schemas["OperatorSessionInventory"]
	items := inventory.Properties["items"]
	if inventory.AdditionalProperties || len(inventory.Required) != 3 || len(inventory.Properties) != 3 || items["minItems"] != float64(1) || items["maxItems"] != float64(128) {
		t.Fatal("inventory bounds not discoverable")
	}
	count := spec.Components.Schemas["OperatorSessionRevocation"].Properties["revoked_count"]
	if count["minimum"] != float64(0) || count["maximum"] != float64(127) {
		t.Fatal("revocation bounds not discoverable")
	}
	// Documentation must not install a second router that transforms Manager JSON.
	c, _ := websiteSignIn(t, f)
	result := websiteRequest(f.handler, "GET", "/api/v1/session/sessions", nil, c, "")
	var actual map[string]json.RawMessage
	if result.Code != 200 || json.Unmarshal(result.Body.Bytes(), &actual) != nil || len(actual) != 3 || actual["items"] == nil || actual["$schema"] != nil {
		t.Fatal("documentation changed native response")
	}
}
