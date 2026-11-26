package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
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
	if item.AdditionalProperties || len(item.Required) != 5 || len(item.Properties) != 5 || item.Properties["kept_signed_in"]["type"] != "boolean" {
		t.Fatal("session metadata fields not exact")
	}
	id := item.Properties["id"]
	if id["pattern"] != "^[0-9a-f]{32}$" || id["minLength"] != float64(32) || id["maxLength"] != float64(32) {
		t.Fatal("management handle schema mismatch")
	}
	inventory := spec.Components.Schemas["OperatorSessionInventory"]
	items := inventory.Properties["items"]
	if inventory.AdditionalProperties || len(inventory.Required) != 4 || len(inventory.Properties) != 4 || inventory.Properties["idle_seconds"] == nil || inventory.Properties["kept_idle_seconds"] == nil || items["minItems"] != float64(1) || items["maxItems"] != float64(128) {
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
	if result.Code != 200 || json.Unmarshal(result.Body.Bytes(), &actual) != nil || len(actual) != 4 || actual["items"] == nil || actual["idle_seconds"] == nil || actual["kept_idle_seconds"] == nil || actual["$schema"] != nil {
		t.Fatal("documentation changed native response")
	}
}

// The passkey routes reach the operator through the API's guards: none is
// refused as an unknown change, tokens never reach them, and on loopback
// passkeys are off with an answer that says what to do.
func TestPasskeyRoutesReachTheOperator(t *testing.T) {
	f := websiteFixture(t)
	w := websiteRequest(f.handler, "GET", "/api/v1/session/passkey-login", nil, nil, "")
	var status struct {
		Available bool   `json:"available"`
		Detail    string `json:"detail"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &status) != nil || status.Available || status.Detail == "" {
		t.Fatalf("status on loopback: %d %s", w.Code, w.Body.String())
	}
	for _, route := range []struct {
		method, path string
		code         int
	}{
		{"POST", "/api/v1/session/passkey-login/begin", 409},
		{"POST", "/api/v1/session/passkey-login/finish", 409},
		{"GET", "/api/v1/session/passkeys", 401},
		{"POST", "/api/v1/session/passkeys/begin", 401},
		{"POST", "/api/v1/session/passkeys/finish", 401},
		{"POST", "/api/v1/session/passkeys/0123456789abcdef0123456789abcdef/remove", 401},
	} {
		body := `{"ceremony":"` + strings.Repeat("A", 43) + `","credential":{}}`
		if w := websiteRequest(f.handler, route.method, route.path, body, nil, ""); w.Code != route.code {
			t.Fatalf("%s %s: %d %s", route.method, route.path, w.Code, w.Body.String())
		}
		r := httptest.NewRequest(route.method, "http://127.0.0.1:8080"+route.path, strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:14000"
		r.Header.Set("Authorization", "Bearer sfr_"+strings.Repeat("A", 43))
		r.Header.Set("Content-Type", "application/json")
		tw := httptest.NewRecorder()
		f.handler.ServeHTTP(tw, r)
		if tw.Code != 403 || !strings.Contains(tw.Body.String(), "token_not_allowed") {
			t.Fatalf("token on %s: %d", route.path, tw.Code)
		}
	}
	if w := websiteRequest(f.handler, "POST", "/api/v1/session/passkeys/x/revoke", "{}", nil, ""); w.Code != 405 {
		t.Fatalf("an action the passkey routes do not have: %d", w.Code)
	}
}
