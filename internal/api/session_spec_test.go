package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestOpenAPIDiscoversNativeSessionAndWebsiteAdmission(t *testing.T) {
	f := websiteFixture(t)
	w := websiteRequest(f.handler, "GET", "/openapi.json", nil, nil, "")
	if w.Code != 200 || strings.Contains(w.Body.String(), f.key) {
		t.Fatal("OpenAPI missing or exposing fixture credential")
	}
	var spec struct {
		Paths map[string]map[string]struct {
			Security   []map[string][]string `json:"security"`
			Parameters []struct {
				Name, In string
				Required bool
				Schema   map[string]any
			} `json:"parameters"`
			RequestBody struct {
				Required bool
				Content  map[string]struct{ Schema map[string]any }
			} `json:"requestBody"`
			Responses map[string]struct {
				Content map[string]struct{ Schema map[string]any }
			}
		}
		Components struct {
			SecuritySchemes map[string]struct{ Type, In, Name string }
			Schemas         map[string]struct {
				Required   []string
				Properties map[string]map[string]any
			}
		}
	}
	if json.Unmarshal(w.Body.Bytes(), &spec) != nil {
		t.Fatal("invalid OpenAPI JSON")
	}
	if s := spec.Components.SecuritySchemes["operatorSession"]; s.Type != "apiKey" || s.In != "cookie" || s.Name != "sifruno_operator" {
		t.Fatal("cookie auth is not discoverable")
	}
	if s := spec.Components.SecuritySchemes["sessionCSRF"]; s.Type != "apiKey" || s.In != "header" || s.Name != "X-CSRF-Token" {
		t.Fatal("CSRF is not discoverable")
	}
	for _, route := range []struct {
		path, method, success string
		mutation              bool
	}{
		{"/api/v1/session/login", "post", "OperatorSession", true}, {"/api/v1/session", "get", "OperatorSession", false}, {"/api/v1/session/logout", "post", "OperatorSignedOut", true},
		{"/api/v1/session/setup/totp", "post", "OperatorSetupSecret", true}, {"/api/v1/session/setup/admin", "post", "OperatorSession", true},
	} {
		op, ok := spec.Paths[route.path][route.method]
		if !ok {
			t.Fatal("native session route missing from OpenAPI")
		}
		if op.Responses["200"].Content["application/json"].Schema["$ref"] != "#/components/schemas/"+route.success {
			t.Fatal("session result DTO not discoverable")
		}
		if route.mutation {
			found := false
			for _, p := range op.Parameters {
				if p.Name == "Origin" && p.In == "header" && p.Required {
					found = true
				}
			}
			if !found {
				t.Fatal("session mutation Origin requirement absent")
			}
		}
		if route.path != "/api/v1/session/login" {
			if len(op.Security) != 1 {
				t.Fatal("session security absent")
			}
			if _, ok := op.Security[0]["operatorSession"]; !ok {
				t.Fatal("session cookie requirement absent")
			}
		}
	}
	login := spec.Paths["/api/v1/session/login"]["post"]
	if !login.RequestBody.Required || login.RequestBody.Content["application/json"].Schema["$ref"] != "#/components/schemas/OperatorLogin" {
		t.Fatal("typed login body missing")
	}
	for _, field := range []string{"password", "totp_code"} {
		if f := spec.Components.Schemas["OperatorLogin"].Properties[field]; f["writeOnly"] != true {
			t.Fatalf("login %s must be write-only", field)
		}
	}
	if status, ok := spec.Paths["/api/v1/session/setup"]["get"]; !ok || status.Responses["200"].Content["application/json"].Schema["$ref"] != "#/components/schemas/OperatorSetupStatus" {
		t.Fatal("setup status route missing from OpenAPI")
	}
	key := spec.Components.Schemas["OperatorLogin"].Properties["access_key"]
	if key["writeOnly"] != true || key["format"] != "password" || key["maxLength"] != float64(43) || key["minLength"] != float64(43) || key["examples"] != nil || key["default"] != nil {
		t.Fatal("access key schema unsafe or inaccurate")
	}
	for path, item := range spec.Paths {
		if !isSitePath(path) {
			continue
		}
		for method, op := range item {
			if method != "get" && method != "post" && method != "put" {
				continue
			}
			if len(op.Security) != 1 {
				t.Fatal("site security alternatives missing")
			}
			if _, ok := op.Security[0]["operatorSession"]; !ok {
				t.Fatal("site cookie security missing")
			}
			if method != "get" {
				if _, ok := op.Security[0]["sessionCSRF"]; !ok {
					t.Fatal("CSRF security must combine with cookie, not be an alternative")
				}
				names := map[string]bool{}
				for _, p := range op.Parameters {
					if p.Required && p.In == "header" {
						names[p.Name] = true
					}
				}
				if !names["Origin"] || !names["X-CSRF-Token"] {
					t.Fatal("typed site mutation headers missing")
				}
			}
		}
	}
	// Spec-only operations must leave the native Manager response and error
	// behavior intact. No duplicate runtime routing is installed.
	c, _ := websiteSignIn(t, f)
	if w := websiteRequest(f.handler, "GET", "/api/v1/session", nil, c, ""); w.Code != 200 {
		t.Fatal("spec documentation altered native session route")
	}
}
