package api

import (
	"net/http"
	"reflect"
	"strconv"

	"github.com/danielgtaylor/huma/v2"
)

// documentOperator describes the native Manager handlers without registering
// another runtime handler or weakening their pre-parse authentication checks.
func documentOperator(a huma.API) {
	spec := a.OpenAPI()
	if spec.Components.SecuritySchemes == nil {
		spec.Components.SecuritySchemes = map[string]*huma.SecurityScheme{}
	}
	spec.Components.SecuritySchemes["operatorSession"] = &huma.SecurityScheme{Type: "apiKey", In: "cookie", Name: "sifruno_operator", Description: "Signed and encrypted local operator session, 15 minutes. HttpOnly and SameSite=Strict; Secure on TLS. Server restart and logout invalidate admission. This is loopback access, not qualified remote production authentication or roles."}
	spec.Components.SecuritySchemes["sessionCSRF"] = &huma.SecurityScheme{Type: "apiKey", In: "header", Name: "X-CSRF-Token", Description: "Independent CSRF token from the active session response. Required together with the session cookie and exact local Origin for each mutation; login rotates it."}
	schemas := spec.Components.Schemas.Map()
	length := 43
	token := func() *huma.Schema {
		return &huma.Schema{Type: "string", MinLength: &length, MaxLength: &length, Pattern: `^[A-Za-z0-9_-]{43}$`}
	}
	access := token()
	access.WriteOnly = true
	access.Format = "password"
	access.Description = "Private server-created access key, read locally from access.key. Never log, persist in browser storage, or return it in API responses."
	schemas["OperatorLogin"] = &huma.Schema{Type: "object", AdditionalProperties: false, Required: []string{"access_key"}, Properties: map[string]*huma.Schema{"access_key": access}}
	schemas["OperatorSession"] = &huma.Schema{Type: "object", AdditionalProperties: false, Required: []string{"authenticated", "csrf_token", "expires_at"}, Properties: map[string]*huma.Schema{
		"authenticated": {Type: "boolean", Enum: []any{true}}, "csrf_token": token(), "expires_at": {Type: "string", Format: "date-time"},
	}}
	schemas["OperatorSignedOut"] = &huma.Schema{Type: "object", AdditionalProperties: false, Required: []string{"authenticated"}, Properties: map[string]*huma.Schema{"authenticated": {Type: "boolean", Enum: []any{false}}}}
	schemas["OperatorLogout"] = &huma.Schema{Type: "object", AdditionalProperties: false, Properties: map[string]*huma.Schema{}}
	schemas["OperatorProblem"] = &huma.Schema{Type: "object", AdditionalProperties: false, Required: []string{"type", "title", "status", "detail", "error", "authenticated"}, Properties: map[string]*huma.Schema{
		"type": {Type: "string", Format: "uri"}, "title": {Type: "string"}, "status": {Type: "integer"}, "detail": {Type: "string"}, "error": {Type: "string", Pattern: `^[a-z_]+$`}, "authenticated": {Type: "boolean", Enum: []any{false}},
	}}
	ref := func(name string) *huma.Schema { return &huma.Schema{Ref: "#/components/schemas/" + name} }
	origin := func() *huma.Param {
		return &huma.Param{Name: "Origin", In: "header", Required: true, Description: "Must exactly equal the request's local scheme and Host (including port), and be allowed by the panel. Forwarded headers do not establish operator access.", Schema: &huma.Schema{Type: "string"}}
	}
	csrf := func() *huma.Param {
		return &huma.Param{Name: "X-CSRF-Token", In: "header", Required: true, Description: "Active session CSRF token; never include it in a URL or logs.", Schema: token()}
	}
	response := func(description string, schema *huma.Schema, contentType string) *huma.Response {
		return &huma.Response{Description: description, Content: map[string]*huma.MediaType{contentType: {Schema: schema}}}
	}
	problem := func(code int) *huma.Response {
		return response(http.StatusText(code)+"; fixed non-sensitive problem details", ref("OperatorProblem"), "application/problem+json")
	}
	responses := func(success string, codes ...int) map[string]*huma.Response {
		r := map[string]*huma.Response{"200": response("Confirmed local operator session result", ref(success), "application/json")}
		for _, code := range codes {
			r[httpCode(code)] = problem(code)
		}
		return r
	}
	readSecurity := []map[string][]string{{"operatorSession": {}}}
	writeSecurity := []map[string][]string{{"operatorSession": {}, "sessionCSRF": {}}}
	add := func(op *huma.Operation) {
		// Native responses bypass Huma serialization. Direct spec insertion
		// intentionally avoids runtime SchemaLinkTransformer callbacks.
		item := spec.Paths[op.Path]
		if item == nil {
			item = &huma.PathItem{}
			spec.Paths[op.Path] = item
		}
		if op.Method == http.MethodGet {
			item.Get = op
		} else {
			item.Post = op
		}
	}
	add(&huma.Operation{OperationID: "operator-login", Method: http.MethodPost, Path: "/api/v1/session/login", Summary: "Create a local operator session", Description: "Local loopback only. Strict JSON object bounded to 2048 bytes; 20-attempt burst refills one attempt per 3 seconds. At most 128 active sessions. The response sets an encrypted session cookie and returns its separate CSRF token. Invalid input never echoes the access key.", Security: []map[string][]string{}, Parameters: []*huma.Param{origin()}, RequestBody: &huma.RequestBody{Required: true, Content: map[string]*huma.MediaType{"application/json": {Schema: ref("OperatorLogin")}}}, Responses: responses("OperatorSession", 400, 401, 403, 413, 415, 429, 503)})
	add(&huma.Operation{OperationID: "operator-session", Method: http.MethodGet, Path: "/api/v1/session", Summary: "Inspect the active local operator session", Description: "An unauthenticated request returns HTTP 401 with authenticated=false and fixed problem details.", Security: readSecurity, Responses: responses("OperatorSession", 401, 403, 503)})
	add(&huma.Operation{OperationID: "operator-logout", Method: http.MethodPost, Path: "/api/v1/session/logout", Summary: "Invalidate the active session and expire its cookie", Description: "A revoked cookie cannot be replayed. Send an empty JSON object (an empty body with application/json is also accepted).", Security: writeSecurity, Parameters: []*huma.Param{origin(), csrf()}, RequestBody: &huma.RequestBody{Required: false, Content: map[string]*huma.MediaType{"application/json": {Schema: ref("OperatorLogout")}}}, Responses: responses("OperatorSignedOut", 400, 401, 403, 413, 415, 503)})
	storeProblem := spec.Components.Schemas.Schema(reflect.TypeOf(huma.ErrorModel{}), true, "ErrorModel")
	for path, item := range spec.Paths {
		if !isSitePath(path) && !isAccountPath(path) {
			continue
		}
		for _, op := range []*huma.Operation{item.Get, item.Post, item.Put} {
			if op == nil {
				continue
			}
			op.Description = "Authenticated app-owned static website operation. Loopback only; OS accounts, DNS, TLS, PHP, mail, databases and full host backups are outside this slice."
			if isAccountPath(path) {
				op.Description = "Authenticated native Linux identity/home operation through a separate root broker. Domain is reserved metadata only. No web, DNS, mail or full cPanel provisioning. Suspension sets account expiry for new PAM-aware access; existing processes are unaffected. A timed-out create must be reconciled by refreshing the list before retrying."
			}
			op.Security = readSecurity
			if op.Method != http.MethodGet {
				op.Security = writeSecurity
				op.Parameters = append(op.Parameters, origin(), csrf())
			}
			if op.Responses == nil {
				op.Responses = map[string]*huma.Response{}
			}
			for _, code := range []int{401, 403, 503} {
				op.Responses[httpCode(code)] = response(http.StatusText(code)+"; non-sensitive authentication or storage error", &huma.Schema{AnyOf: []*huma.Schema{ref("OperatorProblem"), storeProblem}}, "application/problem+json")
			}
			if op.Method != http.MethodGet {
				for _, code := range []int{400, 413, 415} {
					op.Responses[httpCode(code)] = problem(code)
				}
			}
		}
	}
}

func httpCode(code int) string {
	return strconv.Itoa(code)
}
