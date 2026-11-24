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
	spec.Components.SecuritySchemes["apiToken"] = &huma.SecurityScheme{Type: "http", Scheme: "bearer", Description: "Admin API token (sfr_ and 43 base64url characters), created under /api/v1/session/tokens. Sent as Authorization: Bearer <token> on loopback or the HTTPS listener. It gives an admin session's access to every API route except /api/v1/session/*, which refuse it (403 token_not_allowed). No cookie, Origin or CSRF header; a request with both a token and the session cookie is refused (400). A wrong, expired or revoked token returns 401 invalid_token; failed attempts are rate limited like sign-ins (429 with Retry-After)."}
	schemas := spec.Components.Schemas.Map()
	length := 43
	token := func() *huma.Schema {
		return &huma.Schema{Type: "string", MinLength: &length, MaxLength: &length, Pattern: `^[A-Za-z0-9_-]{43}$`}
	}
	access := token()
	access.WriteOnly = true
	access.Format = "password"
	access.Description = "Private server-created access key, read locally from access.key. Never log, persist in browser storage, or return it in API responses."
	usernameMin, usernameMax, passwordMin, passwordMax, codeLen, secretLen := 3, 32, 12, 256, 6, 32
	username := func() *huma.Schema {
		return &huma.Schema{Type: "string", MinLength: &usernameMin, MaxLength: &usernameMax, Pattern: `^[a-z][a-z0-9._-]{2,31}$`, Description: "Admin username."}
	}
	password := &huma.Schema{Type: "string", MinLength: &passwordMin, MaxLength: &passwordMax, WriteOnly: true, Format: "password", Description: "At least 12 characters, at most 256 bytes. Stored only as an Argon2id hash."}
	code := &huma.Schema{Type: "string", MinLength: &codeLen, MaxLength: &codeLen, Pattern: `^[0-9]{6}$`, WriteOnly: true, Description: "Current 6-digit code from the admin's authenticator app (RFC 6238, 30-second steps). Each code works once."}
	schemas["OperatorLogin"] = &huma.Schema{Type: "object", AdditionalProperties: false,
		Description: "Either the local access key alone, or an admin's username, password and code together.",
		Properties:  map[string]*huma.Schema{"access_key": access, "username": username(), "password": password, "totp_code": code},
		OneOf:       []*huma.Schema{{Required: []string{"access_key"}}, {Required: []string{"username", "password", "totp_code"}}}}
	sessionUser := username()
	sessionUser.Description = "Present for an admin's password-and-code session; absent for an access-key session."
	schemas["OperatorSession"] = &huma.Schema{Type: "object", AdditionalProperties: false, Required: []string{"authenticated", "csrf_token", "expires_at"}, Properties: map[string]*huma.Schema{
		"authenticated": {Type: "boolean", Enum: []any{true}}, "csrf_token": token(), "expires_at": {Type: "string", Format: "date-time"}, "username": sessionUser,
	}}
	schemas["OperatorSetupStatus"] = &huma.Schema{Type: "object", AdditionalProperties: false, Required: []string{"admin_required"}, Properties: map[string]*huma.Schema{
		"admin_required": {Type: "boolean", Description: "True until the first admin account exists."},
	}}
	schemas["OperatorSetupBegin"] = &huma.Schema{Type: "object", AdditionalProperties: false, Required: []string{"username"}, Properties: map[string]*huma.Schema{"username": username()}}
	schemas["OperatorSetupSecret"] = &huma.Schema{Type: "object", AdditionalProperties: false, Required: []string{"secret", "otpauth_uri", "expires_at"}, Properties: map[string]*huma.Schema{
		"secret":      {Type: "string", MinLength: &secretLen, MaxLength: &secretLen, Pattern: `^[A-Z2-7]{32}$`, ReadOnly: true, Description: "Base32 authenticator secret, shown once to this session. Never log it."},
		"otpauth_uri": {Type: "string", Format: "uri", ReadOnly: true, Description: "otpauth://totp link for authenticator apps; contains the secret."},
		"expires_at":  {Type: "string", Format: "date-time", Description: "The setup must be finished within 10 minutes."},
	}}
	schemas["OperatorSetupAdmin"] = &huma.Schema{Type: "object", AdditionalProperties: false, Required: []string{"username", "password", "totp_code"}, Properties: map[string]*huma.Schema{
		"username": username(), "password": password, "totp_code": code,
	}}
	schemas["OperatorSignedOut"] = &huma.Schema{Type: "object", AdditionalProperties: false, Required: []string{"authenticated"}, Properties: map[string]*huma.Schema{"authenticated": {Type: "boolean", Enum: []any{false}}}}
	schemas["OperatorLogout"] = &huma.Schema{Type: "object", AdditionalProperties: false, Properties: map[string]*huma.Schema{}}
	idLength, inventoryMin, inventoryMax := 32, 1, 128
	countMin, countMax := float64(0), float64(127)
	managementID := &huma.Schema{Type: "string", MinLength: &idLength, MaxLength: &idLength, Pattern: `^[0-9a-f]{32}$`, Description: "Public session-management handle. This is not a cookie ID, access key or CSRF credential."}
	schemas["OperatorManagedSession"] = &huma.Schema{Type: "object", AdditionalProperties: false, Required: []string{"id", "created_at", "expires_at", "current"}, Properties: map[string]*huma.Schema{
		"id": managementID, "created_at": {Type: "string", Format: "date-time"}, "expires_at": {Type: "string", Format: "date-time"}, "current": {Type: "boolean"},
	}}
	schemas["OperatorSessionInventory"] = &huma.Schema{Type: "object", AdditionalProperties: false, Required: []string{"items", "capacity", "lifetime_seconds"}, Properties: map[string]*huma.Schema{
		"items":    {Type: "array", MinItems: &inventoryMin, MaxItems: &inventoryMax, Items: &huma.Schema{Ref: "#/components/schemas/OperatorManagedSession"}, Description: "Unexpired in-process sessions, newest creation first, public handle ascending on ties. Exactly one is current."},
		"capacity": {Type: "integer", Enum: []any{128}}, "lifetime_seconds": {Type: "integer", Enum: []any{900}},
	}}
	schemas["OperatorSessionRevocation"] = &huma.Schema{Type: "object", AdditionalProperties: false, Required: []string{"revoked_count"}, Properties: map[string]*huma.Schema{
		"revoked_count": {Type: "integer", Minimum: &countMin, Maximum: &countMax},
	}}
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
	add(&huma.Operation{OperationID: "operator-login", Method: http.MethodPost, Path: "/api/v1/session/login", Summary: "Create a local operator session", Description: "On loopback, send either the access key or an admin's username, password and 6-digit code; on the HTTPS listener (--https-listen) only the admin credentials are accepted (403 local_access_required for the key). Over that listener every other API route also needs an admin session; wrong admin credentials all return 401 invalid_credentials. Strict JSON object bounded to 2048 bytes; 20-attempt burst refills one attempt per 3 seconds, and each admin account also allows 5 attempts refilling one per minute (429 with Retry-After). At most 128 active sessions. The response sets an encrypted session cookie and returns its separate CSRF token. Invalid input never echoes the access key.", Security: []map[string][]string{}, Parameters: []*huma.Param{origin()}, RequestBody: &huma.RequestBody{Required: true, Content: map[string]*huma.MediaType{"application/json": {Schema: ref("OperatorLogin")}}}, Responses: responses("OperatorSession", 400, 401, 403, 413, 415, 429, 503)})
	add(&huma.Operation{OperationID: "operator-session", Method: http.MethodGet, Path: "/api/v1/session", Summary: "Inspect the active local operator session", Description: "An unauthenticated request returns HTTP 401 with authenticated=false and fixed problem details.", Security: readSecurity, Responses: responses("OperatorSession", 401, 403, 503)})
	add(&huma.Operation{OperationID: "operator-logout", Method: http.MethodPost, Path: "/api/v1/session/logout", Summary: "Invalidate the active session and expire its cookie", Description: "A revoked cookie cannot be replayed. Send an empty JSON object (an empty body with application/json is also accepted).", Security: writeSecurity, Parameters: []*huma.Param{origin(), csrf()}, RequestBody: &huma.RequestBody{Required: false, Content: map[string]*huma.MediaType{"application/json": {Schema: ref("OperatorLogout")}}}, Responses: responses("OperatorSignedOut", 400, 401, 403, 413, 415, 503)})
	add(&huma.Operation{OperationID: "operator-session-inventory", Method: http.MethodGet, Path: "/api/v1/session/sessions", Summary: "List active local operator sessions", Description: "Authenticated loopback-only inventory, revalidated under the session lock. Bounded to 128 entries, with exactly one current session. Public management handles and timestamps only; raw cookie IDs, CSRF values, access keys, IPs and device fingerprints are excluded. Restart clears all session admission.", Security: readSecurity, Responses: responses("OperatorSessionInventory", 401, 403, 503)})
	add(&huma.Operation{OperationID: "operator-setup-status", Method: http.MethodGet, Path: "/api/v1/session/setup", Summary: "Whether first-run admin setup is needed", Description: "Loopback only, no session needed. Reveals only whether an admin account exists.", Security: []map[string][]string{}, Responses: responses("OperatorSetupStatus", 403)})
	setupBody := func(name string) *huma.RequestBody {
		return &huma.RequestBody{Required: true, Content: map[string]*huma.MediaType{"application/json": {Schema: ref(name)}}}
	}
	add(&huma.Operation{OperationID: "operator-setup-totp", Method: http.MethodPost, Path: "/api/v1/session/setup/totp", Summary: "Start first-run admin setup: issue an authenticator secret", Description: "Needs an access-key session and no existing admin (409 setup_complete otherwise). The secret is kept for this session for 10 minutes; asking again replaces it.", Security: writeSecurity, Parameters: []*huma.Param{origin(), csrf()}, RequestBody: setupBody("OperatorSetupBegin"), Responses: responses("OperatorSetupSecret", 400, 401, 403, 409, 413, 415, 422, 503)})
	add(&huma.Operation{OperationID: "operator-setup-admin", Method: http.MethodPost, Path: "/api/v1/session/setup/admin", Summary: "Finish first-run setup: create the first admin", Description: "Needs the same session that received the secret, the same username, a valid password and the current code (422 invalid_password or invalid_code; 409 setup_expired). On success the current session becomes the admin's.", Security: writeSecurity, Parameters: []*huma.Param{origin(), csrf()}, RequestBody: setupBody("OperatorSetupAdmin"), Responses: responses("OperatorSession", 400, 401, 403, 409, 413, 415, 422, 503)})
	emptyBody := &huma.RequestBody{Required: true, Content: map[string]*huma.MediaType{"application/json": {Schema: ref("OperatorLogout")}}}
	add(&huma.Operation{OperationID: "operator-revoke-session", Method: http.MethodPost, Path: "/api/v1/session/sessions/{id}/revoke", Summary: "Revoke another local operator session", Description: "Send exactly an empty JSON object, bounded to 2048 bytes. Authorizing session is rechecked under the same lock as deletion. A revoked cookie cannot be replayed. The current session returns 409: use ordinary logout instead. Unknown handles return 404. This is single-operator local control, not tenant roles or remote production authentication.", Security: writeSecurity, Parameters: []*huma.Param{{Name: "id", In: "path", Required: true, Schema: managementID}, origin(), csrf()}, RequestBody: emptyBody, Responses: responses("OperatorSessionRevocation", 400, 401, 403, 404, 409, 413, 415, 503)})
	tokenID := &huma.Schema{Type: "string", MinLength: &idLength, MaxLength: &idLength, Pattern: `^[0-9a-f]{32}$`, Description: "Public token handle for revocation. Not the token."}
	nameMin, nameMax, daysMin, daysMax, tokenMax, prefixLen, apiTokenLen := 1, 64, float64(1), float64(365), 32, 10, 47
	schemas["OperatorAPIToken"] = &huma.Schema{Type: "object", AdditionalProperties: false, Required: []string{"id", "name", "prefix", "created_at", "expires_at", "last_used_at", "expired"}, Properties: map[string]*huma.Schema{
		"id": tokenID, "name": {Type: "string", MinLength: &nameMin, MaxLength: &nameMax}, "prefix": {Type: "string", MinLength: &prefixLen, MaxLength: &prefixLen, Pattern: `^sfr_[A-Za-z0-9_-]{6}$`, Description: "The token's first 10 characters, to tell tokens apart. Not enough to use it."},
		"created_at": {Type: "string", Format: "date-time"}, "expires_at": {Type: "string", Format: "date-time"},
		"last_used_at": {Type: "string", Format: "date-time", Nullable: true, Description: "Null until first use; saved at most once a minute."}, "expired": {Type: "boolean"},
	}}
	schemas["OperatorAPITokenList"] = &huma.Schema{Type: "object", AdditionalProperties: false, Required: []string{"items", "capacity"}, Properties: map[string]*huma.Schema{
		"items": {Type: "array", MaxItems: &tokenMax, Items: ref("OperatorAPIToken"), Description: "Newest first. Expired tokens stay listed until revoked."}, "capacity": {Type: "integer", Enum: []any{32}},
	}}
	schemas["OperatorAPITokenCreate"] = &huma.Schema{Type: "object", AdditionalProperties: false, Required: []string{"name"}, Properties: map[string]*huma.Schema{
		"name":            {Type: "string", MinLength: &nameMin, MaxLength: &nameMax, Description: "Where the token is used, such as WHMCS. Unique regardless of case; no control or formatting characters, no outer spaces."},
		"expires_in_days": {Type: "integer", Minimum: &daysMin, Maximum: &daysMax, Default: 90},
	}}
	created := &huma.Schema{Type: "object", AdditionalProperties: false, Required: []string{"id", "name", "prefix", "created_at", "expires_at", "last_used_at", "expired", "token"}, Properties: map[string]*huma.Schema{}}
	for k, v := range schemas["OperatorAPIToken"].Properties {
		created.Properties[k] = v
	}
	created.Properties["token"] = &huma.Schema{Type: "string", MinLength: &apiTokenLen, MaxLength: &apiTokenLen, Pattern: `^sfr_[A-Za-z0-9_-]{43}$`, ReadOnly: true, Format: "password", Description: "The token itself, returned only in this response. The server keeps only a keyed hash. Never log it."}
	schemas["OperatorAPITokenCreated"] = created
	add(&huma.Operation{OperationID: "operator-api-tokens", Method: http.MethodGet, Path: "/api/v1/session/tokens", Summary: "List admin API tokens", Description: "Needs a session; an API token cannot list tokens (403 token_not_allowed). Never returns a token or its hash.", Security: readSecurity, Responses: responses("OperatorAPITokenList", 401, 403, 503)})
	add(&huma.Operation{OperationID: "operator-create-api-token", Method: http.MethodPost, Path: "/api/v1/session/tokens", Summary: "Create an admin API token", Description: "Needs a session with Origin and CSRF; an API token cannot create tokens. The token is in this response only. Expiry is required: 90 days unless expires_in_days (1 to 365) is sent. 422 invalid_token_name or invalid_expiry; 409 token_name_taken or token_limit (32).", Security: writeSecurity, Parameters: []*huma.Param{origin(), csrf()}, RequestBody: setupBody("OperatorAPITokenCreate"), Responses: responses("OperatorAPITokenCreated", 400, 401, 403, 409, 413, 415, 422, 503)})
	add(&huma.Operation{OperationID: "operator-revoke-api-token", Method: http.MethodPost, Path: "/api/v1/session/tokens/{id}/revoke", Summary: "Revoke an admin API token", Description: "Send exactly an empty JSON object. The token stops working at once and is removed from the list; the answer describes it. Unknown handles return 404.", Security: writeSecurity, Parameters: []*huma.Param{{Name: "id", In: "path", Required: true, Schema: tokenID}, origin(), csrf()}, RequestBody: emptyBody, Responses: responses("OperatorAPIToken", 400, 401, 403, 404, 413, 415, 503)})
	add(&huma.Operation{OperationID: "operator-revoke-other-sessions", Method: http.MethodPost, Path: "/api/v1/session/revoke-others", Summary: "Revoke all other local operator sessions", Description: "Send exactly an empty JSON object, bounded to 2048 bytes. The authorizing session is rechecked and retained under the same lock as deletion. A zero count is valid when no other session remains. All cookies for removed sessions immediately lose admission; restart also clears admission.", Security: writeSecurity, Parameters: []*huma.Param{origin(), csrf()}, RequestBody: emptyBody, Responses: responses("OperatorSessionRevocation", 400, 401, 403, 413, 415, 503)})
	storeProblem := spec.Components.Schemas.Schema(reflect.TypeOf(huma.ErrorModel{}), true, "ErrorModel")
	for path, item := range spec.Paths {
		if !isSitePath(path) && !isAccountPath(path) && !isWizardPath(path) {
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
			if isWizardPath(path) {
				op.Description = "Authenticated WordPress website job. The POST checks the request (exactly the six keys, each once, at most 4 KiB; 422 names the field), starts a background job and answers 202; the job creates the hosting account, puts its site live, creates the database and installs WordPress through the root broker and the database service, and on a failure removes what it created, newest first. Poll the job by ID. Job records hold no passwords. Sites are plain HTTP for now; certificates are a later slice."
			}
			if isSiteDatabasePath(path) {
				op.Description = "Authenticated database management for one website. The owner is the account service's username for the account in the address, never a name from the request; names are <username>_<suffix>, and a name that belongs to another website answers 404 like one that does not exist. Each POST takes exactly its own keys, each once, each text, at most 4 KiB. Passwords go to the database server only: they are never stored, logged or returned, and error text is scrubbed of them. Deleting a database leaves its users in place."
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
