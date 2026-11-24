package hostaccounts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

func handler(s *store) http.Handler { return handlerWithWebPreview(s, nil) }

func handlerWithWebPreview(s *store, preview WebPreviewService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if r.Host != "unix" || r.URL.RawQuery != "" || r.Header.Get("Origin") != "" {
			writeError(w, ErrInvalid)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/web-preview":
			if r.URL.ForceQuery || r.URL.RawPath != "" {
				writeError(w, ErrInvalid)
				return
			}
			if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
				writeError(w, ErrInvalid)
				return
			}
			if r.Body != nil {
				var one [1]byte
				n, err := r.Body.Read(one[:])
				if n != 0 || err != io.EOF {
					writeError(w, ErrInvalid)
					return
				}
			}
			if preview == nil {
				writeError(w, ErrUnavailable)
				return
			}
			result, err := preview.Preview(ctx)
			if err != nil {
				writeError(w, err)
				return
			}
			if ctx.Err() != nil || !validWebPreview(result) {
				writeError(w, ErrUnavailable)
				return
			}
			json.NewEncoder(w).Encode(result)
		case r.Method == "GET" && r.URL.Path == "/v1/capability":
			if r.ContentLength != 0 {
				writeError(w, ErrInvalid)
				return
			}
			cap, err := s.capability(ctx)
			if err != nil {
				writeError(w, err)
				return
			}
			json.NewEncoder(w).Encode(cap)
		case r.Method == "GET" && r.URL.Path == "/v1/accounts":
			if r.ContentLength != 0 {
				writeError(w, ErrInvalid)
				return
			}
			items, err := s.list(ctx)
			if err != nil {
				writeError(w, err)
				return
			}
			json.NewEncoder(w).Encode(struct {
				Items []Account `json:"items"`
			}{items})
		case r.Method == "POST" && r.URL.Path == "/v1/accounts":
			var in struct {
				Input CreateInput `json:"input"`
				Actor string      `json:"actor"`
			}
			if decodeBody(w, r, &in, []string{"username", "domain", "plan", "reason"}) != nil {
				writeError(w, ErrInvalid)
				return
			}
			item, err := s.create(ctx, in.Input, in.Actor)
			if err != nil {
				writeError(w, err)
				return
			}
			json.NewEncoder(w).Encode(item)
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/accounts/") && strings.HasSuffix(r.URL.Path, "/state"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/accounts/"), "/state")
			if !idPattern.MatchString(id) {
				writeError(w, ErrInvalid)
				return
			}
			var in struct {
				Input StateInput `json:"input"`
				Actor string     `json:"actor"`
			}
			if decodeBody(w, r, &in, []string{"state", "expected_revision", "reason"}) != nil {
				writeError(w, ErrInvalid)
				return
			}
			// For an account with a live site the change runs the web apply,
			// on its own limit.
			if e := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(webApplyTimeout + time.Minute)); e != nil && !errors.Is(e, http.ErrNotSupported) {
				writeError(w, ErrUnavailable)
				return
			}
			item, err := s.setState(ctx, id, in.Input, in.Actor)
			if err != nil {
				writeError(w, err)
				return
			}
			json.NewEncoder(w).Encode(item)
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/accounts/") && strings.HasSuffix(r.URL.Path, "/plan"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/accounts/"), "/plan")
			if !idPattern.MatchString(id) {
				writeError(w, ErrInvalid)
				return
			}
			var in struct {
				Input PlanInput `json:"input"`
				Actor string    `json:"actor"`
			}
			if decodeBody(w, r, &in, []string{"plan", "expected_revision", "reason"}) != nil {
				writeError(w, ErrInvalid)
				return
			}
			item, err := s.setPlan(ctx, id, in.Input, in.Actor)
			if err != nil {
				writeError(w, err)
				return
			}
			json.NewEncoder(w).Encode(item)
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/accounts/") && strings.HasSuffix(r.URL.Path, "/ssh-keys"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/accounts/"), "/ssh-keys")
			if !idPattern.MatchString(id) || r.ContentLength != 0 {
				writeError(w, ErrInvalid)
				return
			}
			result, err := s.sshKeys(ctx, id)
			if err != nil {
				writeError(w, err)
				return
			}
			json.NewEncoder(w).Encode(result)
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/accounts/") && strings.HasSuffix(r.URL.Path, "/ssh-keys"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/accounts/"), "/ssh-keys")
			if !idPattern.MatchString(id) {
				writeError(w, ErrInvalid)
				return
			}
			var in struct {
				Input SSHKeysInput `json:"input"`
				Actor string       `json:"actor"`
			}
			if decodeBody(w, r, &in, []string{"keys", "expected_revision", "reason"}) != nil {
				writeError(w, ErrInvalid)
				return
			}
			result, err := s.setSSHKeys(ctx, id, in.Input, in.Actor)
			if err != nil {
				writeError(w, err)
				return
			}
			json.NewEncoder(w).Encode(result)
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/accounts/") && strings.HasSuffix(r.URL.Path, "/web"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/accounts/"), "/web")
			if !idPattern.MatchString(id) {
				writeError(w, ErrInvalid)
				return
			}
			var in struct {
				Input WebInput `json:"input"`
				Actor string   `json:"actor"`
			}
			if decodeBody(w, r, &in, []string{"php_version", "quota_mib", "expected_revision", "reason"}) != nil {
				writeError(w, ErrInvalid)
				return
			}
			// The apply can take minutes on a busy host, longer than the
			// server's default write deadline; it runs on its own limit.
			if e := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(webApplyTimeout + time.Minute)); e != nil && !errors.Is(e, http.ErrNotSupported) {
				writeError(w, ErrUnavailable)
				return
			}
			result, err := s.setWeb(ctx, id, in.Input, in.Actor)
			if err != nil {
				writeError(w, err)
				return
			}
			json.NewEncoder(w).Encode(result)
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/accounts/") && strings.HasSuffix(r.URL.Path, "/certificate"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/accounts/"), "/certificate")
			if !idPattern.MatchString(id) {
				writeError(w, ErrInvalid)
				return
			}
			var in struct {
				Input CertificateInput `json:"input"`
				Actor string           `json:"actor"`
			}
			// Two PEMs of up to 64 KiB do not fit the usual request bound.
			if decodeBodyWithin(w, r, &in, []string{"expected_revision", "cert_pem", "key_pem", "reason"}, maxCertificateRequestBytes) != nil {
				writeError(w, ErrInvalid)
				return
			}
			// The install runs the web apply, on its own limit.
			if e := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(webApplyTimeout + time.Minute)); e != nil && !errors.Is(e, http.ErrNotSupported) {
				writeError(w, ErrUnavailable)
				return
			}
			result, err := s.setCertificate(ctx, id, in.Input, in.Actor)
			if err != nil {
				writeError(w, err)
				return
			}
			json.NewEncoder(w).Encode(result)
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/accounts/") && strings.HasSuffix(r.URL.Path, "/wordpress"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/accounts/"), "/wordpress")
			if !idPattern.MatchString(id) {
				writeError(w, ErrInvalid)
				return
			}
			var in struct {
				Input WordPressInput `json:"input"`
				Actor string         `json:"actor"`
			}
			if decodeBody(w, r, &in, []string{"expected_revision", "https", "title", "admin_user", "admin_email", "admin_password", "db_name", "db_user", "db_password"}) != nil {
				writeError(w, ErrInvalid)
				return
			}
			// An install takes minutes, longer than the server's default
			// write deadline; it runs on its own limit, not this request's.
			if e := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(wordpressTimeout + time.Minute)); e != nil && !errors.Is(e, http.ErrNotSupported) {
				writeError(w, ErrUnavailable)
				return
			}
			result, err := s.installWordPress(ctx, id, in.Input, in.Actor)
			var failed *InstallError
			if errors.As(err, &failed) {
				w.WriteHeader(422)
				json.NewEncoder(w).Encode(struct {
					Error  string `json:"error"`
					Step   string `json:"step"`
					Detail string `json:"detail"`
				}{"install_failed", failed.Step, failed.Detail})
				return
			}
			if err != nil {
				writeError(w, err)
				return
			}
			json.NewEncoder(w).Encode(result)
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/accounts/") && strings.HasSuffix(r.URL.Path, "/delete"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/accounts/"), "/delete")
			if !idPattern.MatchString(id) {
				writeError(w, ErrInvalid)
				return
			}
			var in struct {
				Input DeleteInput `json:"input"`
				Actor string      `json:"actor"`
			}
			if decodeBody(w, r, &in, []string{"expected_revision", "reason"}) != nil {
				writeError(w, ErrInvalid)
				return
			}
			if e := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(webApplyTimeout + time.Minute)); e != nil && !errors.Is(e, http.ErrNotSupported) {
				writeError(w, ErrUnavailable)
				return
			}
			item, err := s.delete(ctx, id, in.Input, in.Actor)
			if err != nil {
				writeError(w, err)
				return
			}
			json.NewEncoder(w).Encode(item)
		default:
			writeError(w, ErrNotFound)
		}
	})
}
func writeError(w http.ResponseWriter, err error) {
	code, status := "unavailable", 503
	switch {
	case errors.Is(err, ErrInvalid):
		code, status = "invalid", 400
	case errors.Is(err, ErrConflict):
		code, status = "conflict", 409
	case errors.Is(err, ErrNotFound):
		code, status = "not_found", 404
	case errors.Is(err, ErrWebRejected):
		code, status = "web_rejected", 422
	case errors.Is(err, ErrCertificateRejected):
		code, status = "certificate_rejected", 422
	case errors.Is(err, ErrRecovery):
		code, status = "recovery", 503
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{code})
}
func decodeBody(w http.ResponseWriter, r *http.Request, out any, inputKeys []string) error {
	return decodeBodyWithin(w, r, out, inputKeys, MaxRequestBytes)
}

// decodeBodyWithin is decodeBody with its own size bound, for the one
// request whose input is larger than MaxRequestBytes.
func decodeBodyWithin(w http.ResponseWriter, r *http.Request, out any, inputKeys []string, limit int64) error {
	media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || params["charset"] != "" && strings.ToLower(params["charset"]) != "utf-8" {
		return ErrInvalid
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil || !utf8.Valid(b) {
		return ErrInvalid
	}
	keys := map[string]bool{}
	for _, key := range inputKeys {
		keys[key] = true
	}
	d := json.NewDecoder(bytes.NewReader(b))
	if strictObject(d, map[string]bool{"input": true, "actor": true}, true, keys, false) != nil {
		return ErrInvalid
	}
	if _, err = d.Token(); err != io.EOF {
		return ErrInvalid
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrInvalid
	}
	return nil
}
func strictObject(d *json.Decoder, allowed map[string]bool, requireAll bool, nested map[string]bool, nestedRequireAll bool) error {
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok || !allowed[key] || seen[key] {
			return ErrInvalid
		}
		seen[key] = true
		if key == "input" && nested != nil {
			if strictObject(d, nested, nestedRequireAll, nil, false) != nil {
				return ErrInvalid
			}
		} else {
			var raw json.RawMessage
			if d.Decode(&raw) != nil || bytes.Equal(raw, []byte("null")) {
				return ErrInvalid
			}
		}
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') {
		return ErrInvalid
	}
	if requireAll && len(seen) != len(allowed) {
		return ErrInvalid
	}
	return nil
}
