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
		case fileRoutePattern.MatchString(r.URL.Path):
			// The file manager's routes (files_http.go), first because
			// ".../files/delete" also ends like an account delete. Each runs
			// the file helper as the account's user, on its own limit.
			serveFiles(w, r, s)
		case migrateRoute(r.URL.Path):
			// Migration (http_migrate.go): reading a cPanel server and
			// copying one of its accounts here.
			serveMigrate(ctx, w, r, s)
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
			// The slice limits, the systemd reload and the user's creation
			// run on their own limit, not this request's.
			if e := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(webApplyTimeout + time.Minute)); e != nil && !errors.Is(e, http.ErrNotSupported) {
				writeError(w, ErrUnavailable)
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
			if decodeBody(w, r, &in, []string{"plan", "limits", "expected_revision", "reason"}) != nil {
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
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/accounts/") && strings.HasSuffix(r.URL.Path, "/domains"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/accounts/"), "/domains")
			if !idPattern.MatchString(id) || r.ContentLength != 0 {
				writeError(w, ErrInvalid)
				return
			}
			result, err := s.siteDomains(ctx, id)
			if err != nil {
				writeError(w, err)
				return
			}
			json.NewEncoder(w).Encode(result)
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/accounts/") && strings.HasSuffix(r.URL.Path, "/domains"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/accounts/"), "/domains")
			if !idPattern.MatchString(id) {
				writeError(w, ErrInvalid)
				return
			}
			var in struct {
				Input SiteDomainsInput `json:"input"`
				Actor string           `json:"actor"`
			}
			// Up to 100 redirects do not fit the usual request bound. Both
			// lists are required: a list left out would remove them all.
			if decodeBodyWithin(w, r, &in, []string{"aliases", "redirects", "expected_revision", "reason"}, maxSiteDomainsRequestBytes) != nil || in.Input.Aliases == nil || in.Input.Redirects == nil {
				writeError(w, ErrInvalid)
				return
			}
			// The change runs the web apply, on its own limit.
			if e := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(webApplyTimeout + time.Minute)); e != nil && !errors.Is(e, http.ErrNotSupported) {
				writeError(w, ErrUnavailable)
				return
			}
			result, err := s.setSiteDomains(ctx, id, in.Input, in.Actor)
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
					Error     string `json:"error"`
					Step      string `json:"step"`
					Detail    string `json:"detail"`
					Installed bool   `json:"wordpress_installed"`
				}{"install_failed", failed.Step, failed.Detail, failed.Installed})
				return
			}
			if err != nil {
				writeError(w, err)
				return
			}
			json.NewEncoder(w).Encode(result)
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/accounts/") && strings.HasSuffix(r.URL.Path, "/placeholder"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/accounts/"), "/placeholder")
			if !idPattern.MatchString(id) {
				writeError(w, ErrInvalid)
				return
			}
			var in struct {
				Input PlaceholderInput `json:"input"`
				Actor string           `json:"actor"`
			}
			if decodeBody(w, r, &in, []string{"expected_revision"}) != nil {
				writeError(w, ErrInvalid)
				return
			}
			result, err := s.installPlaceholder(ctx, id, in.Input, in.Actor)
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
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/accounts/") && strings.HasSuffix(r.URL.Path, "/public-html"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/accounts/"), "/public-html")
			if !idPattern.MatchString(id) {
				writeError(w, ErrInvalid)
				return
			}
			var in struct {
				Input AdoptInput `json:"input"`
				Actor string     `json:"actor"`
			}
			if decodeBody(w, r, &in, []string{"expected_revision", "reason"}) != nil {
				writeError(w, ErrInvalid)
				return
			}
			item, err := s.adoptPublicHTML(ctx, id, in.Input, in.Actor)
			if err != nil {
				writeError(w, err)
				return
			}
			json.NewEncoder(w).Encode(item)
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
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/accounts/") && strings.HasSuffix(r.URL.Path, "/abandon-create"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/accounts/"), "/abandon-create")
			if !idPattern.MatchString(id) {
				writeError(w, ErrInvalid)
				return
			}
			var in struct {
				Input AbandonCreateInput `json:"input"`
				Actor string             `json:"actor"`
			}
			if decodeBody(w, r, &in, []string{"reason"}) != nil {
				writeError(w, ErrInvalid)
				return
			}
			// userdel and the rest run on the operation's own limit.
			if e := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(webApplyTimeout + time.Minute)); e != nil && !errors.Is(e, http.ErrNotSupported) {
				writeError(w, ErrUnavailable)
				return
			}
			item, err := s.abandonCreate(ctx, id, in.Input, in.Actor)
			var refused *AbandonRefusedError
			if errors.As(err, &refused) {
				w.WriteHeader(409)
				json.NewEncoder(w).Encode(struct {
					Error  string `json:"error"`
					Reason string `json:"reason"`
				}{"abandon_refused", refused.Reason})
				return
			}
			if err != nil {
				writeError(w, err)
				return
			}
			json.NewEncoder(w).Encode(item)
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/accounts/") && strings.HasSuffix(r.URL.Path, "/finish-delete"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/accounts/"), "/finish-delete")
			if !idPattern.MatchString(id) {
				writeError(w, ErrInvalid)
				return
			}
			var in struct {
				Input FinishDeleteInput `json:"input"`
				Actor string            `json:"actor"`
			}
			if decodeBody(w, r, &in, []string{"reason"}) != nil {
				writeError(w, ErrInvalid)
				return
			}
			// userdel and the rest run on the operation's own limit.
			if e := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(webApplyTimeout + time.Minute)); e != nil && !errors.Is(e, http.ErrNotSupported) {
				writeError(w, ErrUnavailable)
				return
			}
			item, err := s.finishDelete(ctx, id, in.Input, in.Actor)
			var refused *DeleteRefusedError
			if errors.As(err, &refused) {
				w.WriteHeader(409)
				json.NewEncoder(w).Encode(struct {
					Error  string `json:"error"`
					Reason string `json:"reason"`
				}{"delete_refused", refused.Reason})
				return
			}
			if err != nil {
				writeError(w, err)
				return
			}
			json.NewEncoder(w).Encode(item)
		case r.Method == "GET" && r.URL.Path == "/v1/backup":
			if r.ContentLength != 0 {
				writeError(w, ErrInvalid)
				return
			}
			result, err := s.backupStatus(ctx)
			answerBackup(w, result, err)
		case r.Method == "POST" && r.URL.Path == "/v1/backup/target":
			var in struct {
				Input BackupTargetInput `json:"input"`
				Actor string            `json:"actor"`
			}
			if decodeBody(w, r, &in, []string{"host", "port", "user", "path", "known_hosts", "reason"}) != nil {
				writeError(w, ErrInvalid)
				return
			}
			if !backupDeadline(w, backupTargetTimeout) {
				return
			}
			result, err := s.setBackupTarget(ctx, in.Input, in.Actor)
			answerBackup(w, result, err)
		case r.Method == "POST" && (r.URL.Path == "/v1/backup/password" || r.URL.Path == "/v1/backup/password-saved"):
			var in struct {
				Input BackupPasswordInput `json:"input"`
				Actor string              `json:"actor"`
			}
			if decodeBody(w, r, &in, []string{"reason"}) != nil {
				writeError(w, ErrInvalid)
				return
			}
			if r.URL.Path == "/v1/backup/password" {
				result, err := s.showBackupPassword(ctx, in.Input, in.Actor)
				answerBackup(w, result, err)
				return
			}
			result, err := s.confirmBackupPassword(ctx, in.Input, in.Actor)
			answerBackup(w, result, err)
		case r.Method == "POST" && r.URL.Path == "/v1/backup/prune":
			var in struct {
				Input PruneInput `json:"input"`
				Actor string     `json:"actor"`
			}
			if decodeBody(w, r, &in, []string{"reason"}) != nil {
				writeError(w, ErrInvalid)
				return
			}
			if !backupDeadline(w, backupTimeout) {
				return
			}
			result, err := s.pruneBackups(ctx, in.Input, in.Actor)
			answerBackup(w, result, err)
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/accounts/") && strings.HasSuffix(r.URL.Path, "/backup"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/accounts/"), "/backup")
			if !idPattern.MatchString(id) {
				writeError(w, ErrInvalid)
				return
			}
			var in struct {
				Input BackupInput `json:"input"`
				Actor string      `json:"actor"`
			}
			if decodeBody(w, r, &in, []string{"databases", "reason"}) != nil {
				writeError(w, ErrInvalid)
				return
			}
			if !backupDeadline(w, backupTimeout) {
				return
			}
			result, err := s.backupAccount(ctx, id, in.Input, in.Actor)
			answerBackup(w, result, err)
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/accounts/") && strings.HasSuffix(r.URL.Path, "/backups"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/accounts/"), "/backups")
			if !idPattern.MatchString(id) || r.ContentLength != 0 {
				writeError(w, ErrInvalid)
				return
			}
			if !backupDeadline(w, backupListTimeout) {
				return
			}
			items, err := s.listBackups(ctx, id)
			answerBackup(w, struct {
				Items []Snapshot `json:"items"`
			}{items}, err)
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/accounts/") && strings.HasSuffix(r.URL.Path, "/restore"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/accounts/"), "/restore")
			if !idPattern.MatchString(id) {
				writeError(w, ErrInvalid)
				return
			}
			var in struct {
				Input RestoreInput `json:"input"`
				Actor string       `json:"actor"`
			}
			if decodeBody(w, r, &in, []string{"expected_revision", "snapshot", "files", "databases", "reason"}) != nil {
				writeError(w, ErrInvalid)
				return
			}
			if !backupDeadline(w, backupTimeout) {
				return
			}
			result, err := s.restoreAccount(ctx, id, in.Input, in.Actor)
			answerBackup(w, result, err)
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/accounts/") && strings.HasSuffix(r.URL.Path, "/drill"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/accounts/"), "/drill")
			if !idPattern.MatchString(id) {
				writeError(w, ErrInvalid)
				return
			}
			var in struct {
				Input DrillInput `json:"input"`
				Actor string     `json:"actor"`
			}
			if decodeBody(w, r, &in, []string{"reason"}) != nil {
				writeError(w, ErrInvalid)
				return
			}
			if !backupDeadline(w, backupTimeout) {
				return
			}
			result, err := s.drillAccount(ctx, id, in.Input, in.Actor)
			answerBackup(w, result, err)
		case siteToolsRoute(r.URL.Path):
			serveSiteTools(ctx, w, r, s)
		default:
			writeError(w, ErrNotFound)
		}
	})
}

// backupDeadline lets a backup operation's answer wait for its own limit,
// which is longer than the server's default write deadline.
func backupDeadline(w http.ResponseWriter, limit time.Duration) bool {
	if e := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(limit + time.Minute)); e != nil && !errors.Is(e, http.ErrNotSupported) {
		writeError(w, ErrUnavailable)
		return false
	}
	return true
}

// answerBackup writes a backup operation's result, or 422 backup_failed
// with the failed step and the end of its output, or the usual error.
func answerBackup(w http.ResponseWriter, result any, err error) {
	var failed *BackupError
	if errors.As(err, &failed) {
		w.WriteHeader(422)
		json.NewEncoder(w).Encode(struct {
			Error  string `json:"error"`
			Step   string `json:"step"`
			Detail string `json:"detail"`
		}{"backup_failed", failed.Step, failed.Detail})
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}
	json.NewEncoder(w).Encode(result)
}
func writeError(w http.ResponseWriter, err error) {
	code, status := "unavailable", 503
	switch {
	case errors.Is(err, ErrInvalid):
		code, status = "invalid", 400
	case errors.Is(err, ErrDeleteBusy):
		code, status = "delete_busy", 409
	case errors.Is(err, ErrDomainTaken):
		code, status = "domain_taken", 409
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
	case errors.Is(err, ErrDeleteStopped):
		code, status = "delete_stopped", 503
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
		} else if key == "limits" && nested == nil {
			// A plan's limits inside the input: all three keys, each once,
			// in bounds. All zeros would decode as limits left out.
			var raw json.RawMessage
			var limits AccountLimits
			if d.Decode(&raw) != nil || strictObject(json.NewDecoder(bytes.NewReader(raw)), map[string]bool{"processes": true, "memory_mib": true, "cpu_percent": true}, true, nil, false) != nil || json.Unmarshal(raw, &limits) != nil || !validLimits(limits) {
				return ErrInvalid
			}
		} else if key == "redirects" && nested == nil {
			// A site's redirects inside the input: an array of objects, each
			// with only its own keys, each once, in this case.
			var raw []json.RawMessage
			if d.Decode(&raw) != nil || raw == nil {
				return ErrInvalid
			}
			for _, item := range raw {
				if strictObject(json.NewDecoder(bytes.NewReader(item)), map[string]bool{"domain": true, "path": true, "target": true, "status": true}, false, nil, false) != nil {
					return ErrInvalid
				}
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
