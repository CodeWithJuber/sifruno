package hostaccounts

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"
)

// The broker's migration routes (README, Migration):
//
//	POST /v1/migrations                         host, port, reason
//	GET  /v1/migrations/{id}                    the migration
//	POST /v1/migrations/{id}/host-key           fingerprint, reason
//	GET  /v1/migrations/{id}/accounts           the source's accounts
//	POST /v1/migrations/{id}/plan               username, reason
//	POST /v1/migrations/{id}/finish             reason
//	GET  /v1/migrations/stale                   key lines that may still be on old servers
//	POST /v1/migrations/{id}/stale-cleared      reason: the admin removed that line
//	POST /v1/accounts/{id}/migrate-files        migration, expected_revision, reason
//	POST /v1/accounts/{id}/migrate-database     migration, database, expected_revision, reason
var (
	migrationPath   = regexp.MustCompile(`^/v1/migrations/([a-f0-9]{32})(/host-key|/accounts|/plan|/finish|/stale-cleared)?$`)
	migrateCopyPath = regexp.MustCompile(`^/v1/accounts/([a-f0-9]{32})/(migrate-files|migrate-database)$`)
)

func migrateRoute(path string) bool {
	return path == "/v1/migrations" || path == "/v1/migrations/stale" || migrationPath.MatchString(path) || migrateCopyPath.MatchString(path)
}

// answerMigration writes the result, or 422 migration_failed with the step,
// the broker's words and the end of the error output, or the usual error.
func answerMigration(w http.ResponseWriter, result any, err error) {
	var failed *MigrationError
	if errors.As(err, &failed) {
		w.WriteHeader(422)
		json.NewEncoder(w).Encode(struct {
			Error  string `json:"error"`
			Step   string `json:"step"`
			Detail string `json:"detail"`
			Output string `json:"output"`
		}{"migration_failed", failed.Step, failed.Detail, failed.Output})
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}
	json.NewEncoder(w).Encode(result)
}

func serveMigrate(ctx context.Context, w http.ResponseWriter, r *http.Request, s *store) {
	type body[T any] struct {
		Input T      `json:"input"`
		Actor string `json:"actor"`
	}
	if r.URL.Path == "/v1/migrations" {
		var in body[MigrationOpenInput]
		if r.Method != "POST" || decodeBody(w, r, &in, []string{"host", "port", "via", "reason"}) != nil {
			writeError(w, ErrInvalid)
			return
		}
		result, err := s.openMigration(ctx, in.Input, in.Actor)
		answerMigration(w, result, err)
		return
	}
	if r.URL.Path == "/v1/migrations/stale" {
		if r.Method != "GET" || !noBody(r) {
			writeError(w, ErrInvalid)
			return
		}
		items, err := s.listStaleKeys(ctx)
		answerMigration(w, struct {
			Items []StaleMigrationKey `json:"items"`
		}{items}, err)
		return
	}
	if m := migrateCopyPath.FindStringSubmatch(r.URL.Path); m != nil {
		if r.Method != "POST" {
			writeError(w, ErrNotFound)
			return
		}
		// The copy runs on its own limit, not this request's: the store
		// detaches it, and the answer may wait as long.
		if !backupDeadline(w, backupTimeout) {
			return
		}
		if m[2] == "migrate-files" {
			var in body[MigrateFilesInput]
			if decodeBodyWithin(w, r, &in, []string{"migration", "expected_revision", "cpanel", "reason"}, maxCPanelRequest) != nil {
				writeError(w, ErrInvalid)
				return
			}
			result, err := s.migrateFiles(ctx, m[1], in.Input, in.Actor)
			answerMigration(w, result, err)
			return
		}
		var in body[MigrateDatabaseInput]
		if decodeBodyWithin(w, r, &in, []string{"migration", "database", "expected_revision", "cpanel", "reason"}, maxCPanelRequest) != nil {
			writeError(w, ErrInvalid)
			return
		}
		result, err := s.migrateDatabase(ctx, m[1], in.Input, in.Actor)
		answerMigration(w, result, err)
		return
	}
	m := migrationPath.FindStringSubmatch(r.URL.Path)
	id, action := m[1], m[2]
	switch {
	case action == "" && r.Method == "GET":
		if !noBody(r) {
			writeError(w, ErrInvalid)
			return
		}
		result, err := s.getMigration(ctx, id)
		answerMigration(w, result, err)
	case action == "/accounts" && r.Method == "GET":
		if !noBody(r) || !backupDeadline(w, migrateRemoteTimeout) {
			return
		}
		items, err := s.migrationAccounts(ctx, id)
		answerMigration(w, struct {
			Items any `json:"items"`
		}{items}, err)
	case action == "/host-key" && r.Method == "POST":
		var in body[MigrationPinInput]
		if decodeBody(w, r, &in, []string{"fingerprint", "reason"}) != nil {
			writeError(w, ErrInvalid)
			return
		}
		result, err := s.pinMigrationHostKey(ctx, id, in.Input, in.Actor)
		answerMigration(w, result, err)
	case action == "/plan" && r.Method == "POST":
		var in body[MigrationPlanInput]
		if decodeBodyWithin(w, r, &in, []string{"username", "cpanel", "reason"}, maxCPanelRequest) != nil {
			writeError(w, ErrInvalid)
			return
		}
		if !backupDeadline(w, 10*time.Minute) {
			return
		}
		result, err := s.planMigration(ctx, id, in.Input, in.Actor)
		answerMigration(w, result, err)
	case action == "/stale-cleared" && r.Method == "POST":
		var in body[MigrationFinishInput]
		if decodeBody(w, r, &in, []string{"reason"}) != nil {
			writeError(w, ErrInvalid)
			return
		}
		answerMigration(w, struct{}{}, s.clearStaleKey(ctx, id, in.Input, in.Actor))
	case action == "/finish" && r.Method == "POST":
		var in body[MigrationFinishInput]
		if decodeBody(w, r, &in, []string{"reason"}) != nil {
			writeError(w, ErrInvalid)
			return
		}
		if !backupDeadline(w, 3*migrateRemoteTimeout) {
			return
		}
		result, err := s.finishMigration(ctx, id, in.Input, in.Actor)
		answerMigration(w, result, err)
	default:
		writeError(w, ErrNotFound)
	}
}
