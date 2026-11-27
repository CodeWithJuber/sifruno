package api

import (
	"context"
	"encoding/json"
	"mime"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"sifruno/internal/hostaccounts"
)

// "Move a website here" from a cPanel backup file (docs/migration-design.md):
// the admin uploads the cpmove-USER.tar.gz the old host made, and the panel
// streams it to the broker (OpenArchiveMigration), which keeps it root-only
// for the move and answers what it holds and what will not move. From
// there the move is a migration like one from a server: the source is the
// file, its one account is listed, and StartMigration copies it.

const (
	migrationArchivePath = "/api/v1/websites/migrations/archive"
	// maxArchiveUpload is the broker's bound on one backup file.
	maxArchiveUpload = 32 << 30
	// archiveUploadWait bounds an upload, and the broker's first read.
	archiveUploadWait = 2 * time.Hour
)

func isMigrationArchive(r *http.Request) bool {
	return r.Method == http.MethodPost && r.URL.Path == migrationArchivePath
}

// prepareMigrationArchive leaves the body to its handler, which reads it as
// a stream.
func prepareMigrationArchive(http.ResponseWriter, *http.Request) bool { return true }

func registerMigrationArchive(mux *routeMux, a huma.API, o Options) {
	mux.HandleFunc("POST "+migrationArchivePath, func(w http.ResponseWriter, r *http.Request) {
		if o.Migrations == nil || o.Wizard == nil {
			writeFileProblem(w, huma.Error503ServiceUnavailable(migrationsUnavailable))
			return
		}
		media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/octet-stream" || len(params) != 0 || r.ContentLength <= 0 || len(r.TransferEncoding) != 0 || r.URL.RawQuery != "" {
			writeFileProblem(w, newMigrationProblem(http.StatusUnsupportedMediaType, "The backup file did not arrive as a file upload.", "Choose the file again, then press Upload.", ""))
			return
		}
		if r.ContentLength > maxArchiveUpload {
			writeFileProblem(w, newMigrationProblem(http.StatusRequestEntityTooLarge, "The backup file is larger than 32 GiB, the most one move takes.", "Move this website from its server instead: choose \"cPanel server\" or \"Another Linux server\".", ""))
			return
		}
		extendDeadlines(w, archiveUploadWait)
		ctx, cancel := context.WithTimeout(r.Context(), archiveUploadWait)
		defer cancel()
		body := http.MaxBytesReader(w, r.Body, r.ContentLength)
		m, err := o.Migrations.OpenArchiveMigration(ctx, hostaccounts.MigrationArchiveInput{Size: r.ContentLength, Reason: migrationReason}, body, siteActor(ctx))
		if err != nil {
			writeFileProblem(w, migrationBrokerError(err))
			return
		}
		var out migrationSourceOutput
		out.Body.Source = migrationSource(m)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out.Body)
	})
	problem := map[string]*huma.MediaType{"application/problem+json": {Schema: &huma.Schema{Type: "object"}}}
	upload := &huma.Operation{OperationID: "upload-migration-archive", Method: http.MethodPost, Path: migrationArchivePath, Summary: "Upload a cPanel backup file to move its website here",
		Description: "The body is the backup file's own bytes (application/octet-stream: cpmove-USER.tar.gz, USER.tar.gz or backup-..._USER.tar.gz) with a Content-Length of at most 32 GiB. The account service keeps it, root's only, for 24 hours and reads it; the answer is a migration source whose archive says what it holds and what will not move. Admin session with Origin and CSRF; not an API token.",
		RequestBody: &huma.RequestBody{Required: true, Content: map[string]*huma.MediaType{"application/octet-stream": {Schema: &huma.Schema{Type: "string", Format: "binary"}}}},
		Responses: map[string]*huma.Response{
			"200": {Description: "The backup file as a migration source.", Content: map[string]*huma.MediaType{"application/json": {Schema: &huma.Schema{Type: "object"}}}},
		}}
	for _, code := range []string{"403", "409", "413", "415", "422", "503"} {
		upload.Responses[code] = &huma.Response{Description: "A problem: what happened, why and what to do next.", Content: problem}
	}
	a.OpenAPI().AddOperation(upload)
}
