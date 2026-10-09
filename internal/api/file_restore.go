package api

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/danielgtaylor/huma/v2"
	"sifruno/internal/sites"
)

func fileRestoreShape(raw []byte, confirm bool) bool {
	keys := []string{"backup_id", "expected_backup_sha256", "expected_revision", "path"}
	if confirm {
		keys = append(keys, "confirmed")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != len(keys) {
		return false
	}
	for _, key := range keys {
		value, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	return true
}

func registerFileRestore(a huma.API, o Options) {
	type previewInput struct {
		ID   string `path:"id"`
		Body sites.FileRestoreInput
	}
	type confirmInput struct {
		ID   string `path:"id"`
		Body sites.ConfirmFileRestoreInput
	}
	type previewOutput struct{ Body sites.FileRestorePreview }
	op := siteOperation("preview-native-file-restore", "POST", "/api/v1/sites/{id}/restore-file-preview")
	op.MaxBodyBytes = 4096
	op.Summary = "Preview restoring one exact file from a saved native ZIP"
	op.Description = "Read-only; exact non-null backup_id, expected_backup_sha256, expected_revision and path keys. Revalidates current files, saved archive and complete merged catalog under the store lock. Every other current file is preserved. Requires local session, Origin and CSRF admission before parsing."
	huma.Register(a, op, func(ctx context.Context, in *previewInput) (*previewOutput, error) {
		v, err := o.Sites.PreviewFileRestore(in.ID, in.Body)
		if err != nil {
			return nil, websiteError(err)
		}
		return &previewOutput{Body: v}, nil
	})
	op = siteOperation("restore-native-file", "POST", "/api/v1/sites/{id}/restore-file")
	op.MaxBodyBytes = 4096
	op.Summary = "Confirm restoring only one selected saved ZIP file"
	op.Description = "Exact preview input plus confirmed:true. Binds current site revision, ZIP ID/SHA256 and selected path; reruns all read-only admission before signed restore checkpoint. Preserves other file bytes, site identity, routing, state, backup history and schedule. Stale/foreign/missing/corrupt/ambiguous inputs refuse without mutation or retry."
	huma.Register(a, op, func(ctx context.Context, in *confirmInput) (*siteOutput, error) {
		v, err := o.Sites.RestoreFile(in.ID, in.Body, siteActor(ctx))
		if err != nil {
			return nil, websiteError(err)
		}
		return &siteOutput{Body: v}, nil
	})
}
