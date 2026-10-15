package whmapi

// backup.archive batch 1: WHM backup_user_list + UAPI
// Backup::list_backups / Backup::fullbackup_to_homedir over the
// backuphost store. Placement delta vs the reference (panel backup root
// instead of the account homedir, which is account-uid-owned) is
// documented in docs/reference/backup-archive-batch1.md.

import (
	"net/http"
	"strings"

	"sifruno/internal/backuphost"
)

// SetBackupStore wires the backup store.
func (s *Server) SetBackupStore(st *backuphost.Store) { s.backups = st }

// handleBackupUserList answers WHM backup_user_list: accounts with their
// backup counts (honest zero when none).
func (s *Server) handleBackupUserList(w http.ResponseWriter, r *http.Request) {
	accts := s.backend.ListAccounts()
	out := make([]map[string]any, 0, len(accts))
	for _, a := range accts {
		count := 0
		if s.backups != nil {
			if list, err := s.backups.List(r.Context(), a.User); err == nil {
				count = len(list)
			}
		}
		out = append(out, map[string]any{"user": a.User, "backup_count": count})
	}
	writeSuccess(w, "backup_user_list", map[string]any{"accounts": out}, "")
}

func (s *Server) uapiBackupList(w http.ResponseWriter, r *http.Request, a Account, u string) {
	if s.backups == nil {
		writeUAPIError(w, "Backup", "list_backups", []string{"backup service unavailable"})
		return
	}
	list, err := s.backups.List(r.Context(), u)
	if err != nil {
		writeUAPIError(w, "Backup", "list_backups", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Backup", "list_backups", list)
}

// uapiBackupFullToHomedir creates the full account backup. Reference
// semantics place the archive in the account homedir; sifruno currently
// stores it in the panel backup root (account homes are account-uid-owned;
// broker-assisted homedir writes land in batch 2). The response path is
// always the real location.
func (s *Server) uapiBackupFullToHomedir(w http.ResponseWriter, r *http.Request, a Account, u string) {
	if s.backups == nil {
		writeUAPIError(w, "Backup", "fullbackup_to_homedir", []string{"backup service unavailable"})
		return
	}
	info, err := s.backups.Create(r.Context(), u)
	if err != nil {
		writeUAPIError(w, "Backup", "fullbackup_to_homedir", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Backup", "fullbackup_to_homedir", map[string]any{
		"file":  info.File,
		"size":  info.Size,
		"path":  strings.Join([]string{"backups", u, info.File}, "/"),
		"notes": "Archive stored in the panel backup root; homedir placement lands with broker file operations (batch 2).",
	})
}
