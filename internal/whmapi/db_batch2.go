package whmapi

// db.grants batch 2 UAPI handlers: Mysql::rename_database and the
// additional MySQL access host functions (add_host/delete_host/list_hosts).

import (
	"net/http"
	"strings"

	"sifruno/internal/dbhost"
)

func (s *Server) uapiMysqlRenameDatabase(w http.ResponseWriter, r *http.Request, account Account, user string) {
	oldName := strings.TrimSpace(r.URL.Query().Get("old_name"))
	newName := strings.TrimSpace(r.URL.Query().Get("new_name"))
	if s.db == nil {
		s.dbOfflineUAPI(w, "rename_database")
		return
	}
	svc, ok := s.db.(dbhost.RenameService)
	if !ok {
		writeUAPIError(w, "Mysql", "rename_database", []string{"database rename unsupported by this database service"})
		return
	}
	renamed, err := svc.RenameDatabase(r.Context(), user, oldName, newName)
	if err != nil {
		writeUAPIError(w, "Mysql", "rename_database", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Mysql", "rename_database", renamed)
}

func (s *Server) uapiMysqlAddHost(w http.ResponseWriter, r *http.Request, account Account, user string) {
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	if s.db == nil {
		s.dbOfflineUAPI(w, "add_host")
		return
	}
	svc, ok := s.db.(dbhost.AccessHostService)
	if !ok {
		writeUAPIError(w, "Mysql", "add_host", []string{"access hosts unsupported by this database service"})
		return
	}
	if err := svc.AddAccessHost(r.Context(), user, host); err != nil {
		writeUAPIError(w, "Mysql", "add_host", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Mysql", "add_host", host)
}

func (s *Server) uapiMysqlDeleteHost(w http.ResponseWriter, r *http.Request, account Account, user string) {
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	if s.db == nil {
		s.dbOfflineUAPI(w, "delete_host")
		return
	}
	svc, ok := s.db.(dbhost.AccessHostService)
	if !ok {
		writeUAPIError(w, "Mysql", "delete_host", []string{"access hosts unsupported by this database service"})
		return
	}
	if err := svc.DeleteAccessHost(r.Context(), user, host); err != nil {
		writeUAPIError(w, "Mysql", "delete_host", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Mysql", "delete_host", host)
}

func (s *Server) uapiMysqlListHosts(w http.ResponseWriter, r *http.Request, account Account, user string) {
	if s.db == nil {
		s.dbOfflineUAPI(w, "list_hosts")
		return
	}
	svc, ok := s.db.(dbhost.AccessHostService)
	if !ok {
		writeUAPIError(w, "Mysql", "list_hosts", []string{"access hosts unsupported by this database service"})
		return
	}
	writeUAPISuccess(w, "Mysql", "list_hosts", svc.ListAccessHosts(r.Context(), user))
}
