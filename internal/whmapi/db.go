package whmapi

import (
	"net/http"
	"strings"

	"sifruno/internal/dbhost"
)

// Database surface (pr-db / db.grants obligation): WHM API 1 mysql functions
// and the UAPI Mysql module, backed by the real local MariaDB through
// dbhost. Fail-closed: when the server is unreachable the reference's
// offline-style error is returned; no fabricated success.

// SetDBService injects the database service. Nil keeps the surface
// fail-closed (offline error on every database call).
func (s *Server) SetDBService(svc dbhost.Service) { s.db = svc }

func (s *Server) dbOfflineWHM(w http.ResponseWriter, command string) {
	writeError(w, command, "The MySQL/MariaDB server is currently offline.")
}

func (s *Server) dbOfflineUAPI(w http.ResponseWriter, fn string) {
	writeUAPIError(w, "Mysql", fn, []string{"The MySQL/MariaDB server is currently offline."})
}

// --- WHM API 1 ---

func (s *Server) handleCurrentMySQLVersion(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.dbOfflineWHM(w, "current_mysql_version")
		return
	}
	v, err := s.db.Probe(r.Context())
	if err != nil {
		s.dbOfflineWHM(w, "current_mysql_version")
		return
	}
	writeSuccess(w, "current_mysql_version", map[string]any{"version": v}, "")
}

func (s *Server) handleListMySQLDatabasesAndUsers(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.dbOfflineWHM(w, "list_mysql_databases_and_users")
		return
	}
	dbs, err := s.db.AllDatabases(r.Context())
	if err != nil {
		s.dbOfflineWHM(w, "list_mysql_databases_and_users")
		return
	}
	users, err := s.db.AllUsers(r.Context())
	if err != nil {
		s.dbOfflineWHM(w, "list_mysql_databases_and_users")
		return
	}
	dbList := make([]map[string]any, 0, len(dbs))
	for _, d := range dbs {
		dbList = append(dbList, map[string]any{"database": d.Name, "owner": d.Owner, "users": d.Users})
	}
	uList := make([]map[string]any, 0, len(users))
	for _, u := range users {
		uList = append(uList, map[string]any{"user": u.Name, "owner": u.Owner})
	}
	writeSuccess(w, "list_mysql_databases_and_users", map[string]any{
		"databases": dbList, "users": uList,
	}, "")
}

func (s *Server) handleSetMySQLPassword(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	password := r.URL.Query().Get("password")
	if user == "" || password == "" {
		writeError(w, "set_mysql_password", "Missing required parameters: user and password.")
		return
	}
	if s.db == nil {
		s.dbOfflineWHM(w, "set_mysql_password")
		return
	}
	if err := s.db.SetPassword(r.Context(), "", user, password); err != nil {
		writeError(w, "set_mysql_password", err.Error())
		return
	}
	writeSuccessReason(w, "set_mysql_password", "The password was changed for the user.", nil, "")
}

func (s *Server) handleRenameMySQLUser(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	user, newUser := q.Get("user"), q.Get("newuser")
	if user == "" || newUser == "" {
		writeError(w, "rename_mysql_user", "Missing required parameters: user and newuser.")
		return
	}
	if s.db == nil {
		s.dbOfflineWHM(w, "rename_mysql_user")
		return
	}
	if err := s.db.RenameUser(r.Context(), "", user, newUser); err != nil {
		writeError(w, "rename_mysql_user", err.Error())
		return
	}
	writeSuccessReason(w, "rename_mysql_user", "The database user was renamed.", nil, "")
}

// --- UAPI Mysql module ---

func (s *Server) uapiMysqlOwner(user string) string { return user }

func (s *Server) uapiMysqlCreateDatabase(w http.ResponseWriter, r *http.Request, account Account, user string) {
	name := dbhost.PrefixedName(user, r.URL.Query().Get("name"))
	if s.db == nil {
		s.dbOfflineUAPI(w, "create_database")
		return
	}
	if err := s.db.CreateDatabase(r.Context(), user, name); err != nil {
		writeUAPIError(w, "Mysql", "create_database", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Mysql", "create_database", name)
}

func (s *Server) uapiMysqlDeleteDatabase(w http.ResponseWriter, r *http.Request, account Account, user string) {
	name := r.URL.Query().Get("name")
	if s.db == nil {
		s.dbOfflineUAPI(w, "delete_database")
		return
	}
	if err := s.db.DropDatabase(r.Context(), user, name); err != nil {
		writeUAPIError(w, "Mysql", "delete_database", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Mysql", "delete_database", name)
}

func (s *Server) uapiMysqlListDatabases(w http.ResponseWriter, r *http.Request, account Account, user string) {
	if s.db == nil {
		s.dbOfflineUAPI(w, "list_databases")
		return
	}
	dbs, err := s.db.ListDatabases(r.Context(), user)
	if err != nil {
		writeUAPIError(w, "Mysql", "list_databases", []string{err.Error()})
		return
	}
	names := make([]string, 0, len(dbs))
	for _, d := range dbs {
		names = append(names, d.Name)
	}
	writeUAPISuccess(w, "Mysql", "list_databases", names)
}

func (s *Server) uapiMysqlCreateUser(w http.ResponseWriter, r *http.Request, account Account, user string) {
	q := r.URL.Query()
	name := dbhost.PrefixedName(user, q.Get("name"))
	password := q.Get("password")
	if password == "" {
		writeUAPIError(w, "Mysql", "create_user", []string{"The password is required."})
		return
	}
	if s.db == nil {
		s.dbOfflineUAPI(w, "create_user")
		return
	}
	if err := s.db.CreateUser(r.Context(), user, name, password); err != nil {
		writeUAPIError(w, "Mysql", "create_user", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Mysql", "create_user", name)
}

func (s *Server) uapiMysqlDeleteUser(w http.ResponseWriter, r *http.Request, account Account, user string) {
	name := r.URL.Query().Get("name")
	if s.db == nil {
		s.dbOfflineUAPI(w, "delete_user")
		return
	}
	if err := s.db.DropUser(r.Context(), user, name); err != nil {
		writeUAPIError(w, "Mysql", "delete_user", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Mysql", "delete_user", name)
}

func (s *Server) uapiMysqlListUsers(w http.ResponseWriter, r *http.Request, account Account, user string) {
	if s.db == nil {
		s.dbOfflineUAPI(w, "list_users")
		return
	}
	users, err := s.db.ListUsers(r.Context(), user)
	if err != nil {
		writeUAPIError(w, "Mysql", "list_users", []string{err.Error()})
		return
	}
	names := make([]string, 0, len(users))
	for _, u := range users {
		names = append(names, u.Name)
	}
	writeUAPISuccess(w, "Mysql", "list_users", names)
}

func (s *Server) uapiMysqlSetPassword(w http.ResponseWriter, r *http.Request, account Account, user string) {
	q := r.URL.Query()
	name, password := q.Get("user"), q.Get("password")
	if name == "" || password == "" {
		writeUAPIError(w, "Mysql", "set_password", []string{"The user and password parameters are required."})
		return
	}
	if s.db == nil {
		s.dbOfflineUAPI(w, "set_password")
		return
	}
	if err := s.db.SetPassword(r.Context(), user, name, password); err != nil {
		writeUAPIError(w, "Mysql", "set_password", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Mysql", "set_password", nil)
}

func (s *Server) uapiMysqlSetPrivileges(w http.ResponseWriter, r *http.Request, account Account, user string) {
	q := r.URL.Query()
	dbUser, db := q.Get("user"), q.Get("database")
	privs, err := dbhost.ParsePrivileges(q.Get("privileges"))
	if err != nil {
		writeUAPIError(w, "Mysql", "set_privileges_on_database", []string{err.Error()})
		return
	}
	if s.db == nil {
		s.dbOfflineUAPI(w, "set_privileges_on_database")
		return
	}
	if err := s.db.SetPrivileges(r.Context(), user, dbUser, db, privs); err != nil {
		writeUAPIError(w, "Mysql", "set_privileges_on_database", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Mysql", "set_privileges_on_database", nil)
}

func (s *Server) uapiMysqlGetPrivileges(w http.ResponseWriter, r *http.Request, account Account, user string) {
	dbUser, db := r.URL.Query().Get("user"), r.URL.Query().Get("database")
	if s.db == nil {
		s.dbOfflineUAPI(w, "get_privileges_on_database")
		return
	}
	dbs, err := s.db.ListDatabases(r.Context(), user)
	if err != nil {
		writeUAPIError(w, "Mysql", "get_privileges_on_database", []string{err.Error()})
		return
	}
	for _, d := range dbs {
		if d.Name == db {
			for _, u := range d.Users {
				if u == dbUser {
					// Registry tracks association; privilege detail comes
					// from SHOW GRANTS in a later batch — report membership
					// truthfully rather than inventing a privilege list.
					writeUAPISuccess(w, "Mysql", "get_privileges_on_database", []string{"granted"})
					return
				}
			}
			writeUAPIError(w, "Mysql", "get_privileges_on_database", []string{"The user has no privileges on the database."})
			return
		}
	}
	writeUAPIError(w, "Mysql", "get_privileges_on_database", []string{"The database does not exist."})
}

func (s *Server) uapiMysqlRevokeAccess(w http.ResponseWriter, r *http.Request, account Account, user string) {
	dbUser, db := r.URL.Query().Get("user"), r.URL.Query().Get("database")
	if s.db == nil {
		s.dbOfflineUAPI(w, "revoke_access_to_database")
		return
	}
	if err := s.db.RevokeAccess(r.Context(), user, dbUser, db); err != nil {
		writeUAPIError(w, "Mysql", "revoke_access_to_database", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Mysql", "revoke_access_to_database", nil)
}

func (s *Server) uapiMysqlRenameUser(w http.ResponseWriter, r *http.Request, account Account, user string) {
	name := r.URL.Query().Get("name")
	newName := dbhost.PrefixedName(user, r.URL.Query().Get("newname"))
	if s.db == nil {
		s.dbOfflineUAPI(w, "rename_user")
		return
	}
	if err := s.db.RenameUser(r.Context(), user, name, newName); err != nil {
		writeUAPIError(w, "Mysql", "rename_user", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Mysql", "rename_user", newName)
}

func (s *Server) uapiMysqlSetupDbAndUser(w http.ResponseWriter, r *http.Request, account Account, user string) {
	q := r.URL.Query()
	suffix, password := q.Get("db"), q.Get("password")
	if suffix == "" || password == "" {
		writeUAPIError(w, "Mysql", "setup_db_and_user", []string{"The db and password parameters are required."})
		return
	}
	if s.db == nil {
		s.dbOfflineUAPI(w, "setup_db_and_user")
		return
	}
	dbName := dbhost.PrefixedName(user, suffix)
	userName := dbhost.PrefixedName(user, suffix)
	if err := s.db.CreateDatabase(r.Context(), user, dbName); err != nil {
		writeUAPIError(w, "Mysql", "setup_db_and_user", []string{err.Error()})
		return
	}
	if err := s.db.CreateUser(r.Context(), user, userName, password); err != nil {
		writeUAPIError(w, "Mysql", "setup_db_and_user", []string{err.Error()})
		return
	}
	if err := s.db.SetPrivileges(r.Context(), user, userName, dbName, []string{"ALL PRIVILEGES"}); err != nil {
		writeUAPIError(w, "Mysql", "setup_db_and_user", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Mysql", "setup_db_and_user", map[string]any{"database": dbName, "user": userName})
}

func (s *Server) uapiMysqlGetRestrictions(w http.ResponseWriter, r *http.Request, account Account, user string) {
	writeUAPISuccess(w, "Mysql", "get_restrictions", map[string]any{
		"database_prefix":     user + "_",
		"max_database_length": dbhost.MaxDatabaseLen,
		"max_user_length":     dbhost.MaxUserLen,
	})
}

func (s *Server) uapiMysqlGetServerInformation(w http.ResponseWriter, r *http.Request, account Account, user string) {
	if s.db == nil {
		s.dbOfflineUAPI(w, "get_server_information")
		return
	}
	v, err := s.db.Probe(r.Context())
	if err != nil {
		writeUAPIError(w, "Mysql", "get_server_information", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Mysql", "get_server_information", map[string]any{
		"version":        v,
		"is_remote":      0,
		"server_version": strings.TrimSpace(v),
	})
}
