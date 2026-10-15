package whmapi

import (
	"fmt"
	"net/http"
	"strings"
)

// UAPI (apiversion 3) surface. Envelope shape captured on the licensed 138
// reference (batch 3): result carries data/errors/warnings/status/messages/
// metadata; `status` — not `result` — is the success flag.

type uapiResult struct {
	Data     any            `json:"data"`
	Errors   any            `json:"errors"`
	Warnings any            `json:"warnings"`
	Status   int            `json:"status"`
	Messages any            `json:"messages"`
	Metadata map[string]any `json:"metadata"`
}

type uapiEnvelope struct {
	APIVersion int        `json:"apiversion"`
	Module     string     `json:"module"`
	Func       string     `json:"func"`
	Result     uapiResult `json:"result"`
}

func writeUAPISuccess(w http.ResponseWriter, module, fn string, data any) {
	writeJSON(w, http.StatusOK, uapiEnvelope{
		APIVersion: 3, Module: module, Func: fn,
		Result: uapiResult{Data: data, Errors: nil, Warnings: nil, Status: 1, Messages: nil, Metadata: map[string]any{}},
	})
}

func writeUAPIError(w http.ResponseWriter, module, fn string, errors []string) {
	writeJSON(w, http.StatusOK, uapiEnvelope{
		APIVersion: 3, Module: module, Func: fn,
		Result: uapiResult{Data: nil, Errors: errors, Warnings: nil, Status: 0, Messages: nil, Metadata: map[string]any{}},
	})
}

// uapiHandler resolves one UAPI call. account is the account record when the
// function is account-scoped (zero value otherwise); user is the requested
// account username ("" when absent).
type uapiHandler func(s *Server, w http.ResponseWriter, r *http.Request, account Account, user string)

var uapiModules = map[string]map[string]uapiHandler{
	"SSL": {
		"install_ssl":     (*Server).uapiSSLInstall,
		"list_certs":      (*Server).uapiSSLListCerts,
		"fetch_cert_info": (*Server).uapiSSLFetchCertInfo,
		"delete_ssl":      (*Server).uapiSSLDelete,
	},
	"DomainInfo": {
		"list_domains":       (*Server).uapiListDomains,
		"primary_domain":     (*Server).uapiPrimaryDomain,
		"single_domain_data": (*Server).uapiSingleDomainData,
		"domains_data":       (*Server).uapiDomainsData,
	},
	"Email": {
		"add_pop":                 (*Server).uapiEmailAddPop,
		"delete_pop":              (*Server).uapiEmailDeletePop,
		"list_pops":               (*Server).uapiEmailListPops,
		"list_pops_with_disk":     (*Server).uapiEmailListPopsWithDisk,
		"passwd_pop":              (*Server).uapiEmailPasswdPop,
		"edit_pop_quota":          (*Server).uapiEmailEditPopQuota,
		"get_pop_quota":           (*Server).uapiEmailGetPopQuota,
		"count_pops":              (*Server).uapiEmailCountPops,
		"verify_password":         (*Server).uapiEmailVerifyPassword,
		"list_mail_domains":       (*Server).uapiEmailListMailDomains,
		"get_default_email_quota": (*Server).uapiEmailGetDefaultQuota,
		"get_max_email_quota":     (*Server).uapiEmailGetMaxQuota,
		"add_forwarder":           (*Server).uapiEmailAddForwarder,
		"delete_forwarder":        (*Server).uapiEmailDeleteForwarder,
		"list_forwarders":         (*Server).uapiEmailListForwarders,
		"count_forwarders":        (*Server).uapiEmailCountForwarders,
		"add_domain_forwarder":    (*Server).uapiEmailAddDomainForwarder,
		"delete_domain_forwarder": (*Server).uapiEmailDeleteDomainForwarder,
		"list_domain_forwarders":  (*Server).uapiEmailListDomainForwarders,
		"set_default_address":     (*Server).uapiEmailSetDefaultAddress,
		"suspend_incoming":        (*Server).uapiEmailSuspendIncoming,
		"unsuspend_incoming":      (*Server).uapiEmailUnsuspendIncoming,
		"suspend_outgoing":        (*Server).uapiEmailSuspendOutgoing,
		"unsuspend_outgoing":      (*Server).uapiEmailUnsuspendOutgoing,
		"suspend_login":           (*Server).uapiEmailSuspendLogin,
		"unsuspend_login":         (*Server).uapiEmailUnsuspendLogin,
		"add_auto_responder":      (*Server).uapiEmailAddAutoResponder,
		"get_auto_responder":      (*Server).uapiEmailGetAutoResponder,
		"list_auto_responders":    (*Server).uapiEmailListAutoResponders,
		"count_auto_responders":   (*Server).uapiEmailCountAutoResponders,
		"delete_auto_responder":   (*Server).uapiEmailDeleteAutoResponder,
		"list_mxs":                (*Server).uapiEmailListMXs,
		"add_mx":                  (*Server).uapiEmailAddMX,
		"delete_mx":               (*Server).uapiEmailDeleteMX,
		"change_mx":               (*Server).uapiEmailChangeMX,
		"list_default_address":    (*Server).uapiEmailListDefaultAddress,
	},
	"Mysql": {
		"create_database":            (*Server).uapiMysqlCreateDatabase,
		"delete_database":            (*Server).uapiMysqlDeleteDatabase,
		"list_databases":             (*Server).uapiMysqlListDatabases,
		"create_user":                (*Server).uapiMysqlCreateUser,
		"delete_user":                (*Server).uapiMysqlDeleteUser,
		"list_users":                 (*Server).uapiMysqlListUsers,
		"set_password":               (*Server).uapiMysqlSetPassword,
		"set_privileges_on_database": (*Server).uapiMysqlSetPrivileges,
		"get_privileges_on_database": (*Server).uapiMysqlGetPrivileges,
		"rename_database":            (*Server).uapiMysqlRenameDatabase,
		"add_host":                   (*Server).uapiMysqlAddHost,
		"delete_host":                (*Server).uapiMysqlDeleteHost,
		"list_hosts":                 (*Server).uapiMysqlListHosts,
		"revoke_access_to_database":  (*Server).uapiMysqlRevokeAccess,
		"rename_user":                (*Server).uapiMysqlRenameUser,
		"setup_db_and_user":          (*Server).uapiMysqlSetupDbAndUser,
		"get_restrictions":           (*Server).uapiMysqlGetRestrictions,
		"get_server_information":     (*Server).uapiMysqlGetServerInformation,
	},
	"ServerInformation": {
		"get_information": (*Server).uapiServerInformation,
	},
}

// accountScoped lists functions that require a `user` context. Root API
// tokens pass the account explicitly (`?user=`); per-account token scoping
// lands with pr-access roles.
var uapiAccountScoped = map[string]bool{
	"Email::add_pop":                    true,
	"Email::delete_pop":                 true,
	"Email::list_pops":                  true,
	"Email::list_pops_with_disk":        true,
	"Email::passwd_pop":                 true,
	"Email::edit_pop_quota":             true,
	"Email::get_pop_quota":              true,
	"Email::count_pops":                 true,
	"Email::verify_password":            true,
	"Email::list_mail_domains":          true,
	"Email::get_default_email_quota":    true,
	"Email::get_max_email_quota":        true,
	"Email::add_forwarder":              true,
	"Email::delete_forwarder":           true,
	"Email::list_forwarders":            true,
	"Email::count_forwarders":           true,
	"Email::add_domain_forwarder":       true,
	"Email::delete_domain_forwarder":    true,
	"Email::list_domain_forwarders":     true,
	"Email::set_default_address":        true,
	"Email::list_default_address":       true,
	"Mysql::create_database":            true,
	"Mysql::delete_database":            true,
	"Mysql::list_databases":             true,
	"Mysql::create_user":                true,
	"Mysql::delete_user":                true,
	"Mysql::list_users":                 true,
	"Mysql::set_password":               true,
	"Mysql::set_privileges_on_database": true,
	"Mysql::get_privileges_on_database": true,
	"Mysql::revoke_access_to_database":  true,
	"Mysql::rename_user":                true,
	"Mysql::setup_db_and_user":          true,
	"Mysql::get_restrictions":           true,
	"Mysql::get_server_information":     true,
	"Mysql::rename_database":            true,
	"Mysql::add_host":                   true,
	"Mysql::delete_host":                true,
	"Mysql::list_hosts":                 true,
	"Email::suspend_incoming":           true,
	"Email::unsuspend_incoming":         true,
	"Email::suspend_outgoing":           true,
	"Email::unsuspend_outgoing":         true,
	"Email::suspend_login":              true,
	"Email::unsuspend_login":            true,
	"Email::add_auto_responder":         true,
	"Email::get_auto_responder":         true,
	"Email::list_auto_responders":       true,
	"Email::count_auto_responders":      true,
	"Email::delete_auto_responder":      true,
	"Email::list_mxs":                   true,
	"Email::add_mx":                     true,
	"Email::delete_mx":                  true,
	"Email::change_mx":                  true,
	"SSL::install_ssl":                  true,
	"SSL::list_certs":                   true,
	"SSL::fetch_cert_info":              true,
	"SSL::delete_ssl":                   true,
	"DomainInfo::list_domains":          true,
	"DomainInfo::primary_domain":        true,
	"DomainInfo::single_domain_data":    true,
	"DomainInfo::domains_data":          true,
}

// uapiOwnUserParam lists account-scoped functions that take their own
// `user` argument (the database user). For these, only `cpanel.user` may
// carry the account context.
var uapiOwnUserParam = map[string]bool{
	"Mysql::set_password":               true,
	"Mysql::set_privileges_on_database": true,
	"Mysql::get_privileges_on_database": true,
	"Mysql::revoke_access_to_database":  true,
}

func (s *Server) serveUAPI(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/execute/"), "/"), "/")
	if len(parts) != 2 {
		writeUAPIError(w, "", "", []string{"UAPI calls use the /execute/<module>/<function> path form."})
		return
	}
	module, fn := parts[0], parts[1]
	funcs, ok := uapiModules[module]
	if !ok {
		// The reference leaks a Perl ModuleLoadError trace here; sifruno
		// returns a clean error instead (documented delta).
		writeUAPIError(w, module, fn, []string{fmt.Sprintf("The system failed to load the module “Cpanel::API::%s”.", module)})
		return
	}
	handler, ok := funcs[fn]
	if !ok {
		writeUAPIError(w, module, fn, []string{fmt.Sprintf("Unknown function “%s” for module “%s” in API version 3.", fn, module)})
		return
	}
	if !s.authorized(r) {
		writeAccessDenied(w)
		return
	}
	if s.backend == nil {
		writeAccessDenied(w)
		return
	}
	// Account scoping: `cpanel.user` (the reference's WHM passthrough name)
	// wins; `user` is the fallback for functions that do not declare their
	// own user argument. This prevents the collision on Mysql functions
	// whose own parameter is named `user`.
	q := r.URL.Query()
	user := q.Get("cpanel.user")
	if user == "" && !uapiOwnUserParam[module+"::"+fn] {
		user = q.Get("user")
	}
	var account Account
	if uapiAccountScoped[module+"::"+fn] {
		if user == "" {
			writeUAPIError(w, module, fn, []string{"The “cpanel.user” parameter is required for root-token calls."})
			return
		}
		found := false
		for _, a := range s.backend.ListAccounts() {
			if a.User == user {
				account, found = a, true
				break
			}
		}
		if !found {
			writeUAPIError(w, module, fn, []string{fmt.Sprintf("The account “%s” does not exist.", user)})
			return
		}
	}
	handler(s, w, r, account, user)
}

// mainDomainData mirrors the observed single_domain_data vhost record for
// the account's main domain. Runtime-specific keys the backend does not
// implement yet (phpversion, customlog, scriptalias) are omitted rather
// than fabricated — see the batch-7 doc.
func mainDomainData(a Account) map[string]any {
	return map[string]any{
		"port":                  "80",
		"user":                  a.User,
		"serveralias":           "mail." + a.Domain + " www." + a.Domain,
		"homedir":               "/home/" + a.User,
		"type":                  "main_domain",
		"servername":            a.Domain,
		"hascgi":                "1",
		"owner":                 a.User,
		"domain":                a.Domain,
		"ip":                    a.IP,
		"usecanonicalname":      "Off",
		"status":                "not redirected",
		"group":                 a.User,
		"documentroot":          "/home/" + a.User + "/public_html",
		"serveradmin":           "webmaster@" + a.Domain,
		"phpopenbasedirprotect": "1",
	}
}

func (s *Server) uapiListDomains(w http.ResponseWriter, _ *http.Request, account Account, _ string) {
	// hostaccounts tracks exactly one domain per account today; addon,
	// parked and subdomain lists are truthfully empty.
	writeUAPISuccess(w, "DomainInfo", "list_domains", map[string]any{
		"parked_domains": []string{},
		"sub_domains":    []string{},
		"main_domain":    account.Domain,
		"addon_domains":  []string{},
	})
}

func (s *Server) uapiPrimaryDomain(w http.ResponseWriter, _ *http.Request, account Account, _ string) {
	writeUAPISuccess(w, "DomainInfo", "primary_domain", map[string]any{"primary_domain": account.Domain})
}

func (s *Server) uapiSingleDomainData(w http.ResponseWriter, r *http.Request, account Account, _ string) {
	domain := r.URL.Query().Get("domain")
	if domain == "" || domain != account.Domain {
		writeUAPIError(w, "DomainInfo", "single_domain_data", []string{fmt.Sprintf("The domain “%s” does not exist on this account.", domain)})
		return
	}
	writeUAPISuccess(w, "DomainInfo", "single_domain_data", mainDomainData(account))
}

func (s *Server) uapiDomainsData(w http.ResponseWriter, _ *http.Request, account Account, _ string) {
	writeUAPISuccess(w, "DomainInfo", "domains_data", map[string]any{
		"main_domain":                           []any{mainDomainData(account)},
		"addon_domains":                         []any{},
		"parked_domains":                        []any{},
		"sub_domains":                           []any{},
		"main_domain_builtin_subdomain_aliases": []any{},
	})
}

func (s *Server) uapiServerInformation(w http.ResponseWriter, _ *http.Request, _ Account, _ string) {
	// Truthful service inventory: only services sifruno actually runs.
	// cPanel-daemon names are not claimed (no cpsrvd/exim/dovecot here).
	data := []any{
		map[string]any{"name": "sifruno", "type": "service", "status": 1, "value": "up"},
		map[string]any{"name": "sifruno_hostaccounts_broker", "type": "service", "status": 1, "value": "up"},
	}
	writeUAPISuccess(w, "ServerInformation", "get_information", data)
}
