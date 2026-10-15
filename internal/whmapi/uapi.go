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
	"DomainInfo": {
		"list_domains":       (*Server).uapiListDomains,
		"primary_domain":     (*Server).uapiPrimaryDomain,
		"single_domain_data": (*Server).uapiSingleDomainData,
		"domains_data":       (*Server).uapiDomainsData,
	},
	"ServerInformation": {
		"get_information": (*Server).uapiServerInformation,
	},
}

// accountScoped lists functions that require a `user` context. Root API
// tokens pass the account explicitly (`?user=`); per-account token scoping
// lands with pr-access roles.
var uapiAccountScoped = map[string]bool{
	"DomainInfo::list_domains":       true,
	"DomainInfo::primary_domain":     true,
	"DomainInfo::single_domain_data": true,
	"DomainInfo::domains_data":       true,
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
	user := r.URL.Query().Get("user")
	var account Account
	if uapiAccountScoped[module+"::"+fn] {
		if user == "" {
			writeUAPIError(w, module, fn, []string{"The “user” parameter is required."})
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
