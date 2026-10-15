package whmapi

import (
	"net/http"
	"strings"
)

// Backend supplies the data behind the read-only WHM API 1 endpoints.
// Production wiring (hostaccounts/hostweb adapters) lands in the
// pr-api-contract lifecycle batches; a nil backend mounts nothing.
type Backend interface {
	// Version is the advertised build, e.g. "11.138.0.11".
	Version() string
	// ListPackages returns packages with the observed WHM key set
	// (BWLIMIT, QUOTA, MAXADDON, FEATURELIST, CPMOD, ...); values are
	// strings because the reference serializes limits as "unlimited".
	ListPackages() []Package
	// ListAccounts returns account records with the observed listaccts
	// field set.
	ListAccounts() []Account
}

// Package mirrors an entry of the listpkgs data.pkg array (observed schema,
// envelopes-and-layout doc §2).
type Package map[string]string

// Account mirrors one listaccts record. Field names, string-vs-number typing
// and presence follow the observed 138 capture (lifecycle-capture doc §3).
type Account struct {
	User               string   `json:"user"`
	UID                string   `json:"uid"`
	Domain             string   `json:"domain"`
	IP                 string   `json:"ip"`
	IPv6               []string `json:"ipv6"`
	Owner              string   `json:"owner"`
	Plan               string   `json:"plan"`
	Theme              string   `json:"theme"`
	Shell              string   `json:"shell"`
	Partition          string   `json:"partition"`
	DiskUsed           string   `json:"diskused"`
	DiskLimit          string   `json:"disklimit"`
	InodesUsed         int64    `json:"inodesused"`
	InodesLimit        string   `json:"inodeslimit"`
	Email              string   `json:"email"`
	StartDate          string   `json:"startdate"`
	UnixStartdate      int64    `json:"unix_startdate"`
	Suspended          int      `json:"suspended"`
	SuspendReason      string   `json:"suspendreason"`
	SuspendTime        int64    `json:"suspendtime"`
	IsLocked           int      `json:"is_locked"`
	Temporary          int      `json:"temporary"`
	IsTemporaryDomain  int      `json:"is_temporary_domain"`
	Backup             int      `json:"backup"`
	LegacyBackup       int      `json:"legacy_backup"`
	HasBackup          int      `json:"has_backup"`
	MailboxFormat      string   `json:"mailbox_format"`
	MaxPop             string   `json:"maxpop"`
	MaxFTP             string   `json:"maxftp"`
	MaxSQL             string   `json:"maxsql"`
	MaxLst             string   `json:"maxlst"`
	MaxSub             string   `json:"maxsub"`
	MaxParked          string   `json:"maxparked"`
	MaxAddons          string   `json:"maxaddons"`
	MaxEmailacctQuota  string   `json:"max_emailacct_quota"`
	MaxEmailPerHour    string   `json:"max_email_per_hour"`
	MaxDeferFailPct    string   `json:"max_defer_fail_percentage"`
	MinDeferFailTrig   string   `json:"min_defer_fail_to_trigger_protection"`
	OutgoingMailHold   int      `json:"outgoing_mail_hold"`
	OutgoingMailSusp   int      `json:"outgoing_mail_suspended"`
	ChildNodes         []string `json:"child_nodes"`
	StandaloneFeature  string   `json:"standalone_feature"`
	StandaloneFeatName string   `json:"standalone_feature_name"`
}

// Server serves the WHM API 1 JSON transport under /json-api/.
type Server struct {
	backend Backend
	auth    Authenticator
	mux     *http.ServeMux
}

// New mounts the compatibility transport. A nil Backend or Authenticator
// yields a Server that refuses every call with the observed access-denied
// shape; the surface never fabricates data.
func New(b Backend, a Authenticator) *Server {
	s := &Server{backend: b, auth: a, mux: http.NewServeMux()}
	s.mux.HandleFunc("/json-api/", s.serve)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// functions implemented in this batch. Read-only contract first, plus the
// three lifecycle mutations that map to the real account service
// (pr-api-contract scope 11). removeacct answers honestly unsupported until
// the account service grows a journaled delete.
var handlers = map[string]func(*Server, http.ResponseWriter, *http.Request){
	"version":       (*Server).handleVersion,
	"listpkgs":      (*Server).handleListPkgs,
	"listaccts":     (*Server).handleListAccts,
	"createacct":    (*Server).handleCreateAcct,
	"suspendacct":   (*Server).handleSuspendAcct,
	"unsuspendacct": (*Server).handleUnsuspendAcct,
	"removeacct":    (*Server).handleRemoveAcct,
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	fn := strings.Trim(strings.TrimPrefix(r.URL.Path, "/json-api/"), "/")
	h, ok := handlers[fn]
	if !ok {
		writeUnknownApp(w, fn)
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
	h(s, w, r)
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeSuccess(w, "version", map[string]string{"version": s.backend.Version()}, "")
}

func (s *Server) handleListPkgs(w http.ResponseWriter, _ *http.Request) {
	pkgs := s.backend.ListPackages()
	if pkgs == nil {
		pkgs = []Package{}
	}
	writeSuccess(w, "listpkgs", map[string]any{"pkg": pkgs}, "")
}

func (s *Server) handleListAccts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	search, searchType := q.Get("search"), q.Get("searchtype")
	accts := s.backend.ListAccounts()
	if search != "" && (searchType == "" || searchType == "user") {
		// Observed: exact user match filter; zero matches return success
		// with no data key (lifecycle-capture doc §1).
		filtered := make([]Account, 0, 1)
		for _, a := range accts {
			if a.User == search {
				filtered = append(filtered, a)
			}
		}
		accts = filtered
	}
	if len(accts) == 0 {
		writeSuccess(w, "listaccts", nil, "")
		return
	}
	writeSuccess(w, "listaccts", map[string]any{"acct": accts}, "")
}
