// Package whmtest is a fake WHM API 1 for tests: an HTTPS server with a
// self-signed certificate that answers, in the shapes cPanel documents,
// listaccts, domainuserdata, php_get_vhost_versions, uapi_cpanel (Mysql
// list_databases and list_users), importsshkey, authorizesshkey,
// deletesshkey and listsshkeys, and refuses a wrong login. Only tests
// import it.
package whmtest

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"

	"sifruno/internal/whmsource"
)

// Key is one of root's SSH keys as the fake keeps it.
type Key struct {
	Text       string
	Authorized bool
	Options    string
}

// Server is the fake WHM.
type Server struct {
	*httptest.Server
	Token    string
	Password string

	mu sync.Mutex
	// Calls are the functions called, in order, with a login the fake took.
	Calls []string
	// Keys are root's keys by file name (<name>.pub).
	Keys map[string]*Key
	// Broken, when set, is printed instead of JSON for every call, as a
	// cPanel whose own processes are hijacked might.
	Broken string
	// Failing names functions that answer metadata.result 0.
	Failing map[string]string
	// Seen are the Authorization headers received, to check what was sent.
	Seen []string
}

// The fake's one account.
const (
	User   = "shopone"
	Domain = "shop.example.test"
)

// New starts the fake with a token and a password for root.
func New() *Server {
	whmsource.AllowLoopbackForTesting()
	s := &Server{Token: "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", Password: "fixture root password", Keys: map[string]*Key{}, Failing: map[string]string{}}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	return s
}

// Address is the fake's address for whmsource.
func (s *Server) Address() whmsource.Address {
	host, port, _ := net.SplitHostPort(s.Listener.Addr().String())
	n, _ := strconv.Atoi(port)
	return whmsource.Address{Host: host, Port: n}
}

// Fingerprint is the fake's certificate fingerprint as whmsource shows it.
func (s *Server) Fingerprint() string { return whmsource.Fingerprint(s.Certificate().Raw) }

// CallList copies Calls.
func (s *Server) CallList() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.Calls...)
}

// Headers copies Seen.
func (s *Server) Headers() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.Seen...)
}

// Authorized reports whether root's keys hold this text, authorized.
func (s *Server) Authorized(text string) (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.Keys {
		if k.Text == text && k.Authorized {
			return true, k.Options
		}
	}
	return false, ""
}

func (s *Server) loginOK(header string) bool {
	if header == "whm root:"+s.Token {
		return true
	}
	if raw, ok := strings.CutPrefix(header, "Basic "); ok {
		decoded, err := base64.StdEncoding.DecodeString(raw)
		return err == nil && string(decoded) == "root:"+s.Password
	}
	return false
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Seen = append(s.Seen, r.Header.Get("Authorization"))
	function, ok := strings.CutPrefix(r.URL.Path, "/json-api/")
	if !ok || r.URL.Query().Get("api.version") != "1" {
		http.NotFound(w, r)
		return
	}
	if !s.loginOK(r.Header.Get("Authorization")) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Access denied"))
		return
	}
	s.Calls = append(s.Calls, function)
	if s.Broken != "" {
		_, _ = w.Write([]byte(s.Broken))
		return
	}
	if reason, failing := s.Failing[function]; failing {
		answer(w, function, 0, reason, nil)
		return
	}
	q := r.URL.Query()
	switch function {
	case "listaccts":
		acct := []map[string]any{{"user": User, "domain": Domain, "diskused": "40M", "disklimit": "unlimited", "suspended": 0, "owner": "root"}}
		if q.Get("search") != "" && (q.Get("searchtype") != "user" || q.Get("searchmethod") != "exact" || q.Get("search") != User) {
			acct = []map[string]any{}
		}
		answer(w, function, 1, "OK", map[string]any{"acct": acct})
	case "domainuserdata":
		if q.Get("domain") != Domain {
			answer(w, function, 0, "No userdata for that domain", nil)
			return
		}
		answer(w, function, 1, "OK", map[string]any{"userdata": map[string]any{"user": User, "homedir": "/home/" + User, "documentroot": "/home/" + User + "/public_html", "servername": Domain, "serveralias": "www." + Domain}})
	case "php_get_vhost_versions":
		answer(w, function, 1, "OK", map[string]any{"versions": []map[string]any{
			{"vhost": Domain, "account": User, "version": "ea-php82"},
			{"vhost": "other.example.test", "account": "other", "version": "ea-php74"},
		}})
	case "uapi_cpanel":
		if q.Get("cpanel.user") != User || q.Get("cpanel.module") != "Mysql" {
			answer(w, function, 0, "Unknown user or module", nil)
			return
		}
		var data any
		switch q.Get("cpanel.function") {
		case "list_databases":
			data = []map[string]any{{"database": User + "_wp", "disk_usage": 0, "users": []string{User + "_wpu"}}}
		case "list_users":
			data = []map[string]any{{"user": User + "_wpu", "shortuser": "wpu", "databases": []string{User + "_wp"}}}
		default:
			answer(w, function, 0, "Unknown function", nil)
			return
		}
		answer(w, function, 1, "OK", map[string]any{"uapi": map[string]any{"data": data, "status": 1, "errors": nil, "messages": nil, "warnings": nil, "metadata": map[string]any{}}})
	case "importsshkey":
		name, key := q.Get("name"), q.Get("key")
		if name == "" || key == "" || strings.Contains(name, "/") {
			answer(w, function, 0, "Invalid key or name", nil)
			return
		}
		s.Keys[name+".pub"] = &Key{Text: key}
		answer(w, function, 1, "Key imported", nil)
	case "authorizesshkey":
		text, file := q.Get("text"), q.Get("file")
		k := s.Keys[file]
		if text != "" {
			if k == nil {
				k = &Key{Text: text}
				s.Keys[file] = k
			}
			k.Text = text
		}
		if k == nil {
			answer(w, function, 0, "The key file does not exist", nil)
			return
		}
		k.Authorized, k.Options = q.Get("authorize") == "1", q.Get("options")
		authorized := 0
		if k.Authorized {
			authorized = 1
		}
		answer(w, function, 1, "OK", map[string]any{"file": file, "authorized": authorized})
	case "deletesshkey":
		file := q.Get("file")
		k := s.Keys[file]
		if k == nil {
			answer(w, function, 0, "The key file does not exist", nil)
			return
		}
		// With leave_authorized=1, the default, the line would stay in
		// authorized_keys; the fake keeps such a key listed.
		if q.Get("leave_authorized") == "0" || !k.Authorized {
			delete(s.Keys, file)
		}
		answer(w, function, 1, "OK", map[string]any{"file": "/root/.ssh/" + file})
	case "listsshkeys":
		keys := []map[string]any{}
		for file, k := range s.Keys {
			authorized := 0
			if k.Authorized {
				authorized = 1
			}
			keys = append(keys, map[string]any{"file": file, "authorized": authorized, "text": k.Text, "comment": "", "private": 0})
		}
		answer(w, function, 1, "OK", map[string]any{"keys": keys})
	default:
		answer(w, function, 0, "Unknown function "+function, nil)
	}
}

func answer(w http.ResponseWriter, function string, result int, reason string, data any) {
	body := map[string]any{"metadata": map[string]any{"command": function, "version": 1, "result": result, "reason": reason}}
	if data != nil {
		body["data"] = data
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}
