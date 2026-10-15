package whmapi

import (
	"net/http"
	"strings"
)

// Forwarders (mail.lifecycle batch 2): the valiases-format store.

func (s *Server) uapiEmailAddForwarder(w http.ResponseWriter, r *http.Request, account Account, user string) {
	q := r.URL.Query()
	email, domain, dest := q.Get("email"), q.Get("domain"), q.Get("fwdfwd")
	if domain == "" {
		domain = account.Domain
	}
	if email == "" || dest == "" {
		writeUAPIError(w, "Email", "add_forwarder", []string{"The email and fwdfwd destination parameters are required."})
		return
	}
	if s.mail == nil {
		s.mailUnavailable(w, "add_forwarder")
		return
	}
	if err := s.mail.AddForwarder(r.Context(), user, domain, email, dest); err != nil {
		writeUAPIError(w, "Email", "add_forwarder", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Email", "add_forwarder", map[string]any{"email": email + "@" + domain, "dest": dest})
}

func (s *Server) uapiEmailDeleteForwarder(w http.ResponseWriter, r *http.Request, account Account, user string) {
	q := r.URL.Query()
	email, dest := q.Get("email"), q.Get("dest")
	if email == "" || dest == "" {
		writeUAPIError(w, "Email", "delete_forwarder", []string{"The email and dest parameters are required."})
		return
	}
	localpart, domain := email, account.Domain
	if strings.Contains(email, "@") {
		p := strings.SplitN(email, "@", 2)
		localpart, domain = p[0], p[1]
	}
	if s.mail == nil {
		s.mailUnavailable(w, "delete_forwarder")
		return
	}
	if err := s.mail.DeleteForwarder(r.Context(), user, domain, localpart, dest); err != nil {
		writeUAPIError(w, "Email", "delete_forwarder", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Email", "delete_forwarder", nil)
}

func (s *Server) uapiEmailListForwarders(w http.ResponseWriter, r *http.Request, account Account, user string) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		domain = account.Domain
	}
	if s.mail == nil {
		s.mailUnavailable(w, "list_forwarders")
		return
	}
	fwd, err := s.mail.ListForwarders(r.Context(), user, domain)
	if err != nil {
		writeUAPIError(w, "Email", "list_forwarders", []string{err.Error()})
		return
	}
	out := make([]map[string]any, 0, len(fwd))
	for _, f := range fwd {
		out = append(out, map[string]any{
			"dest": f.Dest, "forward": f.Dest, "email": f.Localpart + "@" + f.Domain,
			"localpart": f.Localpart, "domain": f.Domain,
		})
	}
	writeUAPISuccess(w, "Email", "list_forwarders", out)
}

func (s *Server) uapiEmailCountForwarders(w http.ResponseWriter, r *http.Request, account Account, user string) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		domain = account.Domain
	}
	if s.mail == nil {
		s.mailUnavailable(w, "count_forwarders")
		return
	}
	n, err := s.mail.CountForwarders(r.Context(), user, domain)
	if err != nil {
		writeUAPIError(w, "Email", "count_forwarders", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Email", "count_forwarders", n)
}

func (s *Server) uapiEmailAddDomainForwarder(w http.ResponseWriter, r *http.Request, account Account, user string) {
	q := r.URL.Query()
	src, dest := q.Get("domain"), q.Get("todomain")
	if src == "" {
		src = account.Domain
	}
	if dest == "" {
		writeUAPIError(w, "Email", "add_domain_forwarder", []string{"The todomain parameter is required."})
		return
	}
	if s.mail == nil {
		s.mailUnavailable(w, "add_domain_forwarder")
		return
	}
	if err := s.mail.AddDomainForwarder(r.Context(), user, src, dest); err != nil {
		writeUAPIError(w, "Email", "add_domain_forwarder", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Email", "add_domain_forwarder", map[string]any{"domain": src, "todomain": dest})
}

func (s *Server) uapiEmailDeleteDomainForwarder(w http.ResponseWriter, r *http.Request, account Account, user string) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		domain = account.Domain
	}
	if s.mail == nil {
		s.mailUnavailable(w, "delete_domain_forwarder")
		return
	}
	if err := s.mail.DeleteDomainForwarder(r.Context(), user, domain); err != nil {
		writeUAPIError(w, "Email", "delete_domain_forwarder", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Email", "delete_domain_forwarder", nil)
}

func (s *Server) uapiEmailListDomainForwarders(w http.ResponseWriter, r *http.Request, account Account, user string) {
	if s.mail == nil {
		s.mailUnavailable(w, "list_domain_forwarders")
		return
	}
	m, err := s.mail.ListDomainForwarders(r.Context(), user)
	if err != nil {
		writeUAPIError(w, "Email", "list_domain_forwarders", []string{err.Error()})
		return
	}
	out := make([]map[string]any, 0, len(m))
	for src, dest := range m {
		out = append(out, map[string]any{"domain": src, "todomain": dest})
	}
	writeUAPISuccess(w, "Email", "list_domain_forwarders", out)
}

func (s *Server) uapiEmailSetDefaultAddress(w http.ResponseWriter, r *http.Request, account Account, user string) {
	q := r.URL.Query()
	domain, dest := q.Get("domain"), q.Get("fwdopt")
	switch q.Get("fwdopt") {
	case "fail":
		dest = ":fail:"
	case "blackhole":
		dest = ":blackhole:"
	case "fwd":
		dest = q.Get("fwdfwd")
	}
	if domain == "" {
		domain = account.Domain
	}
	if dest == "" {
		writeUAPIError(w, "Email", "set_default_address", []string{"A destination (fwdopt=fail|blackhole|fwd with fwdfwd) is required."})
		return
	}
	if s.mail == nil {
		s.mailUnavailable(w, "set_default_address")
		return
	}
	if err := s.mail.SetDefaultAddress(r.Context(), user, domain, dest); err != nil {
		writeUAPIError(w, "Email", "set_default_address", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Email", "set_default_address", nil)
}

func (s *Server) uapiEmailListDefaultAddress(w http.ResponseWriter, r *http.Request, account Account, user string) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		domain = account.Domain
	}
	if s.mail == nil {
		s.mailUnavailable(w, "list_default_address")
		return
	}
	dest, err := s.mail.ListDefaultAddress(r.Context(), user, domain)
	if err != nil {
		writeUAPIError(w, "Email", "list_default_address", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Email", "list_default_address", []map[string]any{{"domain": domain, "dest": dest}})
}
