package whmapi

import (
	"net/http"
	"strconv"
	"strings"

	"sifruno/internal/mailhost"
)

// Mail surface (pr-mail / mail.lifecycle obligation batch 1): mailbox
// lifecycle over the cPanel-style host layout (etc/<domain>/passwd+shadow,
// mail/<domain>/<localpart> Maildir). Fail-closed and ownership-fenced.

// SetMailService injects the mailbox service. Nil keeps the surface
// fail-closed.
func (s *Server) SetMailService(svc mailhost.Service) { s.mail = svc }

func (s *Server) mailUnavailable(w http.ResponseWriter, fn string) {
	writeUAPIError(w, "Email", fn, []string{"The mail service is currently unavailable."})
}

func (s *Server) uapiEmailAddPop(w http.ResponseWriter, r *http.Request, account Account, user string) {
	q := r.URL.Query()
	email, password := q.Get("email"), q.Get("password")
	domain := q.Get("domain")
	if email == "" || password == "" {
		writeUAPIError(w, "Email", "add_pop", []string{"The email and password parameters are required."})
		return
	}
	if domain == "" {
		domain = account.Domain
	}
	localpart := email
	if strings.Contains(email, "@") {
		parts := strings.SplitN(email, "@", 2)
		localpart, domain = parts[0], parts[1]
	}
	quota, _ := strconv.Atoi(q.Get("quota"))
	if s.mail == nil {
		s.mailUnavailable(w, "add_pop")
		return
	}
	m, err := s.mail.CreateMailbox(r.Context(), user, domain, localpart, password, quota)
	if err != nil {
		writeUAPIError(w, "Email", "add_pop", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Email", "add_pop", m.Email)
}

func (s *Server) uapiEmailDeletePop(w http.ResponseWriter, r *http.Request, account Account, user string) {
	email := r.URL.Query().Get("email")
	if s.mail == nil {
		s.mailUnavailable(w, "delete_pop")
		return
	}
	if err := s.mail.DeleteMailbox(r.Context(), user, email); err != nil {
		writeUAPIError(w, "Email", "delete_pop", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Email", "delete_pop", email)
}

func (s *Server) uapiEmailListPops(w http.ResponseWriter, r *http.Request, account Account, user string) {
	if s.mail == nil {
		s.mailUnavailable(w, "list_pops")
		return
	}
	boxes, err := s.mail.ListMailboxes(r.Context(), user)
	if err != nil {
		writeUAPIError(w, "Email", "list_pops", []string{err.Error()})
		return
	}
	emails := make([]string, 0, len(boxes))
	for _, b := range boxes {
		emails = append(emails, b.Email)
	}
	writeUAPISuccess(w, "Email", "list_pops", emails)
}

func (s *Server) uapiEmailListPopsWithDisk(w http.ResponseWriter, r *http.Request, account Account, user string) {
	if s.mail == nil {
		s.mailUnavailable(w, "list_pops_with_disk")
		return
	}
	boxes, err := s.mail.ListMailboxes(r.Context(), user)
	if err != nil {
		writeUAPIError(w, "Email", "list_pops_with_disk", []string{err.Error()})
		return
	}
	out := make([]map[string]any, 0, len(boxes))
	for _, b := range boxes {
		out = append(out, map[string]any{
			"email": b.Email, "login": b.Email, "domain": b.Domain,
			"localpart": b.Localpart, "quota_mib": b.QuotaMiB,
			// disk usage honest-zero until the disk-usage walker batch
			"diskused_bytes": 0,
		})
	}
	writeUAPISuccess(w, "Email", "list_pops_with_disk", out)
}

func (s *Server) uapiEmailPasswdPop(w http.ResponseWriter, r *http.Request, account Account, user string) {
	q := r.URL.Query()
	email, password := q.Get("email"), q.Get("password")
	if email == "" || password == "" {
		writeUAPIError(w, "Email", "passwd_pop", []string{"The email and password parameters are required."})
		return
	}
	if s.mail == nil {
		s.mailUnavailable(w, "passwd_pop")
		return
	}
	if err := s.mail.SetPassword(r.Context(), user, email, password); err != nil {
		writeUAPIError(w, "Email", "passwd_pop", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Email", "passwd_pop", nil)
}

func (s *Server) uapiEmailEditPopQuota(w http.ResponseWriter, r *http.Request, account Account, user string) {
	q := r.URL.Query()
	email := q.Get("email")
	quota, err := strconv.Atoi(q.Get("quota"))
	if email == "" || err != nil {
		writeUAPIError(w, "Email", "edit_pop_quota", []string{"The email and numeric quota parameters are required."})
		return
	}
	if s.mail == nil {
		s.mailUnavailable(w, "edit_pop_quota")
		return
	}
	if err := s.mail.SetQuota(r.Context(), user, email, quota); err != nil {
		writeUAPIError(w, "Email", "edit_pop_quota", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Email", "edit_pop_quota", nil)
}

func (s *Server) uapiEmailGetPopQuota(w http.ResponseWriter, r *http.Request, account Account, user string) {
	email := r.URL.Query().Get("email")
	if s.mail == nil {
		s.mailUnavailable(w, "get_pop_quota")
		return
	}
	q, err := s.mail.Quota(r.Context(), user, email)
	if err != nil {
		writeUAPIError(w, "Email", "get_pop_quota", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Email", "get_pop_quota", map[string]any{"email": email, "quota_mib": q})
}

func (s *Server) uapiEmailCountPops(w http.ResponseWriter, r *http.Request, account Account, user string) {
	if s.mail == nil {
		s.mailUnavailable(w, "count_pops")
		return
	}
	n, err := s.mail.CountMailboxes(r.Context(), user)
	if err != nil {
		writeUAPIError(w, "Email", "count_pops", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Email", "count_pops", n)
}

func (s *Server) uapiEmailVerifyPassword(w http.ResponseWriter, r *http.Request, account Account, user string) {
	q := r.URL.Query()
	email, password := q.Get("email"), q.Get("password")
	if s.mail == nil {
		s.mailUnavailable(w, "verify_password")
		return
	}
	ok, err := s.mail.VerifyPassword(r.Context(), user, email, password)
	if err != nil {
		writeUAPIError(w, "Email", "verify_password", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Email", "verify_password", map[string]any{"verified": ok})
}

func (s *Server) uapiEmailListMailDomains(w http.ResponseWriter, r *http.Request, account Account, user string) {
	domains := []string{}
	if account.Domain != "" {
		domains = append(domains, account.Domain)
	}
	writeUAPISuccess(w, "Email", "list_mail_domains", domains)
}

func (s *Server) uapiEmailGetDefaultQuota(w http.ResponseWriter, r *http.Request, account Account, user string) {
	writeUAPISuccess(w, "Email", "get_default_email_quota", 0) // 0 = unlimited, reference convention
}

func (s *Server) uapiEmailGetMaxQuota(w http.ResponseWriter, r *http.Request, account Account, user string) {
	writeUAPISuccess(w, "Email", "get_max_email_quota", 0) // no host-imposed cap this batch
}
