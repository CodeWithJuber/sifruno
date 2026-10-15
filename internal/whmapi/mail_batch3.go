package whmapi

// mail.lifecycle batch 3 UAPI handlers: autoresponders, per-mailbox
// suspend flags, and MX management over the DNS zone store.

import (
	"net/http"
	"strconv"
	"strings"

	"sifruno/internal/dnshost"
	"sifruno/internal/mailhost"
)

func (s *Server) mailSvc() *mailhost.LocalService {
	if s.mail == nil {
		return nil
	}
	if ls, ok := s.mail.(*mailhost.LocalService); ok {
		return ls
	}
	return nil
}

func (s *Server) emailSuspend(w http.ResponseWriter, r *http.Request, user, fn string, flag mailhost.SuspendFlag, on bool) {
	email := strings.TrimSpace(r.URL.Query().Get("email"))
	ls := s.mailSvc()
	if ls == nil {
		writeUAPIError(w, "Email", fn, []string{"mail service unavailable"})
		return
	}
	if err := ls.SetSuspend(r.Context(), user, email, flag, on); err != nil {
		writeUAPIError(w, "Email", fn, []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Email", fn, email)
}

func (s *Server) uapiEmailSuspendIncoming(w http.ResponseWriter, r *http.Request, a Account, u string) {
	s.emailSuspend(w, r, u, "suspend_incoming", mailhost.SuspendIncoming, true)
}
func (s *Server) uapiEmailUnsuspendIncoming(w http.ResponseWriter, r *http.Request, a Account, u string) {
	s.emailSuspend(w, r, u, "unsuspend_incoming", mailhost.SuspendIncoming, false)
}
func (s *Server) uapiEmailSuspendOutgoing(w http.ResponseWriter, r *http.Request, a Account, u string) {
	s.emailSuspend(w, r, u, "suspend_outgoing", mailhost.SuspendOutgoing, true)
}
func (s *Server) uapiEmailUnsuspendOutgoing(w http.ResponseWriter, r *http.Request, a Account, u string) {
	s.emailSuspend(w, r, u, "unsuspend_outgoing", mailhost.SuspendOutgoing, false)
}
func (s *Server) uapiEmailSuspendLogin(w http.ResponseWriter, r *http.Request, a Account, u string) {
	s.emailSuspend(w, r, u, "suspend_login", mailhost.SuspendLogin, true)
}
func (s *Server) uapiEmailUnsuspendLogin(w http.ResponseWriter, r *http.Request, a Account, u string) {
	s.emailSuspend(w, r, u, "unsuspend_login", mailhost.SuspendLogin, false)
}

func (s *Server) uapiEmailAddAutoResponder(w http.ResponseWriter, r *http.Request, a Account, u string) {
	ls := s.mailSvc()
	if ls == nil {
		writeUAPIError(w, "Email", "add_auto_responder", []string{"mail service unavailable"})
		return
	}
	q := r.URL.Query()
	ar := mailhost.AutoResponder{
		Email:   strings.TrimSpace(q.Get("email")),
		From:    q.Get("from"),
		Subject: q.Get("subject"),
		Body:    q.Get("body"),
		IsHTML:  q.Get("html") == "1",
	}
	if v, err := strconv.Atoi(q.Get("interval")); err == nil {
		ar.Interval = v
	}
	if v, err := strconv.ParseInt(q.Get("start"), 10, 64); err == nil {
		ar.Start = v
	}
	if v, err := strconv.ParseInt(q.Get("stop"), 10, 64); err == nil {
		ar.Stop = v
	}
	if err := ls.AddAutoResponder(r.Context(), u, ar); err != nil {
		writeUAPIError(w, "Email", "add_auto_responder", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Email", "add_auto_responder", ar.Email)
}

func (s *Server) uapiEmailGetAutoResponder(w http.ResponseWriter, r *http.Request, a Account, u string) {
	ls := s.mailSvc()
	if ls == nil {
		writeUAPIError(w, "Email", "get_auto_responder", []string{"mail service unavailable"})
		return
	}
	ar, err := ls.GetAutoResponder(r.Context(), u, strings.TrimSpace(r.URL.Query().Get("email")))
	if err != nil {
		writeUAPIError(w, "Email", "get_auto_responder", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Email", "get_auto_responder", ar)
}

func (s *Server) uapiEmailListAutoResponders(w http.ResponseWriter, r *http.Request, a Account, u string) {
	ls := s.mailSvc()
	if ls == nil {
		writeUAPIError(w, "Email", "list_auto_responders", []string{"mail service unavailable"})
		return
	}
	ars, err := ls.ListAutoResponders(r.Context(), u)
	if err != nil {
		writeUAPIError(w, "Email", "list_auto_responders", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Email", "list_auto_responders", ars)
}

func (s *Server) uapiEmailCountAutoResponders(w http.ResponseWriter, r *http.Request, a Account, u string) {
	ls := s.mailSvc()
	if ls == nil {
		writeUAPIError(w, "Email", "count_auto_responders", []string{"mail service unavailable"})
		return
	}
	n, err := ls.CountAutoResponders(r.Context(), u)
	if err != nil {
		writeUAPIError(w, "Email", "count_auto_responders", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Email", "count_auto_responders", n)
}

func (s *Server) uapiEmailDeleteAutoResponder(w http.ResponseWriter, r *http.Request, a Account, u string) {
	ls := s.mailSvc()
	if ls == nil {
		writeUAPIError(w, "Email", "delete_auto_responder", []string{"mail service unavailable"})
		return
	}
	if err := ls.DeleteAutoResponder(r.Context(), u, strings.TrimSpace(r.URL.Query().Get("email"))); err != nil {
		writeUAPIError(w, "Email", "delete_auto_responder", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Email", "delete_auto_responder", nil)
}

// --- MX management over the DNS zone store -----------------------------

// mxFence ensures the domain belongs to the account (main domain for now;
// addon/parked domains land with the domain-management surface).
func (s *Server) mxFence(account Account, domain string) bool {
	return domain != "" && domain == account.Domain
}

type mxEntry struct {
	Exchange   string `json:"exchange"`
	Preference int    `json:"preference"`
}

// mxRecords extracts MX entries from a zone.
func mxRecords(z dnshost.Zone) []mxEntry {
	out := []mxEntry{}
	for _, rec := range z.Records {
		if rec.Type != "MX" {
			continue
		}
		parts := strings.Fields(rec.Value)
		if len(parts) != 2 {
			continue
		}
		pref, _ := strconv.Atoi(parts[0])
		out = append(out, mxEntry{Exchange: parts[1], Preference: pref})
	}
	return out
}

func validMX(pref int, exchange string) bool {
	return pref >= 0 && pref <= 65535 && exchange != "" &&
		!strings.ContainsAny(exchange, " \t\r\n;'\"\\")
}

func (s *Server) uapiEmailListMXs(w http.ResponseWriter, r *http.Request, a Account, u string) {
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if !s.mxFence(a, domain) {
		writeUAPIError(w, "Email", "list_mxs", []string{"domain not owned by this account"})
		return
	}
	if s.dns == nil {
		writeUAPIError(w, "Email", "list_mxs", []string{"DNS service unavailable"})
		return
	}
	z, err := s.dns.Load(domain)
	if err != nil {
		writeUAPIError(w, "Email", "list_mxs", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Email", "list_mxs", mxRecords(z))
}

func (s *Server) uapiEmailAddMX(w http.ResponseWriter, r *http.Request, a Account, u string) {
	q := r.URL.Query()
	domain := strings.TrimSpace(q.Get("domain"))
	exchange := strings.TrimSpace(q.Get("exchange"))
	pref, err := strconv.Atoi(q.Get("preference"))
	if !s.mxFence(a, domain) {
		writeUAPIError(w, "Email", "add_mx", []string{"domain not owned by this account"})
		return
	}
	if err != nil || !validMX(pref, exchange) {
		writeUAPIError(w, "Email", "add_mx", []string{"valid exchange and preference (0-65535) are required"})
		return
	}
	if s.dns == nil {
		writeUAPIError(w, "Email", "add_mx", []string{"DNS service unavailable"})
		return
	}
	z, err := s.dns.Load(domain)
	if err != nil {
		writeUAPIError(w, "Email", "add_mx", []string{err.Error()})
		return
	}
	if err := z.AddRecord(dnshost.Record{Name: "@", Type: "MX", Value: strconv.Itoa(pref) + " " + exchange}); err != nil {
		writeUAPIError(w, "Email", "add_mx", []string{err.Error()})
		return
	}
	if err := s.dns.Save(z); err != nil {
		writeUAPIError(w, "Email", "add_mx", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Email", "add_mx", mxEntry{Exchange: exchange, Preference: pref})
}

func (s *Server) uapiEmailDeleteMX(w http.ResponseWriter, r *http.Request, a Account, u string) {
	q := r.URL.Query()
	domain := strings.TrimSpace(q.Get("domain"))
	exchange := strings.TrimSpace(q.Get("exchange"))
	if !s.mxFence(a, domain) {
		writeUAPIError(w, "Email", "delete_mx", []string{"domain not owned by this account"})
		return
	}
	if s.dns == nil {
		writeUAPIError(w, "Email", "delete_mx", []string{"DNS service unavailable"})
		return
	}
	z, err := s.dns.Load(domain)
	if err != nil {
		writeUAPIError(w, "Email", "delete_mx", []string{err.Error()})
		return
	}
	removed := 0
	for _, rec := range append([]dnshost.Record{}, z.Records...) {
		if rec.Type == "MX" && strings.HasSuffix(strings.TrimSpace(rec.Value), exchange) {
			removed += z.RemoveRecord(rec.Name, "MX", rec.Value)
		}
	}
	if removed == 0 {
		writeUAPIError(w, "Email", "delete_mx", []string{"no MX record for exchange " + exchange})
		return
	}
	if err := s.dns.Save(z); err != nil {
		writeUAPIError(w, "Email", "delete_mx", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Email", "delete_mx", removed)
}

func (s *Server) uapiEmailChangeMX(w http.ResponseWriter, r *http.Request, a Account, u string) {
	q := r.URL.Query()
	domain := strings.TrimSpace(q.Get("domain"))
	oldExch := strings.TrimSpace(q.Get("oldexchange"))
	newExch := strings.TrimSpace(q.Get("exchange"))
	pref, perr := strconv.Atoi(q.Get("preference"))
	if !s.mxFence(a, domain) {
		writeUAPIError(w, "Email", "change_mx", []string{"domain not owned by this account"})
		return
	}
	if oldExch == "" || perr != nil || !validMX(pref, newExch) {
		writeUAPIError(w, "Email", "change_mx", []string{"oldexchange, exchange and preference (0-65535) are required"})
		return
	}
	if s.dns == nil {
		writeUAPIError(w, "Email", "change_mx", []string{"DNS service unavailable"})
		return
	}
	z, err := s.dns.Load(domain)
	if err != nil {
		writeUAPIError(w, "Email", "change_mx", []string{err.Error()})
		return
	}
	found := false
	for _, rec := range z.Records {
		if rec.Type == "MX" && strings.HasSuffix(strings.TrimSpace(rec.Value), oldExch) {
			z.RemoveRecord(rec.Name, "MX", rec.Value)
			found = true
			break
		}
	}
	if !found {
		writeUAPIError(w, "Email", "change_mx", []string{"no MX record for exchange " + oldExch})
		return
	}
	if err := z.AddRecord(dnshost.Record{Name: "@", Type: "MX", Value: strconv.Itoa(pref) + " " + newExch}); err != nil {
		writeUAPIError(w, "Email", "change_mx", []string{err.Error()})
		return
	}
	if err := s.dns.Save(z); err != nil {
		writeUAPIError(w, "Email", "change_mx", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "Email", "change_mx", mxEntry{Exchange: newExch, Preference: pref})
}
