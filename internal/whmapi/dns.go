package whmapi

import (
	"net/http"

	"sifruno/internal/dnshost"
)

// DNS surface (dns.cluster batch 1): WHM API 1 zone functions over the
// BIND-format store. createacct/removeacct auto-create/kill account zones.

// SetDNSStore injects the zone store. Nil = DNS surface fail-closed.
func (s *Server) SetDNSStore(store *dnshost.Store) { s.dns = store }

// SetDNSDefaults configures the default-zone template (nameservers + IP).
func (s *Server) SetDNSDefaults(ns1, ns2, ip string) { s.dnsNS1, s.dnsNS2, s.dnsIP = ns1, ns2, ip }

func (s *Server) dnsUnavailable(w http.ResponseWriter, command string) {
	writeError(w, command, "The DNS service is not configured on this server.")
}

func (s *Server) handleListZones(w http.ResponseWriter, r *http.Request) {
	if s.dns == nil {
		s.dnsUnavailable(w, "listzones")
		return
	}
	zones, err := s.dns.List()
	if err != nil {
		writeError(w, "listzones", err.Error())
		return
	}
	names := make([]string, 0, len(zones))
	for _, z := range zones {
		names = append(names, z.Domain)
	}
	writeSuccess(w, "listzones", map[string]any{"zone": names}, "")
}

func (s *Server) handleAddDNS(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	domain, ip := q.Get("domain"), q.Get("ip")
	if domain == "" || ip == "" {
		writeError(w, "adddns", `Missing required parameters: "domain" and "ip".`)
		return
	}
	if s.dns == nil {
		s.dnsUnavailable(w, "adddns")
		return
	}
	if err := dnshost.ValidateDomain(domain); err != nil {
		writeError(w, "adddns", err.Error())
		return
	}
	ns1, ns2 := s.dnsNS1, s.dnsNS2
	if ns1 == "" {
		ns1, ns2 = "ns1."+domain, "ns2."+domain
	}
	z := dnshost.NewDefaultZone(domain, ns1, ns2, ip)
	if err := s.dns.Save(z); err != nil {
		writeError(w, "adddns", err.Error())
		return
	}
	writeSuccessReason(w, "adddns", "Added the zone for "+domain, map[string]any{"domain": domain},
		"Checking for NS records..Done\nAdding zone for "+domain+"...Done\n")
}

func (s *Server) handleKillDNS(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		writeError(w, "killdns", `"domain" is a required argument.`)
		return
	}
	if s.dns == nil {
		s.dnsUnavailable(w, "killdns")
		return
	}
	if _, err := s.dns.Load(domain); err != nil {
		writeError(w, "killdns", "The zone “"+domain+"” does not exist.")
		return
	}
	if err := s.dns.Delete(domain); err != nil {
		writeError(w, "killdns", err.Error())
		return
	}
	writeSuccessReason(w, "killdns", "Removed the zone for "+domain, map[string]any{}, "")
}

func (s *Server) handleDumpZone(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if s.dns == nil {
		s.dnsUnavailable(w, "dumpzone")
		return
	}
	z, err := s.dns.Load(domain)
	if err != nil {
		writeError(w, "dumpzone", "The zone “"+domain+"” does not exist.")
		return
	}
	recs := make([]map[string]any, 0, len(z.Records))
	for _, rec := range z.Records {
		recs = append(recs, map[string]any{"name": rec.Name, "type": rec.Type, "value": rec.Value})
	}
	writeSuccess(w, "dumpzone", map[string]any{"domain": z.Domain, "serial": z.Serial, "record": recs}, "")
}

func (s *Server) handleAddZoneRecord(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	domain := q.Get("domain") // reference: 'zone'
	if domain == "" {
		domain = q.Get("zone")
	}
	if s.dns == nil {
		s.dnsUnavailable(w, "addzonerecord")
		return
	}
	z, err := s.dns.Load(domain)
	if err != nil {
		writeError(w, "addzonerecord", "The zone “"+domain+"” does not exist.")
		return
	}
	rec := dnshost.Record{Name: q.Get("name"), Type: q.Get("type"), Value: q.Get("value")}
	if q.Get("type") == "MX" && q.Get("preference") != "" {
		rec.Value = q.Get("preference") + " " + q.Get("value")
	}
	if err := z.AddRecord(rec); err != nil {
		writeError(w, "addzonerecord", err.Error())
		return
	}
	if err := s.dns.Save(z); err != nil {
		writeError(w, "addzonerecord", err.Error())
		return
	}
	writeSuccessReason(w, "addzonerecord", "The record was added.", map[string]any{"newserial": z.Serial}, "")
}

func (s *Server) handleRemoveZoneRecord(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	domain := q.Get("zone")
	if domain == "" {
		domain = q.Get("domain")
	}
	if s.dns == nil {
		s.dnsUnavailable(w, "removezonerecord")
		return
	}
	z, err := s.dns.Load(domain)
	if err != nil {
		writeError(w, "removezonerecord", "The zone “"+domain+"” does not exist.")
		return
	}
	n := z.RemoveRecord(q.Get("name"), q.Get("type"), q.Get("value"))
	if n == 0 {
		writeError(w, "removezonerecord", "No matching record was found.")
		return
	}
	if err := s.dns.Save(z); err != nil {
		writeError(w, "removezonerecord", err.Error())
		return
	}
	writeSuccessReason(w, "removezonerecord", "The record was removed.", map[string]any{"newserial": z.Serial}, "")
}

func (s *Server) handleGetZoneRecord(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	domain := q.Get("zone")
	if domain == "" {
		domain = q.Get("domain")
	}
	if s.dns == nil {
		s.dnsUnavailable(w, "getzonerecord")
		return
	}
	z, err := s.dns.Load(domain)
	if err != nil {
		writeError(w, "getzonerecord", "The zone “"+domain+"” does not exist.")
		return
	}
	name, typ := q.Get("name"), q.Get("type")
	out := []map[string]any{}
	for _, rec := range z.Records {
		if (name == "" || rec.Name == name) && (typ == "" || rec.Type == typ) {
			out = append(out, map[string]any{"name": rec.Name, "type": rec.Type, "value": rec.Value})
		}
	}
	writeSuccess(w, "getzonerecord", map[string]any{"record": out}, "")
}

func (s *Server) handleResetZone(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		writeError(w, "resetzone", `"domain" is a required argument.`)
		return
	}
	if s.dns == nil {
		s.dnsUnavailable(w, "resetzone")
		return
	}
	z, err := s.dns.Load(domain)
	if err != nil {
		writeError(w, "resetzone", "The zone “"+domain+"” does not exist.")
		return
	}
	// keep first A record's IP as the rebuild source
	ip := s.dnsIP
	for _, rec := range z.Records {
		if rec.Type == "A" && rec.Name == "@" {
			ip = rec.Value
		}
	}
	ns1, ns2 := s.dnsNS1, s.dnsNS2
	if ns1 == "" {
		ns1, ns2 = "ns1."+domain, "ns2."+domain
	}
	nz := dnshost.NewDefaultZone(domain, ns1, ns2, ip)
	if err := s.dns.Save(nz); err != nil {
		writeError(w, "resetzone", err.Error())
		return
	}
	writeSuccessReason(w, "resetzone", "The zone was reset to the default template.", map[string]any{}, "")
}
