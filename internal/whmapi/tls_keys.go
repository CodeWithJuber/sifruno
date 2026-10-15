package whmapi

// tls.autossl batch 2 UAPI handlers: SSL::generate_key, generate_csr,
// list_keys, list_csrs, delete_key, delete_csr.

import (
	"net/http"
	"strings"
)

func (s *Server) uapiSSLGenerateKey(w http.ResponseWriter, r *http.Request, a Account, u string) {
	if s.tlsStore == nil {
		writeUAPIError(w, "SSL", "generate_key", []string{"TLS store unavailable"})
		return
	}
	info, err := s.tlsStore.GenerateKey(u)
	if err != nil {
		writeUAPIError(w, "SSL", "generate_key", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "SSL", "generate_key", info)
}

func (s *Server) uapiSSLGenerateCSR(w http.ResponseWriter, r *http.Request, a Account, u string) {
	if s.tlsStore == nil {
		writeUAPIError(w, "SSL", "generate_csr", []string{"TLS store unavailable"})
		return
	}
	q := r.URL.Query()
	keyID := strings.TrimSpace(q.Get("key_id"))
	domains := []string{}
	for _, d := range strings.Split(q.Get("domains"), ",") {
		if strings.TrimSpace(d) != "" {
			domains = append(domains, strings.TrimSpace(d))
		}
	}
	info, err := s.tlsStore.GenerateCSR(u, keyID, domains, strings.TrimSpace(q.Get("email")))
	if err != nil {
		writeUAPIError(w, "SSL", "generate_csr", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "SSL", "generate_csr", info)
}

func (s *Server) uapiSSLListKeys(w http.ResponseWriter, r *http.Request, a Account, u string) {
	if s.tlsStore == nil {
		writeUAPIError(w, "SSL", "list_keys", []string{"TLS store unavailable"})
		return
	}
	keys, err := s.tlsStore.ListKeys(u)
	if err != nil {
		writeUAPIError(w, "SSL", "list_keys", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "SSL", "list_keys", keys)
}

func (s *Server) uapiSSLListCSRs(w http.ResponseWriter, r *http.Request, a Account, u string) {
	if s.tlsStore == nil {
		writeUAPIError(w, "SSL", "list_csrs", []string{"TLS store unavailable"})
		return
	}
	csrs, err := s.tlsStore.ListCSRs(u)
	if err != nil {
		writeUAPIError(w, "SSL", "list_csrs", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "SSL", "list_csrs", csrs)
}

func (s *Server) uapiSSLDeleteKey(w http.ResponseWriter, r *http.Request, a Account, u string) {
	if s.tlsStore == nil {
		writeUAPIError(w, "SSL", "delete_key", []string{"TLS store unavailable"})
		return
	}
	if err := s.tlsStore.DeleteKey(u, strings.TrimSpace(r.URL.Query().Get("id"))); err != nil {
		writeUAPIError(w, "SSL", "delete_key", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "SSL", "delete_key", nil)
}

func (s *Server) uapiSSLDeleteCSR(w http.ResponseWriter, r *http.Request, a Account, u string) {
	if s.tlsStore == nil {
		writeUAPIError(w, "SSL", "delete_csr", []string{"TLS store unavailable"})
		return
	}
	if err := s.tlsStore.DeleteCSR(u, strings.TrimSpace(r.URL.Query().Get("id"))); err != nil {
		writeUAPIError(w, "SSL", "delete_csr", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "SSL", "delete_csr", nil)
}
