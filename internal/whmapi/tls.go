package whmapi

// tls.autossl batch 1: WHM installssl/listcrts/fetchsslinfo and UAPI
// SSL::install_ssl/list_certs/fetch_cert_info/delete_ssl over the tlshost
// store. Real x509 parsing; no fabricated certificate data.

import (
	"net/http"
	"strings"

	"sifruno/internal/tlshost"
)

// SetTLSStore wires the certificate store.
func (s *Server) SetTLSStore(st *tlshost.Store) { s.tlsStore = st }

func (s *Server) handleInstallSSL(w http.ResponseWriter, r *http.Request) {
	// PEM payloads arrive as POST form fields; parse both body and query.
	if err := r.ParseForm(); err != nil {
		writeError(w, "installssl", "malformed form body")
		return
	}
	q := r.Form
	domain := strings.TrimSpace(q.Get("domain"))
	crt := q.Get("crt")
	key := q.Get("key")
	cab := q.Get("cabundle")
	if s.tlsStore == nil {
		writeError(w, "installssl", "TLS store unavailable")
		return
	}
	info, err := s.tlsStore.Install(r.Context(), domain, []byte(crt), []byte(key), []byte(cab))
	if err != nil {
		writeError(w, "installssl", err.Error())
		return
	}
	writeSuccess(w, "installssl", map[string]any{
		"domain":     info.Domain,
		"subject_cn": info.SubjectCN,
		"expires":    info.NotAfter,
	}, "Certificate installed")
}

func (s *Server) handleListCrts(w http.ResponseWriter, r *http.Request) {
	if s.tlsStore == nil {
		writeError(w, "listcrts", "TLS store unavailable")
		return
	}
	infos, err := s.tlsStore.List(r.Context())
	if err != nil {
		writeError(w, "listcrts", err.Error())
		return
	}
	writeSuccess(w, "listcrts", map[string]any{"crt": infos}, "")
}

func (s *Server) handleFetchSSLInfo(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if s.tlsStore == nil {
		writeError(w, "fetchsslinfo", "TLS store unavailable")
		return
	}
	info, err := s.tlsStore.Info(r.Context(), domain)
	if err != nil {
		writeError(w, "fetchsslinfo", err.Error())
		return
	}
	writeSuccess(w, "fetchsslinfo", info, "")
}

// --- UAPI SSL -----------------------------------------------------------

func (s *Server) uapiSSLInstall(w http.ResponseWriter, r *http.Request, a Account, u string) {
	if err := r.ParseForm(); err != nil {
		writeUAPIError(w, "SSL", "install_ssl", []string{"malformed form body"})
		return
	}
	q := r.Form
	domain := strings.TrimSpace(q.Get("domain"))
	if domain != a.Domain {
		writeUAPIError(w, "SSL", "install_ssl", []string{"domain not owned by this account"})
		return
	}
	if s.tlsStore == nil {
		writeUAPIError(w, "SSL", "install_ssl", []string{"TLS store unavailable"})
		return
	}
	info, err := s.tlsStore.Install(r.Context(), domain,
		[]byte(q.Get("cert")), []byte(q.Get("key")), []byte(q.Get("cabundle")))
	if err != nil {
		writeUAPIError(w, "SSL", "install_ssl", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "SSL", "install_ssl", info)
}

func (s *Server) uapiSSLListCerts(w http.ResponseWriter, r *http.Request, a Account, u string) {
	if s.tlsStore == nil {
		writeUAPIError(w, "SSL", "list_certs", []string{"TLS store unavailable"})
		return
	}
	infos, err := s.tlsStore.List(r.Context())
	if err != nil {
		writeUAPIError(w, "SSL", "list_certs", []string{err.Error()})
		return
	}
	// account scope: only the account's own domain cert is listed
	out := []tlshost.CertInfo{}
	for _, i := range infos {
		if i.Domain == a.Domain {
			out = append(out, i)
		}
	}
	writeUAPISuccess(w, "SSL", "list_certs", out)
}

func (s *Server) uapiSSLFetchCertInfo(w http.ResponseWriter, r *http.Request, a Account, u string) {
	if s.tlsStore == nil {
		writeUAPIError(w, "SSL", "fetch_cert_info", []string{"TLS store unavailable"})
		return
	}
	info, err := s.tlsStore.Info(r.Context(), strings.TrimSpace(r.URL.Query().Get("domain")))
	if err != nil {
		writeUAPIError(w, "SSL", "fetch_cert_info", []string{err.Error()})
		return
	}
	if info.Domain != a.Domain {
		writeUAPIError(w, "SSL", "fetch_cert_info", []string{"domain not owned by this account"})
		return
	}
	writeUAPISuccess(w, "SSL", "fetch_cert_info", info)
}

func (s *Server) uapiSSLDelete(w http.ResponseWriter, r *http.Request, a Account, u string) {
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if domain != a.Domain {
		writeUAPIError(w, "SSL", "delete_ssl", []string{"domain not owned by this account"})
		return
	}
	if s.tlsStore == nil {
		writeUAPIError(w, "SSL", "delete_ssl", []string{"TLS store unavailable"})
		return
	}
	if err := s.tlsStore.Delete(r.Context(), domain); err != nil {
		writeUAPIError(w, "SSL", "delete_ssl", []string{err.Error()})
		return
	}
	writeUAPISuccess(w, "SSL", "delete_ssl", domain)
}
