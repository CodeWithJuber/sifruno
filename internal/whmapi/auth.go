package whmapi

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// Authenticator validates a WHM credential pair (API token or password for
// basic auth). Implementations must fail closed.
type Authenticator interface {
	Authenticate(user, credential string) bool
}

// TokenStore is a bootstrap in-memory authenticator mapping user -> API
// token. Comparisons are constant-time; unknown users and empty stored
// tokens never match. A file-backed, hashed store with rotation replaces
// this in the pr-access wiring batch.
type TokenStore map[string]string

func (t TokenStore) Authenticate(user, credential string) bool {
	want, ok := t[user]
	if !ok || want == "" || credential == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(credential)) == 1
}

// authorized accepts the observed WHM auth schemes:
//   - `Authorization: whm <user>:<token>` (the WHMCS module contract)
//   - HTTP basic auth (root/password, as used by whmapi1 over HTTP)
//
// The deprecated accesshash scheme is not implemented: the reference host
// runs with allow_deprecated_accesshash=0 (envelopes-and-layout doc §8).
func (s *Server) authorized(r *http.Request) bool {
	if s.auth == nil {
		return false
	}
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(h) >= 4 && strings.EqualFold(h[:4], "whm ") {
		cred := strings.TrimSpace(h[4:])
		user, token, ok := strings.Cut(cred, ":")
		if ok && user != "" && token != "" {
			return s.auth.Authenticate(user, token)
		}
		return false
	}
	if user, pass, ok := r.BasicAuth(); ok {
		return s.auth.Authenticate(user, pass)
	}
	return false
}
