package whmapi

import (
	"net/http"
	"strings"
)

// Authenticator validates a WHM credential pair (API token or password for
// basic auth). Implementations must fail closed.
type Authenticator interface {
	Authenticate(user, credential string) bool
}

// authorized accepts the observed WHM auth schemes:
//   - `Authorization: whm <user>:<token>` (the WHMCS module contract)
//   - HTTP basic auth (root/password, as used by whmapi1 over HTTP)
//
// The deprecated accesshash scheme is not implemented: the reference host
// runs with allow_deprecated_accesshash=0 (envelopes-and-layout doc §8).
// *TokenStore (tokens.go) is the bootstrap Authenticator.
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
