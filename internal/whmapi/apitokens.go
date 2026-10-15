package whmapi

import (
	"errors"
	"net/http"
	"sort"
	"strings"
)

// TokenManager is the token lifecycle surface used by the api_token_*
// functions. *TokenStore implements it.
type TokenManager interface {
	Create(user, name string) (string, TokenInfo, error)
	Revoke(name string) error
	List() []TokenInfo
}

func (s *Server) tokenManager() (TokenManager, bool) {
	tm, ok := s.auth.(TokenManager)
	return tm, ok
}

// tokenACLBlock mirrors the observed api_token_list shape. Sifruno tokens
// are root-equivalent for now ("all":1); per-ACL enforcement lands with the
// pr-access roles batch. This is stated in the delivery doc, not hidden.
func tokenACLBlock() map[string]int {
	return map[string]int{"all": 1}
}

func (s *Server) handleTokenCreate(w http.ResponseWriter, r *http.Request) {
	tm, ok := s.tokenManager()
	if !ok {
		writeErrorData(w, "api_token_create", "The system failed to create the API token: token storage is unavailable.")
		return
	}
	name := r.URL.Query().Get("token_name")
	if name == "" {
		// Observed verbatim on the reference.
		writeErrorData(w, "api_token_create", "The system failed to create the API token: The parameter “token_name” is required.")
		return
	}
	// The WHM auth header carries user:token; the authenticated user owns
	// the token. Extract the user from the Authorization header.
	user := authUser(r)
	token, info, err := tm.Create(user, name)
	if errors.Is(err, ErrInvalidTokenName) {
		// Observed verbatim on the reference.
		writeErrorData(w, "api_token_create", "The system failed to create the API token: “"+name+"” is not a valid API token name. An API token name must not be longer than 50 characters and may only contain the following characters: a-z A-Z 0-9 _ -")
		return
	}
	if errors.Is(err, ErrTokenConflict) {
		// Observed verbatim on the reference.
		writeErrorData(w, "api_token_create", "The system failed to create the API token: A conflicting API token with the name “"+name+"” already exists.")
		return
	}
	if err != nil {
		writeErrorData(w, "api_token_create", "The system failed to create the API token: internal persistence failure; no token was stored.")
		return
	}
	writeSuccess(w, "api_token_create", map[string]any{
		"name":        info.Name,
		"expires_at":  nil,
		"create_time": info.CreateTime,
		"token":       token,
	}, "")
}

func (s *Server) handleTokenList(w http.ResponseWriter, _ *http.Request) {
	tm, ok := s.tokenManager()
	if !ok {
		writeErrorData(w, "api_token_list", "The system failed to list API tokens: token storage is unavailable.")
		return
	}
	infos := tm.List()
	sort.Slice(infos, func(i, j int) bool { return infos[i].Name < infos[j].Name })
	tokens := map[string]any{}
	for _, info := range infos {
		tokens[info.Name] = map[string]any{
			"acls":        tokenACLBlock(),
			"expires_at":  nil,
			"create_time": info.CreateTime,
			"name":        info.Name,
		}
	}
	writeSuccess(w, "api_token_list", map[string]any{"tokens": tokens}, "")
}

func (s *Server) handleTokenRevoke(w http.ResponseWriter, r *http.Request) {
	tm, ok := s.tokenManager()
	if !ok {
		writeErrorData(w, "api_token_revoke", "The system failed to revoke the API token: token storage is unavailable.")
		return
	}
	name := r.URL.Query().Get("token_name")
	if name == "" {
		writeErrorData(w, "api_token_revoke", "The system failed to revoke the API token: The parameter “token_name” is required.")
		return
	}
	if err := tm.Revoke(name); err != nil {
		writeErrorData(w, "api_token_revoke", "The system failed to revoke the API token: internal persistence failure.")
		return
	}
	// Observed: revoke is idempotent — repeat revoke returns result:1 with
	// an empty data object.
	writeJSON(w, http.StatusOK, envelope{Data: map[string]any{}, Metadata: metadata{Version: 1, Result: 1, Command: "api_token_revoke", Reason: "OK"}})
}

// authUser extracts the user portion of the WHM/basic credential.
func authUser(r *http.Request) string {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(h) >= 4 && strings.EqualFold(h[:4], "whm ") {
		user, _, _ := strings.Cut(strings.TrimSpace(h[4:]), ":")
		return user
	}
	user, _, _ := r.BasicAuth()
	return user
}
