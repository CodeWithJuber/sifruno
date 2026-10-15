package whmapi

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"sifruno/internal/hostpkgs"
)

// WithPackageStore attaches the package store used by listpkgs, addpkg,
// killpkg, getpkginfo and createacct plan validation. Nil keeps listpkgs
// truthful-empty and plan validation disabled.
func (s *Server) WithPackageStore(st *hostpkgs.Store) *Server {
	s.pkgs = st
	return s
}

func (s *Server) handleListPkgs(w http.ResponseWriter, _ *http.Request) {
	if s.pkgs != nil {
		writeSuccess(w, "listpkgs", map[string]any{"pkg": s.pkgs.List()}, "")
		return
	}
	pkgs := s.backend.ListPackages()
	if pkgs == nil {
		pkgs = []Package{}
	}
	writeSuccess(w, "listpkgs", map[string]any{"pkg": pkgs}, "")
}

// pkgName reads the observed parameter aliases: addpkg accepts pkgname|name,
// killpkg accepts pkgname|pkg.
func pkgName(r *http.Request, keys ...string) string {
	q := r.URL.Query()
	for _, k := range keys {
		if v := q.Get(k); v != "" {
			return v
		}
	}
	return ""
}

func (s *Server) handleAddPkg(w http.ResponseWriter, r *http.Request) {
	if s.pkgs == nil {
		writeErrorData(w, "addpkg", "API failure: package storage is unavailable.")
		return
	}
	name := pkgName(r, "pkgname", "name")
	if name == "" {
		// Observed verbatim (XID volatile).
		writeErrorData(w, "addpkg", "(XID "+xid()+") You must specify either the “pkgname” or “name” parameter.")
		return
	}
	overrides := map[string]string{}
	for k := range r.URL.Query() {
		if k == "pkgname" || k == "name" || k == "api.version" {
			continue
		}
		overrides[k] = r.URL.Query().Get(k)
	}
	err := s.pkgs.Create(name, overrides)
	if errors.Is(err, hostpkgs.ErrConflict) {
		// Observed verbatim.
		writeErrorData(w, "addpkg", fmt.Sprintf("(XID %s) The package “%s” already exists. If you wish to make changes, please edit the package.", xid(), name))
		return
	}
	if errors.Is(err, hostpkgs.ErrInvalid) {
		writeErrorData(w, "addpkg", fmt.Sprintf("(XID %s) “%s” is not a valid package name.", xid(), name))
		return
	}
	if err != nil {
		writeErrorData(w, "addpkg", "API failure: (XID "+xid()+") "+strings.TrimPrefix(err.Error(), "hostpkgs: "))
		return
	}
	// Observed success shape: data.pkg carries the created name.
	writeSuccess(w, "addpkg", map[string]any{"pkg": name}, "")
}

func (s *Server) handleKillPkg(w http.ResponseWriter, r *http.Request) {
	if s.pkgs == nil {
		writeError(w, "killpkg", "API failure: package storage is unavailable.")
		return
	}
	name := pkgName(r, "pkgname", "pkg")
	if name == "" {
		writeError(w, "killpkg", `The package “” does not exist.`)
		return
	}
	err := s.pkgs.Delete(name)
	if errors.Is(err, hostpkgs.ErrNotFound) {
		// Observed verbatim.
		writeError(w, "killpkg", fmt.Sprintf("The package “%s” does not exist.", name))
		return
	}
	if err != nil {
		writeError(w, "killpkg", "API failure: (XID "+xid()+") package removal failed; store unchanged.")
		return
	}
	writeSuccess(w, "killpkg", nil, "")
}

func (s *Server) handleGetPkgInfo(w http.ResponseWriter, r *http.Request) {
	if s.pkgs == nil {
		writeError(w, "getpkginfo", "API failure: package storage is unavailable.")
		return
	}
	name := pkgName(r, "pkg", "pkgname", "name")
	pkg, ok := s.pkgs.Get(name)
	if !ok {
		// Observed verbatim.
		writeError(w, "getpkginfo", fmt.Sprintf("Failed to load package “%s”: No such file or directory", name))
		return
	}
	writeSuccess(w, "getpkginfo", map[string]any{"pkg": pkg}, "")
}
