package whmapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"sifruno/internal/hostpkgs"
)

// Golden strings verbatim from the licensed 138 reference (batch-4 capture,
// docs/reference/whm-api-contract-batch4.md). Server left clean afterwards.

func pkgServer(t *testing.T) (*Server, *hostpkgs.Store, string) {
	t.Helper()
	ts, token := issueToken(t)
	st := hostpkgs.NewMemory()
	s := New(testBackend{}, ts).WithPackageStore(st)
	return s, st, token
}

func pkgCall(t *testing.T, s *Server, token, path string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Header.Set("Authorization", "whm root:"+token)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestAddPkgSuccessShape(t *testing.T) {
	s, st, token := pkgServer(t)
	w := pkgCall(t, s, token, "/json-api/addpkg?api.version=1&pkgname=gold&quota=1024&bwlimit=20480&maxpop=10&maxaddon=3&featurelist=default")
	var body struct {
		Data struct {
			Pkg string `json:"pkg"`
		} `json:"data"`
		Metadata struct {
			Result int `json:"result"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Metadata.Result != 1 || body.Data.Pkg != "gold" {
		t.Fatalf("body = %s", w.Body.String())
	}
	if !st.Has("gold") {
		t.Fatal("store missing created package")
	}
}

func TestAddPkgMissingNameExactError(t *testing.T) {
	s, _, token := pkgServer(t)
	w := pkgCall(t, s, token, "/json-api/addpkg?api.version=1")
	md := metadataOf(t, decodeEnvelope(t, w))
	if !regexp.MustCompile(`^\(XID [a-z0-9]{6}\) You must specify either the “pkgname” or “name” parameter\.$`).MatchString(md["reason"].(string)) {
		t.Fatalf("reason = %q", md["reason"])
	}
}

func TestAddPkgConflictExactError(t *testing.T) {
	s, _, token := pkgServer(t)
	pkgCall(t, s, token, "/json-api/addpkg?api.version=1&pkgname=gold")
	w := pkgCall(t, s, token, "/json-api/addpkg?api.version=1&pkgname=gold")
	md := metadataOf(t, decodeEnvelope(t, w))
	if !regexp.MustCompile(`^\(XID [a-z0-9]{6}\) The package “gold” already exists\. If you wish to make changes, please edit the package\.$`).MatchString(md["reason"].(string)) {
		t.Fatalf("reason = %q", md["reason"])
	}
}

func TestGetPkgInfoShapeAndDefaults(t *testing.T) {
	s, _, token := pkgServer(t)
	pkgCall(t, s, token, "/json-api/addpkg?api.version=1&pkgname=gold&quota=1024&maxpop=10&maxaddon=3")
	w := pkgCall(t, s, token, "/json-api/getpkginfo?api.version=1&pkg=gold")
	var body struct {
		Data struct {
			Pkg map[string]any `json:"pkg"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	pkg := body.Data.Pkg
	if pkg["QUOTA"] != "1024" || pkg["MAXPOP"] != "10" || pkg["MAXADDON"] != "3" {
		t.Fatalf("overrides = %v", pkg)
	}
	// Observed defaults on the reference getpkginfo.
	if pkg["CPMOD"] != "jupiter" || pkg["FEATURELIST"] != "default" || pkg["PACKAGE_TYPE"] != "standard" || pkg["MAX_TEAM_USERS"] != "7" {
		t.Fatalf("defaults = %v", pkg)
	}
	for _, k := range []string{"MAXFTP", "MAXSQL", "MAXPARK", "MAXSUB", "MAXLST"} {
		if v, present := pkg[k]; !present || v != nil {
			t.Fatalf("%s must be present and null (observed): %v", k, pkg[k])
		}
	}
	if _, present := pkg["name"]; present {
		t.Fatal("getpkginfo data.pkg must not carry the list-only name key")
	}
}

func TestGetPkgInfoMissingExactError(t *testing.T) {
	s, _, token := pkgServer(t)
	w := pkgCall(t, s, token, "/json-api/getpkginfo?api.version=1&pkg=ghost")
	md := metadataOf(t, decodeEnvelope(t, w))
	if md["reason"] != "Failed to load package “ghost”: No such file or directory" {
		t.Fatalf("reason = %q", md["reason"])
	}
}

func TestKillPkgLifecycle(t *testing.T) {
	s, st, token := pkgServer(t)
	pkgCall(t, s, token, "/json-api/addpkg?api.version=1&pkgname=temp")
	w := pkgCall(t, s, token, "/json-api/killpkg?api.version=1&pkgname=temp")
	if metadataOf(t, decodeEnvelope(t, w))["result"].(float64) != 1 {
		t.Fatalf("killpkg failed: %s", w.Body.String())
	}
	if st.Has("temp") {
		t.Fatal("package survived killpkg")
	}
	// Repeat: observed exact error.
	w = pkgCall(t, s, token, "/json-api/killpkg?api.version=1&pkgname=temp")
	md := metadataOf(t, decodeEnvelope(t, w))
	if md["reason"] != "The package “temp” does not exist." || md["result"].(float64) != 0 {
		t.Fatalf("repeat killpkg = %v", md)
	}
}

func TestListPkgsFromStore(t *testing.T) {
	s, _, token := pkgServer(t)
	pkgCall(t, s, token, "/json-api/addpkg?api.version=1&pkgname=gold")
	pkgCall(t, s, token, "/json-api/addpkg?api.version=1&pkgname=silver")
	w := pkgCall(t, s, token, "/json-api/listpkgs?api.version=1")
	var body struct {
		Data struct {
			Pkg []map[string]any `json:"pkg"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Data.Pkg) != 2 || body.Data.Pkg[0]["name"] != "gold" || body.Data.Pkg[1]["name"] != "silver" {
		t.Fatalf("pkg = %v", body.Data.Pkg)
	}
}

func TestCreateAcctPlanValidation(t *testing.T) {
	h := &fakeHost{}
	ts, token := issueToken(t)
	st := hostpkgs.NewMemory()
	s := New(HostAccounts{Svc: h, Build: "11.138.0.11", Server: "203.0.113.10"}, ts).WithPackageStore(st)
	// Unknown plan: observed changepackage wording.
	w := pkgCall(t, s, token, "/json-api/createacct?api.version=1&username=planuser&domain=p.example.com&plan=ghost")
	md := metadataOf(t, decodeEnvelope(t, w))
	if md["result"].(float64) != 0 || !regexp.MustCompile(`Specified package does not exist\.`).MatchString(md["reason"].(string)) {
		t.Fatalf("missing-plan metadata = %v", md)
	}
	if len(h.accounts) != 0 {
		t.Fatal("account created despite unknown plan")
	}
	// Known plan flows into the account record.
	pkgCall(t, s, token, "/json-api/addpkg?api.version=1&pkgname=gold")
	w = pkgCall(t, s, token, "/json-api/createacct?api.version=1&username=planuser&domain=p.example.com&plan=gold")
	body := decodeEnvelope(t, w)
	if metadataOf(t, body)["result"].(float64) != 1 {
		t.Fatalf("create with plan failed: %s", w.Body.String())
	}
	if h.accounts[0].Plan != "gold" {
		t.Fatalf("backend plan = %q", h.accounts[0].Plan)
	}
	if body["data"].(map[string]any)["package"] != "gold" {
		t.Fatalf("response package = %v", body["data"])
	}
}

func TestHostPkgsPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "packages.json")
	s1, err := hostpkgs.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s1.Create("gold", map[string]string{"quota": "1024"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o", fi.Mode().Perm())
	}
	s2, err := hostpkgs.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	pkg, ok := s2.Get("gold")
	if !ok || pkg["QUOTA"] != "1024" {
		t.Fatalf("reopened pkg = %v", pkg)
	}
	if err := s2.Delete("gold"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := s2.Delete("gold"); err != hostpkgs.ErrNotFound {
		t.Fatalf("second delete = %v", err)
	}
}
