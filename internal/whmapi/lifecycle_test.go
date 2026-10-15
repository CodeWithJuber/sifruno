package whmapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"sifruno/internal/hostaccounts"
)

// fakeHost is a minimal in-memory hostaccounts.Service for adapter tests.
type fakeHost struct {
	accounts []hostaccounts.Account
	nextUID  int
}

func (f *fakeHost) Capability(context.Context) (hostaccounts.Capability, error) {
	return hostaccounts.Capability{Available: true, Backend: "fake"}, nil
}
func (f *fakeHost) List(context.Context) ([]hostaccounts.Account, error) {
	out := make([]hostaccounts.Account, len(f.accounts))
	copy(out, f.accounts)
	return out, nil
}
func (f *fakeHost) Create(_ context.Context, in hostaccounts.CreateInput, actor string) (hostaccounts.Account, error) {
	for _, a := range f.accounts {
		if a.Username == in.Username {
			return hostaccounts.Account{}, hostaccounts.ErrConflict
		}
	}
	f.nextUID++
	a := hostaccounts.Account{
		ID: "0123456789abcdef0123456789abcdef", Username: in.Username,
		Domain: in.Domain, Plan: in.Plan, Home: "/home/" + in.Username, State: "active",
		UID: 20000 + f.nextUID, Revision: 1,
		CreatedAt: time.Date(2026, 10, 15, 6, 34, 0, 0, time.UTC),
	}
	f.accounts = append(f.accounts, a)
	return a, nil
}
func (f *fakeHost) SetState(_ context.Context, id string, in hostaccounts.StateInput, actor string) (hostaccounts.Account, error) {
	for i, a := range f.accounts {
		if a.ID == id {
			if a.Revision != in.ExpectedRevision {
				return hostaccounts.Account{}, hostaccounts.ErrConflict
			}
			f.accounts[i].State = in.State
			f.accounts[i].Revision++
			f.accounts[i].UpdatedAt = time.Date(2026, 10, 15, 7, 0, 0, 0, time.UTC)
			return f.accounts[i], nil
		}
	}
	return hostaccounts.Account{}, hostaccounts.ErrNotFound
}

func newLifecycleServer(t *testing.T, h *fakeHost) (*Server, string) {
	t.Helper()
	ts, token := issueToken(t)
	return New(HostAccounts{Svc: h, Build: "11.138.0.11", Server: "203.0.113.10"}, ts), token
}

func post(t *testing.T, s *Server, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil) // WHM API 1 accepts GET with query params
	r.Header.Set("Authorization", "whm root:"+token)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func decodeEnvelope(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	return body
}

func metadataOf(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	md, ok := body["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("no metadata: %v", body)
	}
	return md
}

func TestCreateAcctSuccess(t *testing.T) {
	h := &fakeHost{}
	s, token := newLifecycleServer(t, h)
	w := post(t, s, "/json-api/createacct?api.version=1&username=newuser&domain=newuser.example.com", token)
	body := decodeEnvelope(t, w)
	md := metadataOf(t, body)
	if md["result"].(float64) != 1 || md["reason"] != "OK" {
		t.Fatalf("metadata = %v", md)
	}
	out := md["output"].(map[string]any)
	raw := out["raw"].(string)
	for _, step := range []string{"Checking input data", "Setting up System User", "Setting up Home Directory", "Account Creation Ok"} {
		if !regexp.MustCompile(regexp.QuoteMeta(step)).MatchString(raw) {
			t.Fatalf("raw log missing step %q: %q", step, raw)
		}
	}
	data := body["data"].(map[string]any)
	if data["ip"] != "203.0.113.10" || data["package"] != "default" {
		t.Fatalf("data = %v", data)
	}
	if len(h.accounts) != 1 || h.accounts[0].Username != "newuser" {
		t.Fatalf("backend accounts = %+v", h.accounts)
	}
}

func TestCreateAcctMissingUsername(t *testing.T) {
	s, token := newLifecycleServer(t, &fakeHost{})
	w := post(t, s, "/json-api/createacct?api.version=1&domain=x.example.com", token)
	md := metadataOf(t, decodeEnvelope(t, w))
	// Observed verbatim on the reference.
	if md["reason"] != `No user name supplied: "username" is a required argument.` {
		t.Fatalf("reason = %q", md["reason"])
	}
	if md["result"].(float64) != 0 {
		t.Fatalf("result = %v", md["result"])
	}
}

func TestCreateAcctInvalidUsername(t *testing.T) {
	s, token := newLifecycleServer(t, &fakeHost{})
	w := post(t, s, "/json-api/createacct?api.version=1&username=bad%20user!!&domain=x.example.com", token)
	md := metadataOf(t, decodeEnvelope(t, w))
	reason := md["reason"].(string)
	// Volatile XID asserted by pattern; stable text by containment (observed).
	if !regexp.MustCompile(`^\(XID [a-z0-9]{6}\) “bad user!!” is not a valid username on this system\.`).MatchString(reason) {
		t.Fatalf("reason = %q", reason)
	}
	if md["result"].(float64) != 0 {
		t.Fatalf("result = %v", md["result"])
	}
}

func TestCreateAcctDuplicate(t *testing.T) {
	h := &fakeHost{}
	s, token := newLifecycleServer(t, h)
	post(t, s, "/json-api/createacct?api.version=1&username=dupuser&domain=a.example.com", token)
	w := post(t, s, "/json-api/createacct?api.version=1&username=dupuser&domain=b.example.com", token)
	md := metadataOf(t, decodeEnvelope(t, w))
	reason := md["reason"].(string)
	if !regexp.MustCompile(`^\(XID [a-z0-9]{6}\) This system already has an account named “dupuser”\.`).MatchString(reason) {
		t.Fatalf("reason = %q", reason)
	}
	if md["result"].(float64) != 0 {
		t.Fatalf("result = %v", md["result"])
	}
	if len(h.accounts) != 1 {
		t.Fatalf("duplicate created backend state: %+v", h.accounts)
	}
}

func TestSuspendUnsuspendLifecycle(t *testing.T) {
	h := &fakeHost{}
	s, token := newLifecycleServer(t, h)
	post(t, s, "/json-api/createacct?api.version=1&username=lifeuser&domain=life.example.com", token)

	w := post(t, s, "/json-api/suspendacct?api.version=1&user=lifeuser&reason=reference+capture", token)
	md := metadataOf(t, decodeEnvelope(t, w))
	if md["result"].(float64) != 1 {
		t.Fatalf("suspend result = %v", md)
	}
	if h.accounts[0].State != "suspended" {
		t.Fatalf("backend state = %q", h.accounts[0].State)
	}

	// Repeat suspend: observed success-with-notice, not an error.
	w = post(t, s, "/json-api/suspendacct?api.version=1&user=lifeuser", token)
	body := decodeEnvelope(t, w)
	md = metadataOf(t, body)
	if md["result"].(float64) != 1 || md["reason"] != "OK" {
		t.Fatalf("repeat suspend metadata = %v", md)
	}
	raw := md["output"].(map[string]any)["raw"].(string)
	if !regexp.MustCompile(`already suspended`).MatchString(raw) {
		t.Fatalf("repeat suspend raw = %q", raw)
	}

	w = post(t, s, "/json-api/unsuspendacct?api.version=1&user=lifeuser", token)
	md = metadataOf(t, decodeEnvelope(t, w))
	if md["result"].(float64) != 1 || h.accounts[0].State != "active" {
		t.Fatalf("unsuspend failed: %v / %+v", md, h.accounts[0])
	}
}

func TestSuspendNoSuchUser(t *testing.T) {
	s, token := newLifecycleServer(t, &fakeHost{})
	w := post(t, s, "/json-api/suspendacct?api.version=1&user=ghost", token)
	md := metadataOf(t, decodeEnvelope(t, w))
	if !regexp.MustCompile(`^API failure: \(XID [a-z0-9]{6}\) You do not have a user named “ghost”\.`).MatchString(md["reason"].(string)) {
		t.Fatalf("reason = %q", md["reason"])
	}
	if md["result"].(float64) != 0 {
		t.Fatalf("result = %v", md["result"])
	}
}

func TestRemoveAcctHonestUnsupported(t *testing.T) {
	h := &fakeHost{}
	s, token := newLifecycleServer(t, h)
	post(t, s, "/json-api/createacct?api.version=1&username=keepme&domain=keep.example.com", token)
	w := post(t, s, "/json-api/removeacct?api.version=1&user=keepme", token)
	md := metadataOf(t, decodeEnvelope(t, w))
	if md["result"].(float64) != 0 {
		t.Fatalf("removeacct must fail closed: %v", md)
	}
	if !regexp.MustCompile(`not implemented on this backend`).MatchString(md["reason"].(string)) {
		t.Fatalf("reason = %q", md["reason"])
	}
	if len(h.accounts) != 1 {
		t.Fatalf("removeacct changed state: %+v", h.accounts)
	}
}

func TestAdapterMappingFidelity(t *testing.T) {
	h := &fakeHost{}
	s, token := newLifecycleServer(t, h)
	post(t, s, "/json-api/createacct?api.version=1&username=mapuser&domain=map.example.com", token)
	post(t, s, "/json-api/suspendacct?api.version=1&user=mapuser&reason=x", token)
	w := post(t, s, "/json-api/listaccts?api.version=1&search=mapuser&searchtype=user", token)
	body := decodeEnvelope(t, w)
	acct := body["data"].(map[string]any)["acct"].([]any)[0].(map[string]any)
	if acct["user"] != "mapuser" || acct["suspended"].(float64) != 1 || acct["shell"] != "/bin/false" {
		t.Fatalf("suspended mapping wrong: %v", acct)
	}
	if acct["theme"] != "jupiter" || acct["mailbox_format"] != "maildir" || acct["diskused"] != "*unknown*" {
		t.Fatalf("defaults mapping wrong: %v", acct)
	}
	if acct["startdate"] != "26 Oct 15 06:34" {
		t.Fatalf("startdate = %v (observed layout '06 Jan 02 15:04')", acct["startdate"])
	}
	if _, ok := acct["ipv6"].([]any); !ok {
		t.Fatalf("ipv6 must be an array: %v", acct["ipv6"])
	}
}

func TestMutationsDeniedWithoutAuth(t *testing.T) {
	s, _ := newLifecycleServer(t, &fakeHost{})
	for _, path := range []string{
		"/json-api/createacct?api.version=1&username=nope&domain=n.example.com",
		"/json-api/suspendacct?api.version=1&user=nope",
	} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s without auth: status = %d", path, w.Code)
		}
	}
}

var _ hostaccounts.Service = (*fakeHost)(nil)
