package hostaccounts

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sifruno/internal/olsweb"
	"strings"
	"sync"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// This typed fake tests journal/recovery logic only. It never provisions an OS
// user and cannot qualify native shadow-utils, ownership or Unix peer behavior.
type fakeNative struct {
	users   map[string]record
	calls   int
	failure string
	changed bool
	// refuseState names a state SetState fails to set, changing nothing.
	refuseState string
	// siteApplies counts ApplySites calls, failed ones included.
	siteApplies int
	// missingPath is a tenant path that is gone. ApplySites and ApplyWeb
	// render the site list as olsweb does and reject it when any file names
	// that path, as OpenLiteSpeed's config test warns for a vhost whose
	// directory is gone, unless the store named that site's vhost as
	// tenantBroken. That is the worst case, a render that rewrote every
	// vhost: the native test also skips a vhost the change did not rewrite.
	missingPath string
	// broken is the tenantBroken set of the last install.
	broken map[string]bool
	// adopts counts AdoptPublicHTML calls.
	adopts int
	// full and cheap count the two kinds of verification per username.
	full, cheap map[string]int
	keys        map[string][]string
	keyWrites   int
	// sites is the last installed site list; web holds the per-user settings.
	sites     []olsweb.Site
	web       map[string]WebState
	webApply  int
	webGrants int
	// wpInstalls counts installs; when wpGate is set, an install signals
	// wpStarted and waits for the gate, so a test can act meanwhile.
	wpInstalls int
	wpStarted  chan struct{}
	wpGate     chan struct{}
	// staged and live model each site's TLS directory by username: the
	// staged chain and key, and the installed leaf. certApply counts
	// installs; tlsGoneWhileServed records a delete that removed a TLS
	// directory while the site was still in the config.
	staged             map[string][2][]byte
	live               map[string]CertificateState
	certApply          int
	tlsGoneWhileServed bool
	// ended counts EndProcesses calls per username. Failure "busy" stands
	// for a process that outlived every pass: EndProcesses reports it, and
	// Delete answers as userdel's refusal, changing nothing.
	ended map[string]int
}

func (f *fakeNative) EndProcesses(_ context.Context, r record) error {
	if f.ended == nil {
		f.ended = map[string]int{}
	}
	f.ended[r.Account.Username]++
	if f.failure == "busy" {
		return errAccountBusy
	}
	return nil
}

func (f *fakeNative) StageCertificate(_ context.Context, r record, chainPEM, keyPEM []byte) error {
	if f.failure == "stage" {
		return ErrUnavailable
	}
	if len(chainPEM) == 0 && len(keyPEM) == 0 {
		delete(f.staged, r.Account.Username)
		return nil
	}
	if f.staged == nil {
		f.staged = map[string][2][]byte{}
	}
	f.staged[r.Account.Username] = [2][]byte{append([]byte(nil), chainPEM...), append([]byte(nil), keyPEM...)}
	return nil
}

// ApplyCertificate installs the staged pair the way the native system does:
// read back, checked again and compared with the journaled leaf.
func (f *fakeNative) ApplyCertificate(_ context.Context, r record, next CertificateState, sites []olsweb.Site, tenantBroken map[string]bool) error {
	f.certApply++
	f.broken = tenantBroken
	switch f.failure {
	case "cert-before":
		return ErrUnavailable
	case "cert-reject":
		return ErrWebRejected
	}
	pair, ok := f.staged[r.Account.Username]
	if !ok {
		return ErrRecovery
	}
	bundle, err := parseCertificate(string(pair[0]), string(pair[1]))
	if err != nil || bundle.state != next {
		return ErrRecovery
	}
	if f.live == nil {
		f.live = map[string]CertificateState{}
	}
	f.live[r.Account.Username] = next
	f.sites = append([]olsweb.Site(nil), sites...)
	if f.failure == "cert-after" {
		return ErrUnavailable
	}
	return nil
}

func (f *fakeNative) InstallWordPress(_ context.Context, r record, in WordPressInput) (WordPressResult, error) {
	f.wpInstalls++
	if f.wpGate != nil {
		f.wpStarted <- struct{}{}
		<-f.wpGate
	}
	if f.failure == "wp-fail" {
		return WordPressResult{}, &InstallError{Step: "download", Detail: installDetail([]byte("Error: could not reach wordpress.org with "+in.DBPassword), in.DBPassword)}
	}
	return WordPressResult{Version: "6.8.3"}, nil
}

func (f *fakeNative) GrantWebAccess(_ context.Context, r record) error {
	f.webGrants++
	if f.failure == "grant" {
		return ErrRecovery
	}
	return nil
}
func (f *fakeNative) ApplyWeb(_ context.Context, r record, previous, next WebState, sites []olsweb.Site, tenantBroken map[string]bool) error {
	f.webApply++
	f.broken = tenantBroken
	switch f.failure {
	case "web-before":
		return ErrUnavailable
	case "web-reject":
		return ErrWebRejected
	}
	if f.namesMissingPath(sites, tenantBroken) {
		return ErrWebRejected
	}
	if f.web == nil {
		f.web = map[string]WebState{}
	}
	f.web[r.Account.Username] = next
	f.sites = append([]olsweb.Site(nil), sites...)
	if f.failure == "web-after" {
		return ErrUnavailable
	}
	return nil
}
func (f *fakeNative) ApplySites(_ context.Context, sites []olsweb.Site, tenantBroken map[string]bool) error {
	f.siteApplies++
	f.broken = tenantBroken
	switch f.failure {
	case "sites":
		return ErrUnavailable
	case "sites-reject":
		return ErrWebRejected
	}
	if f.namesMissingPath(sites, tenantBroken) {
		return ErrWebRejected
	}
	f.sites = append([]olsweb.Site(nil), sites...)
	return nil
}

// namesMissingPath reports whether a vhost the test judges names
// missingPath. The server fragment names every home as a vhRoot, so the
// vhosts are rendered one at a time.
func (f *fakeNative) namesMissingPath(sites []olsweb.Site, tenantBroken map[string]bool) bool {
	if f.missingPath == "" {
		return false
	}
	for _, site := range sites {
		if tenantBroken[olsweb.NamePrefix+site.Name] {
			continue
		}
		if strings.Contains(string(renderAtHomeRoot([]olsweb.Site{site})[olsweb.VhostConfigPath(site.Name)]), f.missingPath) {
			return true
		}
	}
	return false
}

// renderAtHomeRoot renders a site list as the broker installs it. The
// fixture's homes are in a temporary directory and olsweb wants the real
// homes root, so each document root moves to /home/<user>/public_html.
func renderAtHomeRoot(sites []olsweb.Site) map[string][]byte {
	real := make([]olsweb.Site, len(sites))
	for i, site := range sites {
		site.DocRoot = olsweb.HomeRoot + "/" + site.Username + "/public_html"
		real[i] = site
	}
	files, err := olsweb.Render(webServer(real))
	if err != nil {
		panic(err)
	}
	return files
}

func (f *fakeNative) GuardState(string) error   { return nil }
func (f *fakeNative) GuardHomes([]record) error { return nil }
func (f *fakeNative) Plan(_ context.Context, name string) (int, int, error) {
	if _, ok := f.users[name]; ok {
		return 0, 0, ErrConflict
	}
	// Lowest free ID, like the native allocator, so deletes do not make the
	// fake hand out an ID that is still in use.
	used := map[int]bool{}
	for _, r := range f.users {
		used[r.Account.UID] = true
	}
	uid := 20000
	for used[uid] {
		uid++
	}
	return uid, uid, nil
}
func fakeOwned(r record) ownership {
	return ownership{Home: fileIdentity{1, uint64(r.Account.UID)}, Public: fileIdentity{1, uint64(r.Account.UID) + 100000}, Marker: fileIdentity{1, uint64(r.Account.UID) + 200000}}
}
func (f *fakeNative) Create(ctx context.Context, r record, persist func(ownership) error) (ownership, error) {
	f.calls++
	if f.failure == "before" {
		return ownership{}, ErrUnavailable
	}
	owned := fakeOwned(r)
	r.Ownership = owned
	r.Account.State = "active"
	f.users[r.Account.Username] = r
	if persist(owned) != nil {
		return ownership{}, ErrRecovery
	}
	if f.failure == "after" {
		return ownership{}, ErrUnavailable
	}
	return owned, nil
}
func (f *fakeNative) RecoverCreate(ctx context.Context, r record, persist func(ownership) error) (ownership, error) {
	actual, ok := f.users[r.Account.Username]
	if !ok || actual.Tag != r.Tag || actual.Account.UID != r.Account.UID || actual.Account.GID != r.Account.GID || actual.Account.Home != r.Account.Home {
		return ownership{}, ErrRecovery
	}
	if persist(actual.Ownership) != nil {
		return ownership{}, ErrRecovery
	}
	return actual.Ownership, nil
}
func (f *fakeNative) Delete(_ context.Context, r record) error {
	actual, ok := f.users[r.Account.Username]
	if !ok {
		return nil // already gone: safe retry
	}
	if actual.Tag != r.Tag || actual.Account.UID != r.Account.UID || actual.Account.GID != r.Account.GID || actual.Account.Home != r.Account.Home {
		return ErrRecovery
	}
	if f.failure == "busy" {
		return errAccountBusy
	}
	delete(f.users, r.Account.Username)
	// The native delete removes the site's TLS directory with the account.
	if _, has := f.live[r.Account.Username]; has {
		for _, s := range f.sites {
			if s.Name == siteName(r.Account.ID) {
				f.tlsGoneWhileServed = true
			}
		}
	}
	delete(f.live, r.Account.Username)
	delete(f.staged, r.Account.Username)
	return nil
}

// The fake's ownership.Public stands for the folder a tenant may rename,
// replace or chmod; everything else in a record (tag, IDs, home, marker,
// and f.changed for any of them) only root can change.
func (f *fakeNative) VerifyAccountIdentity(r record) error {
	if f.cheap != nil {
		f.cheap[r.Account.Username]++
	}
	actual, ok := f.users[r.Account.Username]
	if !ok || f.changed || actual.Tag != r.Tag || actual.Account.UID != r.Account.UID || actual.Account.GID != r.Account.GID || r.Ownership.Home != actual.Ownership.Home || r.Ownership.Marker != actual.Ownership.Marker {
		return ErrRecovery
	}
	return nil
}

// VerifyAccount adds the state observation, standing in for the lock and
// expiry check that the native system makes with passwd and chage. Like
// that check, it compares only an active or suspended state, so a delete's
// empty target state passes.
func (f *fakeNative) VerifyAccount(_ context.Context, r record) error {
	if f.full != nil {
		f.full[r.Account.Username]++
	}
	actual, ok := f.users[r.Account.Username]
	if !ok || f.changed || actual.Tag != r.Tag || actual.Account.UID != r.Account.UID || actual.Account.GID != r.Account.GID || (r.Account.State != "" && actual.Account.State != r.Account.State) || r.Ownership.Home != actual.Ownership.Home || r.Ownership.Marker != actual.Ownership.Marker {
		return ErrRecovery
	}
	return nil
}

func (f *fakeNative) VerifySiteFiles(r record) error {
	if actual, ok := f.users[r.Account.Username]; !ok || r.Ownership.Public != actual.Ownership.Public {
		return ErrRecovery
	}
	return nil
}

func (f *fakeNative) VerifyIdentity(r record) error {
	if e := f.VerifyAccountIdentity(r); e != nil {
		return e
	}
	return f.VerifySiteFiles(r)
}

func (f *fakeNative) Verify(ctx context.Context, r record) error {
	if e := f.VerifyAccount(ctx, r); e != nil {
		return e
	}
	return f.VerifySiteFiles(r)
}

// AdoptPublicHTML returns the tenant's current public_html, as the native
// step does after it checked it through handles; failure "adopt" stands for
// a public_html that is missing, a link or not the account's.
func (f *fakeNative) AdoptPublicHTML(_ context.Context, r record) (fileIdentity, error) {
	f.adopts++
	actual, ok := f.users[r.Account.Username]
	if f.failure == "adopt" || !ok || actual.Ownership.Home != r.Ownership.Home {
		return fileIdentity{}, ErrConflict
	}
	return actual.Ownership.Public, nil
}

// tenantMovesPublicHTML is what a tenant can do in its own home: rename
// public_html away and make a new one. The broker sees another directory
// than the one it recorded, and OpenLiteSpeed warns for a vhost that names
// the old path (missingPath models the warning).
func tenantMovesPublicHTML(f *fakeNative, username string) {
	actual := f.users[username]
	actual.Ownership.Public.Ino += 7
	f.users[username] = actual
	f.missingPath = olsweb.HomeRoot + "/" + username + "/public_html"
}
func (f *fakeNative) VerifySSHKeys(r record, canonical []string) error {
	if f.failure == "keys-drift" {
		return ErrRecovery
	}
	got := f.keys[r.Account.Username]
	if len(got) != len(canonical) {
		return ErrRecovery
	}
	for i := range got {
		if got[i] != canonical[i] {
			return ErrRecovery
		}
	}
	return nil
}
func (f *fakeNative) SetSSHKeys(_ context.Context, r record, canonical []string) error {
	f.keyWrites++
	if f.failure == "keys-before" {
		return ErrUnavailable
	}
	if f.keys == nil {
		f.keys = map[string][]string{}
	}
	f.keys[r.Account.Username] = append([]string(nil), canonical...)
	if f.failure == "keys-after" {
		return ErrUnavailable
	}
	return nil
}
func (f *fakeNative) SetState(_ context.Context, r record, state string) error {
	f.calls++
	if state == f.refuseState {
		return ErrUnavailable
	}
	actual := f.users[r.Account.Username]
	actual.Account.State = state
	f.users[r.Account.Username] = actual
	if f.failure == "state-after" {
		return ErrUnavailable
	}
	return nil
}
func setupStore(t *testing.T) (*store, *fakeNative, BrokerOptions) {
	t.Helper()
	root := t.TempDir()
	opts := BrokerOptions{StateDir: filepath.Join(root, "broker"), HomesDir: filepath.Join(root, "homes"), SocketPath: filepath.Join(root, "socket", "control.sock"), ControllerUID: 2000}
	f := &fakeNative{users: map[string]record{}}
	s, e := openStore(context.Background(), opts, f)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.close() })
	return s, f, opts
}
func createFixture(t *testing.T, s *store) Account {
	t.Helper()
	a, e := s.create(context.Background(), CreateInput{Username: "fixtureacct", Domain: "fixture.test", Reason: "Synthetic core verification"}, "test operator")
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func TestJournalLifecycleAndReservation(t *testing.T) {
	s, f, opts := setupStore(t)
	a := createFixture(t, s)
	if a.State != "active" || a.Revision != 1 || a.UID != 20000 || a.GID != a.UID || a.Home != filepath.Join(opts.HomesDir, a.Username) {
		t.Fatalf("unexpected account %+v", a)
	}
	for _, input := range []CreateInput{{"fixtureacct", "different.test", "", "Duplicate username"}, {"otheracct", "fixture.test", "", "Duplicate domain"}} {
		if _, e := s.create(context.Background(), input, "test operator"); e != ErrConflict {
			t.Fatal(e)
		}
	}
	if _, e := s.setState(context.Background(), a.ID, StateInput{"suspended", 99, "Stale revision"}, "test operator"); e != ErrConflict {
		t.Fatal(e)
	}
	a, e := s.setState(context.Background(), a.ID, StateInput{"suspended", a.Revision, "Restrict PAM admission"}, "test operator")
	if e != nil || a.State != "suspended" || a.Revision != 2 {
		t.Fatal(a, e)
	}
	a, e = s.setState(context.Background(), a.ID, StateInput{"active", a.Revision, "Clear expiry only"}, "test operator")
	if e != nil || a.Revision != 3 {
		t.Fatal(a, e)
	}
	if f.calls != 3 {
		t.Fatal("unexpected mutations", f.calls)
	}
	var events []operationEvent
	e = s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(historyBucket).ForEach(func(_, b []byte) error {
			var e operationEvent
			if json.Unmarshal(b, &e) != nil {
				t.Fatal("invalid event")
			}
			events = append(events, e)
			return nil
		})
	})
	if e != nil || len(events) != 6 {
		t.Fatal(e, len(events))
	}
	for i, e := range events {
		if e.Sequence != uint64(i+1) || e.Actor != "test operator" || e.Reason == "" || e.RecordedAt.IsZero() {
			t.Fatalf("incomplete history %+v", e)
		}
	}
	if events[0].Before != nil || events[2].Before.State != "active" || events[3].After.State != "suspended" || events[5].After.Revision != 3 {
		t.Fatal("before/after history wrong")
	}
	if s.close() != nil {
		t.Fatal("close failed")
	}
	reopened, e := openStore(context.Background(), opts, f)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.close()
	items, e := reopened.list(context.Background())
	if e != nil || len(items) != 1 || items[0] != a {
		t.Fatal(items, e)
	}
}

func TestGeneratedOwnershipTagIsPasswdFieldSafe(t *testing.T) {
	s, _, _ := setupStore(t)
	a := createFixture(t, s)
	items, e := s.records()
	if e != nil || len(items) != 1 {
		t.Fatal("record observation", e)
	}
	tag := items[0].Tag
	if tag != "sifruno-managed-"+a.ID || strings.ContainsAny(tag, ":\n\r\x00") {
		t.Fatal("unsafe generated GECOS field")
	}
	fields := strings.Split("fixtureacct:x:20000:20000:"+tag+":/home/fixtureacct:/usr/sbin/nologin", ":")
	if len(fields) != 7 || fields[4] != tag {
		t.Fatal("passwd field boundary changed")
	}
	legacy := items[0]
	legacy.Tag = "sifruno-managed:" + a.ID
	if s.save(legacy) != nil {
		t.Fatal("fixture save")
	}
	if _, e = s.records(); e != ErrRecovery {
		t.Fatal("invalid legacy tag was admitted", e)
	}
}
func TestInterruptedCreateRetainsIdentity(t *testing.T) {
	for _, phase := range []string{"before", "after"} {
		t.Run(phase, func(t *testing.T) {
			s, f, opts := setupStore(t)
			f.failure = phase
			if _, e := s.create(context.Background(), CreateInput{"pendingacct", "pending.test", "", "Interrupted synthetic create"}, "test operator"); e != ErrRecovery {
				t.Fatal(e)
			}
			items, e := s.list(context.Background())
			if e != nil || len(items) != 1 || items[0].State != "recovery_required" || !idPattern.MatchString(items[0].ID) || items[0].UID != 20000 {
				t.Fatal(items, e)
			}
			original := items[0]
			if _, e = s.create(context.Background(), CreateInput{"anotheracct", "another.test", "", "Blocked by recovery"}, "test operator"); e != ErrRecovery {
				t.Fatal(e)
			}
			cap, e := s.capability(context.Background())
			if e != nil || cap.Available || cap.Reason != "managed_account_recovery_required" {
				t.Fatal(cap, e)
			}
			s.close()
			f.failure = ""
			reopened, e := openStore(context.Background(), opts, f)
			if e != nil {
				t.Fatal(e)
			}
			defer reopened.close()
			items, e = reopened.list(context.Background())
			if e != nil || items[0].ID != original.ID || items[0].UID != original.UID {
				t.Fatal(items, e)
			}
			want := "recovery_required"
			if phase == "after" {
				want = "active"
			}
			if items[0].State != want {
				t.Fatal(items)
			}
			if f.calls != 1 {
				t.Fatal("recovery recreated native user")
			}
		})
	}
}
func TestInterruptedStateAndExternalConflict(t *testing.T) {
	s, f, opts := setupStore(t)
	a := createFixture(t, s)
	f.failure = "state-after"
	if _, e := s.setState(context.Background(), a.ID, StateInput{"suspended", 1, "Interrupted state observation"}, "test operator"); e != ErrRecovery {
		t.Fatal(e)
	}
	s.close()
	f.failure = ""
	reopened, e := openStore(context.Background(), opts, f)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.close()
	items, e := reopened.list(context.Background())
	if e != nil || items[0].State != "suspended" || items[0].Revision != 2 {
		t.Fatal(items, e)
	}
	f.changed = true
	items, e = reopened.list(context.Background())
	if e != nil || items[0].State != "recovery_required" {
		t.Fatal(items, e)
	}
	if _, e = reopened.setState(context.Background(), a.ID, StateInput{"active", 2, "External conflict"}, "test operator"); e != ErrRecovery {
		t.Fatal(e)
	}
}
func TestImmutableJournalReplayRejectsTamper(t *testing.T) {
	s, f, opts := setupStore(t)
	a := createFixture(t, s)
	if e := s.db.Update(func(tx *bolt.Tx) error {
		key := eventKey(a.ID, 1)
		var e operationEvent
		json.Unmarshal(tx.Bucket(historyBucket).Get(key), &e)
		e.After.UID++
		b, _ := json.Marshal(e)
		return tx.Bucket(historyBucket).Put(key, b)
	}); e != nil {
		t.Fatal(e)
	}
	if _, e := s.list(context.Background()); e != ErrRecovery {
		t.Fatal(e)
	}
	s.close()
	if reopened, e := openStore(context.Background(), opts, f); e != ErrRecovery {
		if reopened != nil {
			reopened.close()
		}
		t.Fatal(e)
	}
}
func TestSerialCreateReservation(t *testing.T) {
	s, f, _ := setupStore(t)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := s.create(context.Background(), CreateInput{"serialacct", "serial.test", "", "Concurrent synthetic request"}, "test operator")
			results <- e
		}()
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for e := range results {
		if e == nil {
			success++
		} else if e == ErrConflict {
			conflict++
		} else {
			t.Fatal(e)
		}
	}
	if success != 1 || conflict != 1 || f.calls != 1 {
		t.Fatal(success, conflict, f.calls)
	}
}
func TestStrictBrokerJSONNeverInvokesMutation(t *testing.T) {
	s, f, _ := setupStore(t)
	valid := `{"actor":"test operator","input":{"username":"jsonacct","domain":"json.test","reason":"Synthetic request"}}`
	bad := []string{strings.Replace(valid, `"actor":"test operator"`, `"actor":"x","actor":"y"`, 1), strings.Replace(valid, `"username":"jsonacct"`, `"username":"a","username":"b"`, 1), strings.Replace(valid, `"username"`, `"Username"`, 1), strings.Replace(valid, `"reason":"Synthetic request"`, `"reason":null`, 1), strings.Replace(valid, `"reason":"Synthetic request"`, `"reason":"`+string([]byte{0xff})+`"`, 1), valid + ` {}`, `{"actor":"test operator","input":null}`, strings.Repeat("x", MaxRequestBytes+1)}
	for _, body := range bad {
		req := httptest.NewRequest("POST", "http://unix/v1/accounts", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler(s).ServeHTTP(w, req)
		if w.Code != 400 || strings.Contains(w.Body.String(), "test operator") {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if f.calls != 0 {
		t.Fatal("malformed request mutated")
	}
	req := httptest.NewRequest("POST", "http://unix/v1/accounts", strings.NewReader(valid))
	req.Header.Set("Content-Type", "application/json; charset=latin1")
	w := httptest.NewRecorder()
	handler(s).ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
	req = httptest.NewRequest("POST", "http://unix/v1/accounts", strings.NewReader(valid))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	handler(s).ServeHTTP(w, req)
	if w.Code != 200 || f.calls != 1 {
		t.Fatal(w.Code)
	}
}
func TestInputLimitsAndUnavailableService(t *testing.T) {
	s, f, _ := setupStore(t)
	for _, name := range []string{"root", "nginx", "ab", "-inject", "MixedCase", strings.Repeat("a", 33), "a/b"} {
		if _, e := s.create(context.Background(), CreateInput{name, "fixture.test", "", "Invalid username"}, "test operator"); e != ErrInvalid {
			t.Fatal(name, e)
		}
	}
	for _, domain := range []string{"localhost", "https://fixture.test", "UPPER.test", "127.0.0.1", "a..test", "-a.test"} {
		if _, e := s.create(context.Background(), CreateInput{"validacct", domain, "", "Invalid domain"}, "test operator"); e != ErrInvalid {
			t.Fatal(domain, e)
		}
	}
	if f.calls != 0 {
		t.Fatal("invalid inputs mutated")
	}
	cap, e := NewClient("").Capability(context.Background())
	if e != nil || cap.Available || len(cap.Restrictions) == 0 {
		t.Fatal(cap, e)
	}
	if _, e = NewClient("").List(context.Background()); e != ErrUnavailable {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = s.create(ctx, CreateInput{"validacct", "valid.test", "", "Canceled request"}, "test operator"); e != ErrUnavailable {
		t.Fatal(e)
	}
	if f.calls != 0 {
		t.Fatal("cancel mutated")
	}
}
func TestForeignStateNotAdopted(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "foreign")
	os.Mkdir(state, 0700)
	os.WriteFile(filepath.Join(state, "unowned"), []byte("isolated"), 0600)
	f := &fakeNative{users: map[string]record{}}
	_, e := openStore(context.Background(), BrokerOptions{StateDir: state}, f)
	if !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
}
