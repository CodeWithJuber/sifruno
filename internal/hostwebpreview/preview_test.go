package hostwebpreview

import (
	"context"
	"errors"
	"reflect"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/hostweb"
	"strings"
	"testing"
)

type fixtureProvider struct {
	accounts        []hostaccounts.Account
	calls, verifies int
	finalErr        error
	failVerify      int
	cancel          context.CancelFunc
}
type fixtureLease struct {
	p   *fixtureProvider
	ctx context.Context
}

func (l fixtureLease) Context() context.Context { return l.ctx }
func (l fixtureLease) Accounts() []hostaccounts.Account {
	return append([]hostaccounts.Account(nil), l.p.accounts...)
}
func (l fixtureLease) Verify(context.Context) error {
	l.p.verifies++
	if l.p.verifies == l.p.failVerify {
		return hostaccounts.ErrRecovery
	}
	return nil
}
func (p *fixtureProvider) WithSnapshot(ctx context.Context, fn func(hostaccounts.SnapshotLease) error) error {
	p.calls++
	err := fn(fixtureLease{p, ctx})
	if err != nil {
		return err
	}
	if p.cancel != nil {
		p.cancel()
	}
	return p.finalErr
}
func fixtureAccount(id, name, state string) hostaccounts.Account {
	return hostaccounts.Account{ID: strings.Repeat(id, 32), Username: name, Domain: name + ".example.test", Home: "/srv/managed/" + name, PublicHTML: "/srv/managed/" + name + "/public_html", UID: 20001 + int(id[0]), GID: 20001 + int(id[0]), State: state, Revision: 1}
}
func profile() hostweb.Profile {
	return BrokerProfile(hostaccounts.BrokerOptions{HomesDir: "/srv/managed", ControllerUID: 2000})
}
func TestPreviewCanonicalCompilerMetadata(t *testing.T) {
	a, b := fixtureAccount("a", "alpha", "active"), fixtureAccount("b", "bravo", "suspended")
	p := &fixtureProvider{accounts: []hostaccounts.Account{b, a}}
	svc := New(profile(), p)
	one, err := svc.Preview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p.accounts = []hostaccounts.Account{a, b}
	two, err := svc.Preview(context.Background())
	if err != nil || !reflect.DeepEqual(one, two) {
		t.Fatal("noncanonical preview")
	}
	compiled, err := hostweb.Compile(profile(), p.accounts)
	if err != nil {
		t.Fatal(err)
	}
	if one.BundleSHA256 != compiled.SHA256 || one.Accounts != 2 || one.ActiveAccounts != 1 || one.SuspendedAccounts != 1 || len(one.Files) != 3 || p.verifies != 4 {
		t.Fatal("metadata mismatch")
	}
	for i, f := range compiled.Files {
		got := one.Files[i]
		if got.Path != f.Path || got.Bytes != len(f.Data) || got.Mode != uint32(f.Mode.Perm()) || got.SHA256 != f.SHA256 {
			t.Fatal("compiler output mismatch")
		}
	}
}
func TestPreviewDiscardsFailedOrCancelledSnapshot(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fail   int
		final  error
		cancel bool
	}{{"initialverify", 1, nil, false}, {"lastcallbackverify", 2, nil, false}, {"providerfinal", 0, hostaccounts.ErrRecovery, false}, {"cancelaftercallback", 0, nil, true}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := &fixtureProvider{accounts: []hostaccounts.Account{fixtureAccount("a", "alpha", "active")}, failVerify: tc.fail, finalErr: tc.final}
			if tc.cancel {
				p.cancel = cancel
			}
			got, err := New(profile(), p).Preview(ctx)
			if err == nil || !reflect.DeepEqual(got, hostaccounts.WebPreview{}) {
				t.Fatal("failed snapshot leaked output")
			}
		})
	}
}
func TestPreviewInvalidProfileAccountsAndContext(t *testing.T) {
	p := &fixtureProvider{}
	bad := profile()
	bad.Name = "unsupported"
	got, err := New(bad, p).Preview(context.Background())
	if !errors.Is(err, hostaccounts.ErrUnavailable) || got.Files != nil || p.calls != 0 {
		t.Fatal("invalid profile admitted")
	}
	if _, err = New(profile(), nil).Preview(context.Background()); err == nil {
		t.Fatal("nil provider admitted")
	}
	svc := New(profile(), p)
	if _, err = svc.Preview(nil); !errors.Is(err, hostaccounts.ErrInvalid) {
		t.Fatal("nilcontext")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = svc.Preview(ctx); err == nil || p.calls != 0 {
		t.Fatal("cancelled admitted")
	}
	p.accounts = []hostaccounts.Account{fixtureAccount("a", "alpha", "recovery_required")}
	if got, err = svc.Preview(context.Background()); err == nil || got.Files != nil {
		t.Fatal("invalid account admitted")
	}
}
