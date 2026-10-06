package accesspolicy

import (
	"fmt"
	"strings"
	"testing"
)

func actor(s string) ActorID {
	id, err := ParseActorID(s)
	if err != nil {
		panic(err)
	}
	return id
}
func account(n int) AccountID {
	id, err := ParseAccountID(fmt.Sprintf("%032x", n))
	if err != nil {
		panic(err)
	}
	return id
}
func fixture(t *testing.T) (*Policy, []ActorBinding, []AccountBinding) {
	t.Helper()
	actors := []ActorBinding{
		{Actor: actor("admin"), Role: ServerAdmin},
		{Actor: actor("reseller-a"), Role: Reseller},
		{Actor: actor("reseller-b"), Role: Reseller},
		{Actor: actor("user-a"), Role: AccountUser, Assigned: account(1)},
		{Actor: actor("user-b"), Role: AccountUser, Assigned: account(2)},
	}
	accounts := []AccountBinding{{account(1), actor("reseller-a")}, {account(2), actor("reseller-b")}, {account(3), actor("admin")}}
	p, err := NewPolicy(actors, accounts)
	if err != nil {
		t.Fatal(err)
	}
	return p, actors, accounts
}

func TestPermissionMatrix(t *testing.T) {
	p, _, _ := fixture(t)
	resources := []Resource{ServerResource(), AccountResource(account(1)), AccountResource(account(2)), AccountResource(account(3)), AccountResource(account(99)), {}, AccountResource(AccountID{}), {kind: 255}, {kind: 1, account: account(1)}}
	// Each row independently specifies all allowed (action, resource) pairs.
	type permit struct {
		action   Action
		resource Resource
	}
	rows := []struct {
		name    string
		id      ActorID
		allowed []permit
	}{
		{"admin", actor("admin"), []permit{{ReadCapability, resources[0]}, {ListAccounts, resources[0]}, {CreateAccount, resources[0]}, {ReadAccount, resources[1]}, {ReadAccount, resources[2]}, {ReadAccount, resources[3]}, {SetAccountState, resources[1]}, {SetAccountState, resources[2]}, {SetAccountState, resources[3]}}},
		{"reseller-a", actor("reseller-a"), []permit{{ReadAccount, resources[1]}, {SetAccountState, resources[1]}}},
		{"reseller-b", actor("reseller-b"), []permit{{ReadAccount, resources[2]}, {SetAccountState, resources[2]}}},
		{"user-a", actor("user-a"), []permit{{ReadAccount, resources[1]}}},
		{"user-b", actor("user-b"), []permit{{ReadAccount, resources[2]}}},
		{"unknown", actor("stranger"), nil}, {"zero", ActorID{}, nil},
		{"audit-string", actor("local-operator"), nil},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			for n := 0; n <= 255; n++ {
				for i, resource := range resources {
					want := false
					for _, allowed := range row.allowed {
						if allowed.action == Action(n) && allowed.resource == resource {
							want = true
						}
					}
					if got := p.Authorize(row.id, Action(n), resource); got != want {
						t.Fatalf("action %d resource %d: got %v want %v", n, i, got, want)
					}
				}
			}
		})
	}
}

func TestInvalidSnapshotsFailAsAWhole(t *testing.T) {
	_, baseActors, baseAccounts := fixture(t)
	cases := []struct {
		name   string
		change func(*[]ActorBinding, *[]AccountBinding)
	}{
		{"no actors", func(a *[]ActorBinding, b *[]AccountBinding) { *a = nil }},
		{"zero actor", func(a *[]ActorBinding, b *[]AccountBinding) { (*a)[0].Actor = ActorID{} }},
		{"malformed actor", func(a *[]ActorBinding, b *[]AccountBinding) { (*a)[0].Actor = ActorID{value: "ADMIN"} }},
		{"zero role", func(a *[]ActorBinding, b *[]AccountBinding) { (*a)[0].Role = 0 }},
		{"unknown role", func(a *[]ActorBinding, b *[]AccountBinding) { (*a)[0].Role = 255 }},
		{"admin assignment", func(a *[]ActorBinding, b *[]AccountBinding) { (*a)[0].Assigned = account(1) }},
		{"reseller assignment", func(a *[]ActorBinding, b *[]AccountBinding) { (*a)[1].Assigned = account(1) }},
		{"user unassigned", func(a *[]ActorBinding, b *[]AccountBinding) { (*a)[3].Assigned = AccountID{} }},
		{"user unknown assignment", func(a *[]ActorBinding, b *[]AccountBinding) { (*a)[3].Assigned = account(99) }},
		{"duplicate actor", func(a *[]ActorBinding, b *[]AccountBinding) { *a = append(*a, (*a)[0]) }},
		{"role escalation duplicate", func(a *[]ActorBinding, b *[]AccountBinding) {
			*a = append(*a, ActorBinding{Actor: actor("user-a"), Role: ServerAdmin})
		}},
		{"zero account", func(a *[]ActorBinding, b *[]AccountBinding) { (*b)[0].Account = AccountID{} }},
		{"malformed account", func(a *[]ActorBinding, b *[]AccountBinding) { (*b)[0].Account = AccountID{value: "alias"} }},
		{"duplicate account", func(a *[]ActorBinding, b *[]AccountBinding) { *b = append(*b, (*b)[0]) }},
		{"conflicting owner", func(a *[]ActorBinding, b *[]AccountBinding) {
			*b = append(*b, AccountBinding{account(1), actor("reseller-b")})
		}},
		{"zero owner", func(a *[]ActorBinding, b *[]AccountBinding) { (*b)[0].Owner = ActorID{} }},
		{"unknown owner", func(a *[]ActorBinding, b *[]AccountBinding) { (*b)[0].Owner = actor("missing") }},
		{"account user cannot own", func(a *[]ActorBinding, b *[]AccountBinding) { (*b)[0].Owner = actor("user-a") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := append([]ActorBinding(nil), baseActors...)
			b := append([]AccountBinding(nil), baseAccounts...)
			tc.change(&a, &b)
			p, err := NewPolicy(a, b)
			if err != ErrInvalid || p != nil {
				t.Fatalf("expected nil policy and ErrInvalid; got %v, %v", p, err)
			}
		})
	}
}

func TestBoundsAndEmptyAccountInventory(t *testing.T) {
	actors := make([]ActorBinding, MaxActors)
	for i := range actors {
		actors[i] = ActorBinding{Actor: actor(fmt.Sprintf("actor-%d", i)), Role: ServerAdmin}
	}
	accounts := make([]AccountBinding, MaxAccounts)
	for i := range accounts {
		accounts[i] = AccountBinding{account(i), actors[0].Actor}
	}
	if _, err := NewPolicy(actors, accounts); err != nil {
		t.Fatal("exact capacity rejected", err)
	}
	if p, err := NewPolicy(append(actors, ActorBinding{Actor: actor("extra"), Role: Reseller}), accounts); p != nil || err != ErrInvalid {
		t.Fatal("actor capacity not enforced")
	}
	if p, err := NewPolicy(actors, append(accounts, AccountBinding{account(MaxAccounts), actors[0].Actor})); p != nil || err != ErrInvalid {
		t.Fatal("account capacity not enforced")
	}
	p, err := NewPolicy(actors[:1], nil)
	if err != nil || !p.Authorize(actors[0].Actor, CreateAccount, ServerResource()) || p.Authorize(actors[0].Actor, ReadAccount, AccountResource(account(0))) {
		t.Fatal("empty inventory must permit admin creation but deny unknown account")
	}
}

func TestSnapshotIsolationAndReplacement(t *testing.T) {
	p, actors, accounts := fixture(t)
	actors[3] = ActorBinding{Actor: actor("user-a"), Role: ServerAdmin}
	accounts[0].Owner = actor("reseller-b")
	if p.Authorize(actor("user-a"), CreateAccount, ServerResource()) || p.Authorize(actor("reseller-b"), ReadAccount, AccountResource(account(1))) {
		t.Fatal("caller slice changes mutated existing snapshot")
	}
	replacement, err := NewPolicy(actors, accounts)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Authorize(actor("reseller-a"), SetAccountState, AccountResource(account(1))) {
		t.Fatal("former owner retained access in replacement")
	}
	if !replacement.Authorize(actor("reseller-b"), SetAccountState, AccountResource(account(1))) {
		t.Fatal("replacement did not apply trusted transfer")
	}
	// A snapshot intentionally cannot revoke old references. Integration must
	// replace/dispose them rather than retaining p after a trust change.
	if !p.Authorize(actor("reseller-a"), SetAccountState, AccountResource(account(1))) {
		t.Fatal("snapshot unexpectedly changed")
	}
}

func TestUnrelatedAdmissionsDoNotExpandTenantRights(t *testing.T) {
	original, actors, accounts := fixture(t)
	actors = append(actors, ActorBinding{Actor: actor("other-admin"), Role: ServerAdmin})
	accounts = append(accounts, AccountBinding{account(4), actor("other-admin")})
	expanded, err := NewPolicy(actors, accounts)
	if err != nil {
		t.Fatal(err)
	}
	for _, who := range []string{"reseller-a", "user-a"} {
		for n := 0; n <= 255; n++ {
			for i := 1; i <= 5; i++ {
				r := AccountResource(account(i))
				if original.Authorize(actor(who), Action(n), r) != expanded.Authorize(actor(who), Action(n), r) {
					t.Fatal("unrelated admission expanded tenant rights")
				}
			}
		}
	}
}

func TestZeroPolicyAndNoRequestAllocations(t *testing.T) {
	p, _, _ := fixture(t)
	id, r := actor("admin"), AccountResource(account(1))
	for _, empty := range []*Policy{nil, {}} {
		for n := 0; n <= 255; n++ {
			if empty.Authorize(id, Action(n), r) || empty.Authorize(id, Action(n), ServerResource()) {
				t.Fatal("empty policy allowed request")
			}
		}
	}
	if n := testing.AllocsPerRun(1000, func() { p.Authorize(id, ReadAccount, r); p.Authorize(actor("unknown"), ReadAccount, r) }); n != 0 {
		t.Fatalf("Authorize allocations: %v", n)
	}
}

func TestCanonicalIdentityParsing(t *testing.T) {
	for _, s := range []string{"", " Admin", "Admin", "admin ", "a/b", "a.b", "a*", "a\x00", "a\n", "é", "аdmin", "0admin", strings.Repeat("a", 65)} {
		if id, err := ParseActorID(s); err != ErrInvalid || id != (ActorID{}) {
			t.Errorf("accepted actor %q", s)
		}
	}
	for _, s := range []string{"a", "local-operator", "actor_1", strings.Repeat("a", 64)} {
		if id, err := ParseActorID(s); err != nil || id.String() != s {
			t.Errorf("rejected actor %q", s)
		}
	}
	for _, s := range []string{"", "*", strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("A", 32), strings.Repeat("g", 32), " " + strings.Repeat("a", 31), strings.Repeat("a", 31) + "\x00"} {
		if id, err := ParseAccountID(s); err != ErrInvalid || id != (AccountID{}) {
			t.Errorf("accepted account %q", s)
		}
	}
	if id, err := ParseAccountID(strings.Repeat("a", 32)); err != nil || id.String() != strings.Repeat("a", 32) {
		t.Fatal("native format rejected")
	}
}

func FuzzIdentityParsing(f *testing.F) {
	for _, s := range []string{"", "admin", strings.Repeat("a", 32), "../root", "Ａdmin", "a\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		id, err := ParseActorID(s)
		if err == nil {
			if id.String() != s || len(s) < 1 || len(s) > 64 {
				t.Fatal("actor canonical bound")
			}
			round, err := ParseActorID(id.String())
			if err != nil || round != id {
				t.Fatal("actor roundtrip")
			}
		} else if id != (ActorID{}) {
			t.Fatal("invalid actor returned identity")
		}
		a, err := ParseAccountID(s)
		if err == nil {
			if a.String() != s || len(s) != 32 {
				t.Fatal("account canonical bound")
			}
			round, err := ParseAccountID(a.String())
			if err != nil || round != a {
				t.Fatal("account roundtrip")
			}
		} else if a != (AccountID{}) {
			t.Fatal("invalid account returned identity")
		}
	})
}
