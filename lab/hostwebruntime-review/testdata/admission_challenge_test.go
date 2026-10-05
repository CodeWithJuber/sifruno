package hostwebruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	"sifruno/internal/hostaccounts"
	"sifruno/internal/hostweb"
	"sifruno/internal/hostwebgeneration"
)

// These execute common admission logic only. No process/filesystem admission is simulated as native proof.
func reviewHash(data []byte) string {
	value := sha256.Sum256(data)
	return hex.EncodeToString(value[:])
}
func reviewDigest(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return reviewHash(data)
}
func reviewProfile() hostweb.Profile {
	root := "/srv/sifruno-review"
	return hostweb.Profile{Name: hostweb.RestrictedChrootV1, ManagedRoot: root + "/managed", ManagedHomeRoot: root + "/homes", FrontChroot: root + "/front", ApacheModuleRoot: "/usr/lib64/httpd/modules", BackendChrootRoot: root + "/jails", RuntimeRoot: root + "/runtime", ApacheBinary: "/usr/sbin/httpd", FPMBinary: "/usr/sbin/php-fpm", TLSRoot: root + "/tls", CAFile: root + "/tls/ca.pem", FrontendIP: "127.0.0.1", FrontendPort: 18080, BackendPort: hostweb.DefaultBackendPort, FrontUID: 48, FrontGID: 48, ControllerUID: 2000}
}
func reviewAccounts(p hostweb.Profile) []hostaccounts.Account {
	at := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	return []hostaccounts.Account{
		{ID: strings.Repeat("a", 32), Username: "reviewalpha", Domain: "alpha.example.test", UID: 20000, GID: 20000, Home: path.Join(p.ManagedHomeRoot, "reviewalpha"), PublicHTML: path.Join(p.ManagedHomeRoot, "reviewalpha/public_html"), State: "active", Revision: 1, CreatedAt: at, UpdatedAt: at},
		{ID: strings.Repeat("b", 32), Username: "reviewbeta", Domain: "beta.example.test", UID: 20001, GID: 20001, Home: path.Join(p.ManagedHomeRoot, "reviewbeta"), PublicHTML: path.Join(p.ManagedHomeRoot, "reviewbeta/public_html"), State: "suspended", Revision: 2, CreatedAt: at, UpdatedAt: at},
	}
}
func reviewGeneration(t *testing.T, p hostweb.Profile, denied, bootstrap bool) hostwebgeneration.Generation {
	t.Helper()
	accounts := reviewAccounts(p)
	render := append([]hostaccounts.Account(nil), accounts...)
	if denied {
		for i := range render {
			render[i].State = "suspended"
		}
	}
	bundle, err := hostweb.Compile(p, render)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("1", 32)
	if bootstrap {
		id = ""
	}
	return hostwebgeneration.Generation{ID: id, ProfileSHA256: reviewDigest(p), SnapshotSHA256: reviewDigest(accounts), Denied: denied, Accounts: accounts, Bundle: bundle}
}
func reviewRehashBundle(bundle *hostweb.Bundle) {
	digest := sha256.New()
	for i := range bundle.Files {
		file := &bundle.Files[i]
		file.SHA256 = reviewHash(file.Data)
		digest.Write([]byte(file.Path))
		digest.Write([]byte{0})
		digest.Write([]byte(strconv.FormatUint(uint64(file.Mode), 8)))
		digest.Write([]byte{0})
		digest.Write([]byte(file.SHA256))
		digest.Write([]byte{0})
	}
	bundle.SHA256 = hex.EncodeToString(digest.Sum(nil))
}
func TestReviewRecompiledBundleRejectsSelfConsistentAlteredConfig(t *testing.T) {
	p := reviewProfile()
	g := reviewGeneration(t, p, false, false)
	if err := validateGeneration(p, g, false); err != nil {
		t.Fatal(err)
	}
	g.Bundle.Files[0].Data = append(g.Bundle.Files[0].Data, []byte("\n# injected reviewer bytes\n")...)
	reviewRehashBundle(&g.Bundle)
	if err := g.Bundle.Validate(); err != nil {
		t.Fatalf("challenge must remain structurally/hash-valid: %v", err)
	}
	if err := validateGeneration(p, g, false); err == nil {
		t.Fatal("accepted config bytes different from canonical recompile")
	}
}
func TestReviewGenerationIdentityAndAccountDriftRejected(t *testing.T) {
	p := reviewProfile()
	cases := map[string]func(*hostwebgeneration.Generation){
		"profile digest":  func(g *hostwebgeneration.Generation) { g.ProfileSHA256 = strings.Repeat("0", 64) },
		"snapshot digest": func(g *hostwebgeneration.Generation) { g.SnapshotSHA256 = strings.Repeat("0", 64) },
		"domain drift with recomputed snapshot": func(g *hostwebgeneration.Generation) {
			g.Accounts[0].Domain = "changed.example.test"
			g.SnapshotSHA256 = reviewDigest(g.Accounts)
		},
		"denied flag mismatch": func(g *hostwebgeneration.Generation) { g.Denied = true },
		"zero revision": func(g *hostwebgeneration.Generation) {
			g.Accounts[0].Revision = 0
			g.SnapshotSHA256 = reviewDigest(g.Accounts)
		},
		"unsorted accounts": func(g *hostwebgeneration.Generation) {
			g.Accounts[0], g.Accounts[1] = g.Accounts[1], g.Accounts[0]
			g.SnapshotSHA256 = reviewDigest(g.Accounts)
		},
		"invalid file mode": func(g *hostwebgeneration.Generation) { g.Bundle.Files[0].Mode = 0644; reviewRehashBundle(&g.Bundle) },
		"absolute path": func(g *hostwebgeneration.Generation) {
			g.Bundle.Files[0].Path = "/tmp/outside.conf"
			reviewRehashBundle(&g.Bundle)
		},
		"path traversal": func(g *hostwebgeneration.Generation) {
			g.Bundle.Files[0].Path = "apache/../front.conf"
			reviewRehashBundle(&g.Bundle)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			g := reviewGeneration(t, p, false, false)
			mutate(&g)
			if err := validateGeneration(p, g, false); err == nil {
				t.Fatal("admitted changed generation")
			}
		})
	}
}
func TestReviewBootstrapRequiresExactDeniedIdentity(t *testing.T) {
	p := reviewProfile()
	good := reviewGeneration(t, p, true, true)
	if err := validateGeneration(p, good, true); err != nil {
		t.Fatal(err)
	}
	for _, g := range []hostwebgeneration.Generation{reviewGeneration(t, p, false, true), reviewGeneration(t, p, true, false), {}} {
		if err := validateGeneration(p, g, true); err == nil {
			t.Fatal("accepted non-denied/nonempty-ID/empty bootstrap")
		}
	}
	if err := validateGeneration(p, good, false); err == nil {
		t.Fatal("accepted empty bootstrap ID as normal transition")
	}
}
func TestReviewOptionsContainmentAndExposureRejected(t *testing.T) {
	good := Options{Root: "/srv/sifruno-review", Profile: reviewProfile()}
	if err := validateOptions(good); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Options){
		"filesystem root":           func(o *Options) { o.Root = "/" },
		"relative root":             func(o *Options) { o.Root = "relative" },
		"unclean root":              func(o *Options) { o.Root += "/../sifruno-review" },
		"sibling prefix root":       func(o *Options) { o.Profile.ManagedRoot = "/srv/sifruno-review-other/managed" },
		"root equals writable tree": func(o *Options) { o.Profile.ManagedRoot = o.Root },
		"external homes":            func(o *Options) { o.Profile.ManagedHomeRoot = "/home/customer" },
		"public listener":           func(o *Options) { o.Profile.FrontendIP = "0.0.0.0" },
		"front root worker":         func(o *Options) { o.Profile.FrontUID = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			o := good
			mutate(&o)
			if err := validateOptions(o); err == nil {
				t.Fatal("admitted escaped/public options")
			}
		})
	}
}
func TestReviewCallerCopyCannotChangeAdmittedBytes(t *testing.T) {
	g := reviewGeneration(t, reviewProfile(), false, false)
	copied := copyGeneration(g)
	g.Accounts[0].State = "suspended"
	g.Bundle.Files[0].Data[0] ^= 0xff
	g.Bundle.Files[0].SHA256 = "changed"
	if copied.Accounts[0].State != "active" || copied.Bundle.Files[0].SHA256 == "changed" || reviewHash(copied.Bundle.Files[0].Data) != copied.Bundle.Files[0].SHA256 {
		t.Fatal("caller mutation changed copied account/config bytes")
	}
}

func TestReviewRuntimeAccountBoundDiffersFromCompilerCapacity(t *testing.T) {
	p := reviewProfile()
	if MaxRuntimeAccounts < 1 || MaxRuntimeAccounts > 8 || MaxProcesses != 1+2*MaxRuntimeAccounts {
		t.Fatal("runtime exceeds reviewed account/process bounds")
	}
	for _, count := range []int{MaxRuntimeAccounts, MaxRuntimeAccounts + 1} {
		accounts := make([]hostaccounts.Account, count)
		for i := range accounts {
			accounts[i] = reviewAccounts(p)[0]
			accounts[i].ID = fmt.Sprintf("%032x", i+1)
			accounts[i].Username = fmt.Sprintf("review%02d", i)
			accounts[i].Domain = fmt.Sprintf("site%d.example.test", i)
			accounts[i].UID = 20000 + i
			accounts[i].GID = accounts[i].UID
			accounts[i].Home = path.Join(p.ManagedHomeRoot, accounts[i].Username)
			accounts[i].PublicHTML = path.Join(accounts[i].Home, "public_html")
		}
		bundle, err := hostweb.Compile(p, accounts)
		if err != nil {
			t.Fatalf("compiler rejected otherwise-valid boundary fixture: %v", err)
		}
		g := hostwebgeneration.Generation{ID: strings.Repeat("1", 32), ProfileSHA256: reviewDigest(p), SnapshotSHA256: reviewDigest(accounts), Accounts: accounts, Bundle: bundle}
		err = validateGeneration(p, g, false)
		if count == MaxRuntimeAccounts && err != nil {
			t.Fatal("exact supported runtime capacity rejected")
		}
		if count > MaxRuntimeAccounts && err == nil {
			t.Fatal("compiler-valid excess runtime capacity admitted")
		}
	}
}

func TestReviewPendingRevisionMustMatchDurableCAS(t *testing.T) {
	p := reviewProfile()
	before := reviewGeneration(t, p, true, true)
	after := reviewGeneration(t, p, false, false)
	op := strings.Repeat("2", 32)
	r := record{Version: 1, Current: before, Pending: &transaction{OperationID: op, Revision: 0, Before: before, After: after, Target: after}}
	if err := validateRecord(p, r); err != nil {
		t.Fatal("valid precommit intent rejected")
	}
	r.Pending.Revision = 1
	if err := validateRecord(p, r); err == nil {
		t.Fatal("pending intent from a future revision admitted against durable revision zero")
	}
}
