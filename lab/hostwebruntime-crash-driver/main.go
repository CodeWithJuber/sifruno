// This executable is a disposable-guest qualification driver, not a product API.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"sifruno/internal/hostaccounts"
	"sifruno/internal/hostweb"
	"sifruno/internal/hostwebgeneration"
)

const fixtureRoot = "/opt/sifruno-runtime-fixture"
const inputPath = fixtureRoot + "/qualification-input.json"
const inputLimit = 32 << 10
const reportLimit = 64 << 10
const bodyLimit = 128 << 10

var errContract = errors.New("qualification contract rejected")
var idRE = regexp.MustCompile(`^[a-f0-9]{32}$`)

type fixtureInput struct {
	SchemaVersion int                    `json:"schema_version"`
	FixtureOnly   bool                   `json:"fixture_only"`
	RunID         string                 `json:"run_id"`
	Root          string                 `json:"root"`
	Profile       hostweb.Profile        `json:"profile"`
	Accounts      []hostaccounts.Account `json:"accounts"`
}

func fixedProfile() hostweb.Profile {
	return hostweb.Profile{Name: hostweb.RestrictedChrootV1, ManagedRoot: fixtureRoot + "/managed", ManagedHomeRoot: fixtureRoot + "/homes", FrontChroot: fixtureRoot + "/front-jail", ApacheModuleRoot: "/usr/lib64/httpd/modules", BackendChrootRoot: fixtureRoot + "/backend-jails", RuntimeRoot: fixtureRoot + "/runtime", ApacheBinary: "/usr/sbin/httpd", FPMBinary: "/usr/sbin/php-fpm", TLSRoot: fixtureRoot + "/tls", CAFile: fixtureRoot + "/tls/ca.pem", FrontendIP: "127.0.0.1", FrontendPort: 18082, BackendPort: 18443, FrontUID: 48, FrontGID: 48, ControllerUID: 2000}
}
func hash(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func digest(v any) string  { b, _ := json.Marshal(v); return hash(b) }
func newID() (string, error) {
	var b [16]byte
	_, e := rand.Read(b[:])
	return hex.EncodeToString(b[:]), e
}
func arguments(args []string) error {
	if len(args) != 2 || args[0] != "--input" || args[1] != inputPath {
		return errContract
	}
	return nil
}

// Decode tokens first: encoding/json otherwise accepts duplicate keys and
// case-insensitive field aliases. Then require the exact declared field sets.
func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 8 {
		return errContract
	}
	t, e := d.Token()
	if e != nil {
		return errContract
	}
	switch v := t.(type) {
	case json.Delim:
		switch v {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				s, ok := k.(string)
				if e != nil || !ok || seen[s] {
					return errContract
				}
				seen[s] = true
				if uniqueJSON(d, depth+1) != nil {
					return errContract
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return errContract
			}
		case '[':
			for d.More() {
				if uniqueJSON(d, depth+1) != nil {
					return errContract
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return errContract
			}
		default:
			return errContract
		}
	}
	return nil
}
func exactFields(b []byte, typ reflect.Type) error {
	var obj map[string]json.RawMessage
	if json.Unmarshal(b, &obj) != nil || len(obj) != typ.NumField() {
		return errContract
	}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		k := f.Tag.Get("json")
		if k == "" {
			k = f.Name
		}
		if _, ok := obj[k]; !ok {
			return errContract
		}
	}
	return nil
}
func parseInput(b []byte) (fixtureInput, error) {
	var in fixtureInput
	if len(b) == 0 || len(b) > inputLimit {
		return in, errContract
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if uniqueJSON(d, 0) != nil {
		return in, errContract
	}
	if _, e := d.Token(); e != io.EOF {
		return in, errContract
	}
	if exactFields(b, reflect.TypeOf(in)) != nil {
		return in, errContract
	}
	var obj map[string]json.RawMessage
	_ = json.Unmarshal(b, &obj)
	if exactFields(obj["profile"], reflect.TypeOf(hostweb.Profile{})) != nil {
		return in, errContract
	}
	var accounts []json.RawMessage
	if json.Unmarshal(obj["accounts"], &accounts) != nil || len(accounts) != 2 {
		return in, errContract
	}
	for _, a := range accounts {
		if exactFields(a, reflect.TypeOf(hostaccounts.Account{})) != nil {
			return in, errContract
		}
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil {
		return in, errContract
	}
	if in.SchemaVersion != 1 || !in.FixtureOnly || !idRE.MatchString(in.RunID) || in.Root != fixtureRoot || in.Profile != fixedProfile() {
		return in, errContract
	}
	for i, a := range in.Accounts {
		user, domain := []string{"webalpha", "webbravo"}[i], []string{"alpha.test", "bravo.test"}[i]
		if !idRE.MatchString(a.ID) || i > 0 && in.Accounts[i-1].ID >= a.ID || a.Username != user || a.Domain != domain || a.UID != 20001+i || a.GID != a.UID || a.State != "active" || a.Revision == 0 || a.Revision == ^uint64(0) || a.CreatedAt.IsZero() || a.UpdatedAt.Before(a.CreatedAt) || a.Home != fixtureRoot+"/homes/"+user || a.PublicHTML != a.Home+"/public_html" {
			return in, errContract
		}
	}
	if _, e := hostweb.Compile(in.Profile, in.Accounts); e != nil {
		return in, errContract
	}
	return in, nil
}
func generation(in fixtureInput, id string, denied bool) (hostwebgeneration.Generation, error) {
	a := append([]hostaccounts.Account{}, in.Accounts...)
	render := append([]hostaccounts.Account{}, a...)
	if denied {
		for i := range render {
			render[i].State = "suspended"
		}
	}
	b, e := hostweb.Compile(in.Profile, render)
	return hostwebgeneration.Generation{ID: id, ProfileSHA256: digest(in.Profile), SnapshotSHA256: digest(a), Denied: denied, Accounts: a, Bundle: b}, e
}

type probeEvidence struct {
	AccountID      string `json:"account_id"`
	Kind           string `json:"kind"`
	Status         int    `json:"status"`
	Bytes          int    `json:"bytes"`
	SHA256         string `json:"sha256"`
	ContractPassed bool   `json:"contract_passed"`
	NamespacePID   int    `json:"namespace_pid"`
}
type phpIdentity struct{ PID int }

func phpBody(b []byte, a hostaccounts.Account) (phpIdentity, error) {
	var p phpIdentity
	if len(b) > 2048 {
		return p, errContract
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) != 6 || lines[0] != "SIFRUNO_PHP_"+a.Username || lines[1] != "SELF=readable" || lines[2] != "HOST=denied" || lines[3] != "SIBLING=denied" || lines[5] != "" || !strings.HasPrefix(lines[4], "PID=") {
		return p, errContract
	}
	s := strings.TrimPrefix(lines[4], "PID=")
	n, e := strconv.Atoi(s)
	if e != nil || n <= 1 || strconv.Itoa(n) != s {
		return p, errContract
	}
	p.PID = n
	return p, nil
}
func request(ctx context.Context, client *http.Client, host, route string) (int, []byte, error) {
	req, e := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:18082"+route, nil)
	if e != nil {
		return 0, nil, errContract
	}
	req.Host = host
	r, e := client.Do(req)
	if e != nil {
		return 0, nil, errContract
	}
	defer r.Body.Close()
	b, e := io.ReadAll(io.LimitReader(r.Body, bodyLimit+1))
	if e != nil || len(b) > bodyLimit {
		return r.StatusCode, nil, errContract
	}
	return r.StatusCode, b, nil
}
func main() {
	if len(os.Args) == 3 && os.Args[1] == "--child-apply" && idRE.MatchString(os.Args[2]) {
		_ = child()
		os.Exit(3)
	}
	if arguments(os.Args[1:]) != nil {
		fmt.Fprintln(os.Stderr, "qualification_input_rejected")
		os.Exit(2)
	}
	if run() != nil {
		fmt.Fprintln(os.Stderr, "qualification_failed")
		os.Exit(1)
	}
}

// No daemon output, raw responses, private keys or underlying error strings are
// printed. The root-owned bounded report is the qualification evidence.
type observation struct {
	Stage    string                     `json:"stage"`
	Identity hostwebgeneration.Identity `json:"identity"`
}
type workerEvidence struct {
	AccountID    string            `json:"account_id"`
	HostPID      int               `json:"host_pid"`
	NamespacePID int               `json:"namespace_pid"`
	Namespace    uint64            `json:"namespace"`
	UID          []int             `json:"uid"`
	GID          []int             `json:"gid"`
	Groups       []int             `json:"groups"`
	Capabilities map[string]string `json:"capabilities"`
	Root         string            `json:"root"`
	Start        string            `json:"start"`
}
type namespaceProcess struct {
	Role      string `json:"role"`
	AccountID string `json:"account_id"`
	PID       int    `json:"pid"`
	Start     string `json:"start"`
	Namespace uint64 `json:"namespace"`
}
type namespaceEpoch struct {
	Stage       string             `json:"stage"`
	StateSHA256 string             `json:"state_sha256"`
	Processes   []namespaceProcess `json:"processes"`
}
type namespaceMember struct {
	PID       int    `json:"pid"`
	Start     string `json:"start"`
	Namespace uint64 `json:"namespace"`
}
type namespaceScan struct {
	Matching   []namespaceMember `json:"matching"`
	Error      string            `json:"error"`
	ErrorPID   int               `json:"error_pid"`
	ErrorErrno int               `json:"error_errno"`
}
type namespaceDrain struct {
	Attempts      int           `json:"attempts"`
	ElapsedMillis int64         `json:"elapsed_ms"`
	Initial       namespaceScan `json:"initial"`
	Final         namespaceScan `json:"final"`
	Extinct       bool          `json:"extinct"`
}
type report struct {
	SchemaVersion       int                          `json:"schema_version"`
	FixtureOnly         bool                         `json:"fixture_only"`
	ExecutionKind       string                       `json:"execution_kind"`
	RunID               string                       `json:"run_id"`
	Nonce               string                       `json:"nonce"`
	DriverSHA256        string                       `json:"driver_sha256"`
	InputSHA256         string                       `json:"input_sha256"`
	ProfileSHA256       string                       `json:"profile_sha256"`
	Generations         []hostwebgeneration.Identity `json:"intended_generations"`
	Observations        []observation                `json:"observations"`
	Probes              []probeEvidence              `json:"probes"`
	Crash               crashEvidence                `json:"crash"`
	Checkpoints         []checkpoint                 `json:"checkpoints"`
	History             []hostwebgeneration.Event    `json:"history"`
	InventorySHA256     string                       `json:"inventory_sha256"`
	SourceCatalogSHA256 string                       `json:"source_catalog_sha256"`
	Prerequisites       map[string]string            `json:"prerequisites"`
	Stage               string                       `json:"stage"`
	Passed              bool                         `json:"passed"`
	ShutdownPassed      bool                         `json:"shutdown_passed"`
	ClosePassed         bool                         `json:"close_passed"`
	ListenersExtinct    bool                         `json:"listeners_extinct"`
	InputStable         bool                         `json:"input_stable"`
	SELinuxStable       bool                         `json:"selinux_stable"`
	Workers             []workerEvidence             `json:"worker_evidence"`
	ObservedNamespaces  []uint64                     `json:"observed_namespace_ids"`
	NamespacesExtinct   bool                         `json:"namespaces_extinct"`
	NamespaceEpochs     []namespaceEpoch             `json:"namespace_epochs"`
	NamespaceDrain      namespaceDrain               `json:"namespace_drain"`
}

func servingClient() *http.Client {
	return &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 16 << 10}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
