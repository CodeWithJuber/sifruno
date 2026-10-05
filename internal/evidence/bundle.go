// Package evidence reads bounded, integrity-checked characterization captures.
// A matching capture is evidence for its recorded cases, never a compatibility
// certificate or proof that an operator's provenance declarations are authentic.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	SchemaVersion  = 1
	MaxBundleBytes = 4 << 20
	MaxCases       = 128
	MaxOutputBytes = 256 << 10
)

type Artifact struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type Provenance struct {
	Product                   string     `json:"product"`
	ExactBuild                string     `json:"exact_build"`
	OS                        string     `json:"os"`
	Arch                      string     `json:"arch"`
	CapturedAt                string     `json:"captured_at"`
	Features                  []string   `json:"features"`
	Artifacts                 []Artifact `json:"artifacts"`
	DisposableHostAttested    bool       `json:"disposable_host_attested"`
	LicensedReferenceAttested bool       `json:"licensed_reference_attested"`
}

type Operation struct {
	ID           string   `json:"id"`
	ObligationID string   `json:"obligation_id"`
	Transport    string   `json:"transport"`
	Command      []string `json:"command,omitempty"`
	Method       string   `json:"method,omitempty"`
	Path         string   `json:"path,omitempty"`
}

// For HTTP, Stdout is the exact response body. For CLI, ExitCode is mandatory.
// Format is json or text; stderr and exit/status remain significant in both.
type Outcome struct {
	Format     string `json:"format"`
	HTTPStatus int    `json:"http_status,omitempty"`
	ExitCode   *int   `json:"exit_code,omitempty"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
}

type Case struct {
	Operation Operation `json:"operation"`
	Outcome   Outcome   `json:"outcome"`
}

type Bundle struct {
	SchemaVersion int        `json:"schema_version"`
	ID            string     `json:"id"`
	Kind          string     `json:"kind"`
	Role          string     `json:"role"`
	Provenance    Provenance `json:"provenance"`
	Cases         []Case     `json:"cases"`
	SHA256        string     `json:"sha256,omitempty"`
}

var identifier = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,95}$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// Load rejects unknown fields, duplicate JSON keys, oversized documents,
// malformed provenance and altered contents. SHA256 provides corruption
// detection; it is not a signature or an authenticated chain of custody.
func Load(r io.Reader) (Bundle, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxBundleBytes+1))
	if err != nil {
		return Bundle{}, err
	}
	if len(data) > MaxBundleBytes {
		return Bundle{}, errors.New("evidence exceeds 4 MiB")
	}
	if _, err = CanonicalJSON(data); err != nil {
		return Bundle{}, fmt.Errorf("invalid evidence JSON: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var b Bundle
	if err = dec.Decode(&b); err != nil {
		return Bundle{}, fmt.Errorf("invalid evidence schema: %w", err)
	}
	if err = Verify(b); err != nil {
		return Bundle{}, err
	}
	return b, nil
}

// Seal validates and adds a digest to locally produced captures. Re-sealing
// changes the digest and does not make a synthetic capture observed or trusted.
func Seal(b Bundle) (Bundle, error) {
	b.SHA256 = ""
	if err := validate(b); err != nil {
		return Bundle{}, err
	}
	d, err := contentDigest(b)
	if err != nil {
		return Bundle{}, err
	}
	b.SHA256 = d
	return b, nil
}

func Verify(b Bundle) error {
	if err := validate(b); err != nil {
		return err
	}
	if !digestPattern.MatchString(b.SHA256) {
		return errors.New("missing or malformed evidence SHA256")
	}
	d, err := contentDigest(b)
	if err != nil {
		return err
	}
	if d != b.SHA256 {
		return errors.New("evidence SHA256 mismatch")
	}
	return nil
}

func Save(w io.Writer, b Bundle) error {
	if err := Verify(b); err != nil {
		return err
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	if len(data)+1 > MaxBundleBytes {
		return errors.New("serialized evidence exceeds 4 MiB")
	}
	_, err = w.Write(append(data, '\n'))
	return err
}

func contentDigest(b Bundle) (string, error) {
	b.SHA256 = ""
	data, err := json.Marshal(b)
	if err != nil {
		return "", err
	}
	if len(data) > MaxBundleBytes {
		return "", errors.New("evidence exceeds 4 MiB")
	}
	canonical, err := CanonicalJSON(data)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(canonical)
	return hex.EncodeToString(h[:]), nil
}

func validate(b Bundle) error {
	if b.SchemaVersion != SchemaVersion {
		return errors.New("unsupported evidence schema")
	}
	if !identifier.MatchString(b.ID) {
		return errors.New("invalid evidence id")
	}
	if b.Kind != "synthetic" && b.Kind != "observed" {
		return errors.New("kind must be synthetic or observed")
	}
	if b.Role != "reference" && b.Role != "candidate" {
		return errors.New("role must be reference or candidate")
	}
	p := b.Provenance
	for label, value := range map[string]string{"product": p.Product, "exact build": p.ExactBuild, "OS": p.OS, "architecture": p.Arch} {
		if !boundedText(value, 256) {
			return fmt.Errorf("missing or invalid provenance %s", label)
		}
	}
	stamp, err := time.Parse(time.RFC3339Nano, p.CapturedAt)
	if err != nil || stamp.Location() != time.UTC || !strings.HasSuffix(p.CapturedAt, "Z") {
		return errors.New("captured_at must be a UTC RFC3339 timestamp ending Z")
	}
	if len(p.Features) == 0 || len(p.Features) > 64 || !sort.StringsAreSorted(p.Features) {
		return errors.New("features must be nonempty, bounded and sorted")
	}
	for i, f := range p.Features {
		if !boundedText(f, 128) || (i > 0 && p.Features[i-1] == f) {
			return errors.New("invalid or duplicate feature")
		}
	}
	if len(p.Artifacts) == 0 || len(p.Artifacts) > 64 {
		return errors.New("at least one bounded artifact digest required")
	}
	artifacts := map[string]bool{}
	for _, a := range p.Artifacts {
		if !identifier.MatchString(a.Name) || !boundedText(a.Path, 512) || !strings.HasPrefix(a.Path, "/") || path.Clean(a.Path) != a.Path || !digestPattern.MatchString(a.SHA256) || artifacts[a.Name] {
			return errors.New("invalid or duplicate artifact provenance")
		}
		artifacts[a.Name] = true
	}
	if b.Kind == "synthetic" && p.LicensedReferenceAttested {
		return errors.New("synthetic evidence cannot attest a licensed reference")
	}
	if b.Kind == "observed" && (!p.DisposableHostAttested || (b.Role == "reference" && !p.LicensedReferenceAttested)) {
		return errors.New("observed captures require disposable-host and reference-license attestations")
	}
	if len(b.Cases) == 0 || len(b.Cases) > MaxCases {
		return errors.New("capture must contain 1 to 128 cases")
	}
	seen := map[string]bool{}
	for _, c := range b.Cases {
		op, out := c.Operation, c.Outcome
		if !identifier.MatchString(op.ID) || !identifier.MatchString(op.ObligationID) || seen[op.ID] {
			return errors.New("invalid or duplicate operation id")
		}
		seen[op.ID] = true
		if len(out.Stdout) > MaxOutputBytes || len(out.Stderr) > MaxOutputBytes {
			return errors.New("case output exceeds 256 KiB")
		}
		if !utf8.ValidString(out.Stdout) || !utf8.ValidString(out.Stderr) {
			return errors.New("case output must be valid UTF-8")
		}
		if out.Format != "json" && out.Format != "text" {
			return errors.New("output format must be json or text")
		}
		if out.Format == "json" {
			if _, err := CanonicalJSON([]byte(out.Stdout)); err != nil {
				return fmt.Errorf("%s JSON output: %w", op.ID, err)
			}
		}
		switch op.Transport {
		case "cli":
			if len(op.Command) == 0 || len(op.Command) > 32 || op.Method != "" || op.Path != "" || out.HTTPStatus != 0 || out.ExitCode == nil || *out.ExitCode < 0 || *out.ExitCode > 255 {
				return errors.New("invalid CLI operation or outcome")
			}
			for _, arg := range op.Command {
				if !boundedText(arg, 1024) || sensitiveArgument(arg) {
					return errors.New("invalid or sensitive command argument")
				}
			}
		case "http":
			if len(op.Command) != 0 || out.ExitCode != nil || out.Stderr != "" || out.HTTPStatus < 100 || out.HTTPStatus > 599 || !boundedText(op.Path, 2048) || !strings.HasPrefix(op.Path, "/") || sensitiveArgument(op.Path) {
				return errors.New("invalid HTTP operation or outcome")
			}
			switch op.Method {
			case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
			default:
				return errors.New("invalid HTTP method")
			}
		default:
			return errors.New("transport must be cli or http")
		}
	}
	return nil
}

func boundedText(s string, n int) bool {
	if len(s) == 0 || len(s) > n || strings.TrimSpace(s) != s || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

func sensitiveArgument(s string) bool {
	v := strings.ToLower(s)
	for _, marker := range []string{"--password", "--passwd", "--token", "--api-key", "--apikey", "--secret", "--authorization"} {
		if strings.HasPrefix(v, marker) {
			return true
		}
	}
	for _, marker := range []string{"password=", "passwd=", "token=", "api_key=", "apikey=", "secret=", "authorization:", "bearer ", "-----begin"} {
		if strings.Contains(v, marker) {
			return true
		}
	}
	return false
}
