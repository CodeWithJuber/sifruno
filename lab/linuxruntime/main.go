//go:build linux

// This runner qualifies only a trusted, root-staged disposable Linux guest.
// It is not a guest isolation mechanism or a production/hosting installer.
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"sifruno/internal/cpmove"
	"sifruno/internal/serverinfo"
)

const maxFile = 128 << 20
const maxFixture = 8 << 20
const maxJSON = 2 << 20

var errCheck = errors.New("qualification check failed")
var safeID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var safeHash = regexp.MustCompile(`^[a-f0-9]{64}$`)

type options struct {
	bundle, fixtures, parent, id, manifestHash, expectedHash string
	timeout                                                  time.Duration
	guest                                                    bool
}
type hashRecord struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}
type manifest struct {
	SchemaVersion    int          `json:"schema_version"`
	Target           string       `json:"target"`
	InputFingerprint string       `json:"input_fingerprint"`
	Files            []hashRecord `json:"files"`
}
type expectedFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}
type expectation struct {
	Kind                   string            `json:"kind"`
	Producer               string            `json:"producer"`
	CompatibilityCertified bool              `json:"compatibility_certified"`
	Entries                int               `json:"entries"`
	Files                  []expectedFile    `json:"files"`
	SourceSHA256           map[string]string `json:"source_sha256"`
	ForbiddenPayloadSHA256 string            `json:"forbidden_payload_sha256"`
}
type commandResult struct {
	Command       []string `json:"command"`
	ExitCode      int      `json:"exit_code"`
	DurationMS    int64    `json:"duration_ms"`
	TimedOut      bool     `json:"timed_out"`
	OutputBounded bool     `json:"output_bounded"`
}
type httpResult struct {
	Method  string `json:"method"`
	Path    string `json:"path"`
	Variant string `json:"variant"`
	Status  int    `json:"status"`
	Passed  bool   `json:"passed"`
}
type telemetry struct {
	Observed          bool     `json:"observed"`
	LogicalCores      *int     `json:"logical_cores"`
	MemoryBytes       *uint64  `json:"memory_bytes"`
	CPUPercent        *float64 `json:"cpu_percent"`
	SampledAt         string   `json:"sampled_at"`
	HistorySamples    int      `json:"history_samples"`
	StorageAvailable  bool     `json:"storage_available"`
	UptimeAvailable   bool     `json:"uptime_available"`
	NetworkAvailable  bool     `json:"network_available"`
	ServicesAvailable bool     `json:"services_available"`
	ServiceManager    string   `json:"service_manager"`
	ServiceCount      int      `json:"service_count"`
	ServicesTruncated bool     `json:"services_truncated"`
}
type platform struct {
	OS                  string `json:"os"`
	Arch                string `json:"arch"`
	Distribution        string `json:"distribution"`
	VersionID           string `json:"version_id"`
	PrettyName          string `json:"pretty_name"`
	KernelRelease       string `json:"kernel_release"`
	KernelVersion       string `json:"kernel_version"`
	KernelMachine       string `json:"kernel_machine"`
	FilesystemMagic     string `json:"filesystem_magic"`
	FilesystemBlockSize int64  `json:"filesystem_block_size"`
	FilesystemNameLimit int64  `json:"filesystem_name_limit"`
}
type report struct {
	SchemaVersion          int              `json:"schema_version"`
	EvidenceKind           string           `json:"evidence_kind"`
	CheckedAt              string           `json:"checked_at"`
	RunID                  string           `json:"run_id"`
	Phase                  string           `json:"phase"`
	Passed                 bool             `json:"passed"`
	Complete               bool             `json:"complete"`
	FixtureKind            string           `json:"fixture_kind"`
	ReferenceObserved      bool             `json:"reference_observed"`
	CompatibilityCertified bool             `json:"compatibility_certified"`
	RestoreImplemented     bool             `json:"restore_implemented"`
	ProductionMutated      bool             `json:"production_mutated"`
	RebootDurabilityTested bool             `json:"reboot_durability_tested"`
	Host                   platform         `json:"host"`
	RunnerSHA256           string           `json:"runner_sha256"`
	ManifestSHA256         string           `json:"manifest_sha256"`
	ExpectedSHA256         string           `json:"expected_sha256"`
	SourceFingerprint      string           `json:"source_fingerprint"`
	Inputs                 []hashRecord     `json:"inputs"`
	Binaries               []hashRecord     `json:"binaries"`
	Commands               []commandResult  `json:"commands"`
	HTTP                   []httpResult     `json:"http"`
	Telemetry              telemetry        `json:"telemetry"`
	Catalogs               []cpmove.Summary `json:"catalogs"`
	ManifestVerified       bool             `json:"manifest_verified"`
	InputHashesUnchanged   bool             `json:"input_hashes_unchanged"`
	MetadataVerified       bool             `json:"metadata_verified"`
	PrivatePayloadExcluded bool             `json:"private_payload_excluded"`
	CorruptCleanup         bool             `json:"corrupt_cleanup"`
	OverwriteRefused       bool             `json:"overwrite_refused"`
	InspectorNoState       bool             `json:"inspector_no_state"`
	CredentialFreeChildren bool             `json:"credential_free_children"`
	ServerStarted          bool             `json:"server_started"`
	OwnedStatePermissions  bool             `json:"owned_state_permissions"`
	ProcessStopped         bool             `json:"process_stopped"`
	StopMode               string           `json:"stop_mode"`
	CompatibilityGate      gate             `json:"compatibility_gate"`
}

type gate struct {
	Ready    bool `json:"ready"`
	Total    int  `json:"total"`
	Passed   int  `json:"passed"`
	Untested int  `json:"untested"`
}

func main() {
	o, err := parse(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "Linux guest qualification arguments rejected")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	if err = run(ctx, o); err != nil {
		fmt.Fprintln(os.Stderr, "Linux guest qualification failed; inspect the owned report")
		os.Exit(1)
	}
	fmt.Println("Linux guest qualification passed; report.json recorded")
}
func parse(args []string) (options, error) {
	o := options{}
	f := flag.NewFlagSet("linuxruntime", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.BoolVar(&o.guest, "guest-qualification", false, "Explicit disposable guest acknowledgement")
	f.StringVar(&o.bundle, "bundle", "", "Read-only extracted bundle")
	f.StringVar(&o.fixtures, "fixtures", "", "Read-only independent synthetic fixtures")
	f.StringVar(&o.parent, "run-parent", "", "Existing dedicated guest scratch parent")
	f.StringVar(&o.id, "run-id", "", "New run directory identifier")
	f.StringVar(&o.manifestHash, "manifest-sha256", "", "Pinned manifest hash")
	f.StringVar(&o.expectedHash, "expected-sha256", "", "Pinned expected.json hash")
	f.DurationVar(&o.timeout, "timeout", 2*time.Minute, "Total timeout, up to ten minutes")
	if f.Parse(args) != nil || f.NArg() != 0 || !o.guest || !safeID.MatchString(o.id) || !safeHash.MatchString(o.manifestHash) || !safeHash.MatchString(o.expectedHash) || o.timeout < 30*time.Second || o.timeout > 10*time.Minute {
		return o, errCheck
	}
	for _, p := range []string{o.bundle, o.fixtures, o.parent} {
		if len(p) > 4096 || !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsAny(p, "\x00\r\n") {
			return o, errCheck
		}
	}
	for _, pair := range [][2]string{{o.bundle, o.fixtures}, {o.bundle, o.parent}, {o.fixtures, o.parent}} {
		if within(pair[0], pair[1]) || within(pair[1], pair[0]) {
			return o, errCheck
		}
	}
	return o, nil
}
func within(parent, child string) bool {
	r, e := filepath.Rel(parent, child)
	return e == nil && (r == "." || r != ".." && !strings.HasPrefix(r, ".."+string(os.PathSeparator)))
}

func run(ctx context.Context, o options) (result error) {
	for _, p := range []string{o.bundle, o.fixtures, o.parent} {
		if safeDirectory(p) != nil {
			return errCheck
		}
	}
	work := filepath.Join(o.parent, o.id)
	if os.Mkdir(work, 0700) != nil {
		return errCheck
	}
	r := report{SchemaVersion: 1, EvidenceKind: "disposable_linux_guest_runtime_qualification", CheckedAt: time.Now().UTC().Format(time.RFC3339Nano), RunID: o.id, FixtureKind: "synthetic", Phase: "provenance", Commands: []commandResult{}, HTTP: []httpResult{}, Catalogs: []cpmove.Summary{}}
	defer func() {
		r.Complete = true
		r.Passed = result == nil
		r.CheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if writeReport(work, r) != nil {
			result = errCheck
		}
	}()
	if err := observePlatform(work, &r.Host); err != nil {
		return errCheck
	}
	executable, err := os.Executable()
	if err != nil {
		return errCheck
	}
	own, err := hashFile(ctx, executable, maxFile)
	if err != nil {
		return errCheck
	}
	r.RunnerSHA256 = own.SHA256
	for _, d := range []string{"home", "tmp", "catalogs"} {
		if os.Mkdir(filepath.Join(work, d), 0700) != nil {
			return errCheck
		}
	}
	env := []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "HOME=" + filepath.Join(work, "home"), "TMPDIR=" + filepath.Join(work, "tmp"), "XDG_CONFIG_HOME=" + filepath.Join(work, "home"), "XDG_CACHE_HOME=" + filepath.Join(work, "tmp")}
	r.CredentialFreeChildren = true
	m, manifestBytes, err := loadManifest(ctx, o.bundle, o.manifestHash)
	if err != nil {
		return errCheck
	}
	r.ManifestSHA256 = digest(manifestBytes)
	r.SourceFingerprint = m.InputFingerprint
	r.ManifestVerified = true
	for _, f := range m.Files {
		if f.Path == "bin/panelctl" || f.Path == "bin/sifruno" {
			r.Binaries = append(r.Binaries, f)
		}
	}
	if len(r.Binaries) != 2 {
		return errCheck
	}
	for _, f := range r.Binaries {
		if verifyBinary(filepath.Join(o.bundle, f.Path)) != nil {
			return errCheck
		}
	}
	expectedBytes, err := readFile(ctx, filepath.Join(o.fixtures, "expected.json"), 128<<10)
	if err != nil || digest(expectedBytes) != o.expectedHash {
		return errCheck
	}
	r.ExpectedSHA256 = digest(expectedBytes)
	var expected expectation
	if json.Unmarshal(expectedBytes, &expected) != nil || expected.Kind != "synthetic" || expected.Producer != "Python standard tarfile/gzip" || expected.CompatibilityCertified || expected.Entries < 1 || expected.Entries > 1000 || len(expected.Files) < 1 || len(expected.Files) > 1000 || !safeHash.MatchString(expected.ForbiddenPayloadSHA256) {
		return errCheck
	}
	fixtureNames := []string{"synthetic.tar", "synthetic.tar.gz", "bad-crc.tar.gz", "truncated.tar", "trailing.tar"}
	if len(expected.SourceSHA256) != len(fixtureNames) {
		return errCheck
	}
	for _, name := range fixtureNames {
		f, e := hashFile(ctx, filepath.Join(o.fixtures, name), maxFixture)
		if e != nil || f.SHA256 != expected.SourceSHA256[name] || !safeHash.MatchString(f.SHA256) {
			return errCheck
		}
		f.Path = name
		r.Inputs = append(r.Inputs, f)
	}
	reference, forbidden, err := referenceEntries(ctx, filepath.Join(o.fixtures, "synthetic.tar"), expected)
	if err != nil {
		return errCheck
	}
	r.Phase = "packaged_backup_inspector"
	cli := filepath.Join(o.bundle, "bin/panelctl")
	for _, name := range fixtureNames[:2] {
		output := filepath.Join(work, "catalogs", name+".jsonl")
		args := []string{"backup", "inspect", "--from", filepath.Join(o.fixtures, name), "--out", output}
		logArgs := []string{"bundle/bin/panelctl", "backup", "inspect", "--from", "fixtures/" + name, "--out", "run/catalogs/" + name + ".jsonl"}
		stdout, ok := command(ctx, cli, args, logArgs, work, env, &r)
		if !ok {
			return errCheck
		}
		var summary cpmove.Summary
		if json.Unmarshal(stdout, &summary) != nil || summary.SchemaVersion != 1 || !summary.Complete || summary.CompatibilityCertified || summary.ReferenceObserved || summary.RestoreImplemented || summary.Entries != expected.Entries || summary.ArchiveSHA256 != expected.SourceSHA256[name] || summary.BlockerCount < 3 {
			return errCheck
		}
		catalog, err := readFile(ctx, output, maxJSON)
		if err != nil || verifyCatalog(catalog, summary, reference, forbidden) != nil {
			return errCheck
		}
		for _, input := range r.Inputs {
			if input.Path == name && summary.ArchiveBytes != input.Bytes {
				return errCheck
			}
			if input.Path == "synthetic.tar" && summary.ExpandedBytes != input.Bytes {
				return errCheck
			}
		}
		if name == "synthetic.tar" && summary.Format != "tar" || name == "synthetic.tar.gz" && summary.Format != "tar.gz" {
			return errCheck
		}
		r.Catalogs = append(r.Catalogs, summary)
		_, ok = command(ctx, cli, args, logArgs, work, env, &r)
		if ok || !expectedFailure(r) {
			return errCheck
		}
		after, err := readFile(ctx, output, maxJSON)
		if err != nil || !bytes.Equal(catalog, after) {
			return errCheck
		}
	}
	r.MetadataVerified = true
	r.PrivatePayloadExcluded = true
	r.OverwriteRefused = true
	for _, name := range fixtureNames[2:] {
		output := filepath.Join(work, "catalogs", name+".jsonl")
		_, ok := command(ctx, cli, []string{"backup", "inspect", "--from", filepath.Join(o.fixtures, name), "--out", output}, []string{"bundle/bin/panelctl", "backup", "inspect", "--from", "fixtures/" + name, "--out", "run/catalogs/" + name + ".jsonl"}, work, env, &r)
		if ok || !expectedFailure(r) || !absent(output) {
			return errCheck
		}
	}
	r.CorruptCleanup = true
	for _, name := range []string{".state", "server-state"} {
		if !absent(filepath.Join(work, name)) {
			return errCheck
		}
	}
	r.InspectorNoState = true
	r.Phase = "packaged_server_http_telemetry"
	if serverChecks(ctx, o, work, env, &r) != nil {
		return errCheck
	}
	r.Phase = "input_stability"
	if _, _, err = loadManifest(ctx, o.bundle, o.manifestHash); err != nil {
		return errCheck
	}
	for _, f := range r.Inputs {
		after, e := hashFile(ctx, filepath.Join(o.fixtures, f.Path), maxFixture)
		if e != nil || after.Bytes != f.Bytes || after.SHA256 != f.SHA256 {
			return errCheck
		}
	}
	after, e := readFile(ctx, filepath.Join(o.fixtures, "expected.json"), 128<<10)
	if e != nil || digest(after) != o.expectedHash {
		return errCheck
	}
	r.InputHashesUnchanged = true
	if ctx.Err() != nil {
		return errCheck
	}
	r.Phase = "completed"
	return nil
}

func safeDirectory(p string) error {
	current := "/"
	for _, part := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errCheck
		}
	}
	return nil
}
func localPath(p string) bool {
	if p == "" || len(p) > 4096 || strings.ContainsAny(p, "\\\x00\r\n") || filepath.IsAbs(p) {
		return false
	}
	for _, s := range strings.Split(p, "/") {
		if s == "" || s == "." || s == ".." {
			return false
		}
	}
	return true
}
func readFile(ctx context.Context, p string, max int64) ([]byte, error) {
	info, err := os.Lstat(p)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > max || safeDirectory(filepath.Dir(p)) != nil {
		return nil, errCheck
	}
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errCheck
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(&ctxReader{ctx: ctx, r: f}, max+1))
	if err != nil || int64(len(data)) > max {
		return nil, errCheck
	}
	return data, nil
}
func hashFile(ctx context.Context, p string, max int64) (hashRecord, error) {
	info, err := os.Lstat(p)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > max || safeDirectory(filepath.Dir(p)) != nil {
		return hashRecord{}, errCheck
	}
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return hashRecord{}, errCheck
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(&ctxReader{ctx: ctx, r: f}, max+1))
	if err != nil || n > max || n != info.Size() {
		return hashRecord{}, errCheck
	}
	return hashRecord{Bytes: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *ctxReader) Read(p []byte) (int, error) {
	if r.ctx.Err() != nil {
		return 0, errCheck
	}
	n, e := r.r.Read(p)
	if r.ctx.Err() != nil {
		return n, errCheck
	}
	return n, e
}
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func absent(p string) bool   { _, err := os.Lstat(p); return errors.Is(err, os.ErrNotExist) }
func loadManifest(ctx context.Context, bundle, expectedHash string) (manifest, []byte, error) {
	b, err := readFile(ctx, filepath.Join(bundle, "manifest.json"), maxJSON)
	if err != nil || digest(b) != expectedHash {
		return manifest{}, nil, errCheck
	}
	var m manifest
	if json.Unmarshal(b, &m) != nil || m.SchemaVersion != 1 || m.Target != "linux-"+runtime.GOARCH || len(m.Files) < 3 || len(m.Files) > 1000 || !safeHash.MatchString(m.InputFingerprint) {
		return m, nil, errCheck
	}
	seen := map[string]bool{"manifest.json": true}
	total := int64(0)
	for _, f := range m.Files {
		if !localPath(f.Path) || seen[f.Path] || f.Bytes < 0 || f.Bytes > maxFile || !safeHash.MatchString(f.SHA256) {
			return m, nil, errCheck
		}
		actual, e := hashFile(ctx, filepath.Join(bundle, f.Path), maxFile)
		if e != nil || actual.Bytes != f.Bytes || actual.SHA256 != f.SHA256 {
			return m, nil, errCheck
		}
		seen[f.Path] = true
		total += f.Bytes
		if total > 512<<20 {
			return m, nil, errCheck
		}
	}
	files := 0
	err = filepath.WalkDir(bundle, func(path string, d os.DirEntry, e error) error {
		if e != nil || ctx.Err() != nil || d.Type()&os.ModeSymlink != 0 {
			return errCheck
		}
		if d.IsDir() {
			return nil
		}
		files++
		if files > 1001 || !d.Type().IsRegular() {
			return errCheck
		}
		rel, e := filepath.Rel(bundle, path)
		if e != nil || !seen[filepath.ToSlash(rel)] {
			return errCheck
		}
		return nil
	})
	if err != nil || files != len(seen) {
		return m, nil, errCheck
	}
	return m, b, nil
}
func verifyBinary(p string) error {
	info, err := os.Stat(p)
	if err != nil || info.Mode().Perm()&0111 == 0 {
		return errCheck
	}
	b, err := buildinfo.ReadFile(p)
	if err != nil {
		return errCheck
	}
	settings := map[string]string{}
	for _, s := range b.Settings {
		settings[s.Key] = s.Value
	}
	if settings["GOOS"] != "linux" || settings["GOARCH"] != runtime.GOARCH || settings["CGO_ENABLED"] != "0" {
		return errCheck
	}
	return nil
}

func referenceEntries(ctx context.Context, p string, expected expectation) ([]cpmove.Entry, [][]byte, error) {
	b, err := readFile(ctx, p, maxFixture)
	if err != nil {
		return nil, nil, errCheck
	}
	reader := tar.NewReader(bytes.NewReader(b))
	entries := []cpmove.Entry{}
	forbidden := [][]byte{}
	files := map[string]expectedFile{}
	for _, f := range expected.Files {
		if f.Bytes < 0 || f.Bytes > maxFixture || !safeHash.MatchString(f.SHA256) {
			return nil, nil, errCheck
		}
		if _, duplicate := files[f.Name]; duplicate {
			return nil, nil, errCheck
		}
		files[f.Name] = f
	}
	for {
		h, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil || len(entries) >= 1000 || h.Size < 0 || h.Size > maxFixture {
			return nil, nil, errCheck
		}
		e := cpmove.Entry{Index: len(entries), NameBase64: base64.StdEncoding.EncodeToString([]byte(h.Name)), LinkNameBase64: base64.StdEncoding.EncodeToString([]byte(h.Linkname)), PhysicalTypeFlag: h.Typeflag, Size: h.Size, Mode: h.Mode, UID: h.Uid, GID: h.Gid, DevMajor: h.Devmajor, DevMinor: h.Devminor, UnameBase64: base64.StdEncoding.EncodeToString([]byte(h.Uname)), GnameBase64: base64.StdEncoding.EncodeToString([]byte(h.Gname)), ModTime: timestamp(h.ModTime), AccessTime: timestamp(h.AccessTime), ChangeTime: timestamp(h.ChangeTime), Format: h.Format.String(), PAXKeys: []string{}}
		switch h.Typeflag {
		case tar.TypeReg:
			e.Type = "file"
		case tar.TypeDir:
			e.Type = "directory"
		case tar.TypeSymlink:
			e.Type = "symlink"
		case tar.TypeLink:
			e.Type = "hardlink"
		case tar.TypeFifo:
			e.Type = "fifo"
		default:
			return nil, nil, errCheck
		}
		data, err := io.ReadAll(io.LimitReader(reader, maxFixture+1))
		if err != nil || len(data) > maxFixture {
			return nil, nil, errCheck
		}
		if e.Type == "file" {
			f, ok := files[h.Name]
			if !ok || f.Bytes != int64(len(data)) || f.SHA256 != digest(data) || h.Uid != 1234 || h.Gid != 2345 || h.Mode != 0640 {
				return nil, nil, errCheck
			}
			e.SHA256 = digest(data)
			delete(files, h.Name)
			if e.SHA256 == expected.ForbiddenPayloadSHA256 {
				forbidden = append(forbidden, data)
			}
		}
		pax := sha256.New()
		for key := range h.PAXRecords {
			e.PAXKeys = append(e.PAXKeys, key)
		}
		sort.Strings(e.PAXKeys)
		var length [8]byte
		for _, key := range e.PAXKeys {
			value := h.PAXRecords[key]
			for _, s := range []string{key, value} {
				binary.BigEndian.PutUint64(length[:], uint64(len(s)))
				pax.Write(length[:])
				pax.Write([]byte(s))
			}
			if digest([]byte(value)) == expected.ForbiddenPayloadSHA256 {
				forbidden = append(forbidden, []byte(value))
			}
		}
		e.PAXSHA256 = hex.EncodeToString(pax.Sum(nil))
		entries = append(entries, e)
	}
	if len(entries) != expected.Entries || len(files) != 0 || len(forbidden) == 0 {
		return nil, nil, errCheck
	}
	return entries, forbidden, nil
}
func timestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
func verifyCatalog(b []byte, summary cpmove.Summary, reference []cpmove.Entry, forbidden [][]byte) error {
	for _, secret := range forbidden {
		if len(secret) == 0 || bytes.Contains(b, secret) {
			return errCheck
		}
	}
	if len(b) == 0 || b[len(b)-1] != '\n' {
		return errCheck
	}
	lines := bytes.Split(b[:len(b)-1], []byte{'\n'})
	if len(lines) != len(reference)+2 {
		return errCheck
	}
	var header struct {
		Type                   string        `json:"type"`
		SchemaVersion          int           `json:"schema_version"`
		EvidenceKind           string        `json:"evidence_kind"`
		CompatibilityCertified bool          `json:"compatibility_certified"`
		RestoreImplemented     bool          `json:"restore_implemented"`
		Limits                 cpmove.Limits `json:"limits"`
	}
	if json.Unmarshal(lines[0], &header) != nil || header.Type != "header" || header.SchemaVersion != 1 || header.EvidenceKind != "local_archive_characterization" || header.CompatibilityCertified || header.RestoreImplemented || header.Limits != cpmove.DefaultLimits() {
		return errCheck
	}
	fileBytes := int64(0)
	blockers := 0
	for i, want := range reference {
		var row struct {
			Type  string       `json:"type"`
			Entry cpmove.Entry `json:"entry"`
		}
		if json.Unmarshal(lines[i+1], &row) != nil || row.Type != "entry" {
			return errCheck
		}
		got := row.Entry
		want.RestoreBlockers = got.RestoreBlockers
		want.Component = got.Component
		a, _ := json.Marshal(got)
		z, _ := json.Marshal(want)
		if !bytes.Equal(a, z) {
			return errCheck
		}
		if got.Type == "file" {
			fileBytes += got.Size
		}
		blockers += len(got.RestoreBlockers)
		if (got.Type == "symlink" || got.Type == "hardlink" || got.Type == "fifo") && len(got.RestoreBlockers) == 0 {
			return errCheck
		}
	}
	var footer struct {
		Type    string         `json:"type"`
		Summary cpmove.Summary `json:"summary"`
	}
	if json.Unmarshal(lines[len(lines)-1], &footer) != nil || footer.Type != "footer" || footer.Summary != summary || summary.FileBytes != fileBytes || summary.BlockerCount != blockers {
		return errCheck
	}
	prefix := bytes.Join(lines[:len(lines)-1], []byte{'\n'})
	prefix = append(prefix, '\n')
	if summary.CatalogSHA256 != digest(prefix) {
		return errCheck
	}
	return nil
}

type boundedBuffer struct {
	bytes.Buffer
	exceeded bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > maxJSON {
		b.exceeded = true
		return 0, errCheck
	}
	return b.Buffer.Write(p)
}
func command(parent context.Context, bin string, args, logged []string, work string, env []string, r *report) ([]byte, bool) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = work
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = time.Second
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	out, stderr := &boundedBuffer{}, &boundedBuffer{}
	cmd.Stdout = out
	cmd.Stderr = stderr
	started := time.Now()
	err := cmd.Run()
	code := -1
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	r.Commands = append(r.Commands, commandResult{Command: logged, ExitCode: code, DurationMS: time.Since(started).Milliseconds(), TimedOut: ctx.Err() != nil, OutputBounded: !out.exceeded && !stderr.exceeded})
	return out.Bytes(), err == nil && code == 0 && !out.exceeded && !stderr.exceeded && ctx.Err() == nil
}

func expectedFailure(r report) bool {
	if len(r.Commands) == 0 {
		return false
	}
	last := r.Commands[len(r.Commands)-1]
	return last.ExitCode == 1 && !last.TimedOut && last.OutputBounded
}

func serverChecks(ctx context.Context, o options, work string, env []string, r *report) (result error) {
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return errCheck
	}
	address := reservation.Addr().String()
	reservation.Close()
	// Only this freshly started process group is stopped. No process discovery,
	// system service management, firewall, bridge or production state is used.
	cmd := exec.Command(filepath.Join(o.bundle, "bin/sifruno"), "--listen", address, "--sites-listen", "", "--state", filepath.Join(work, "server-state"), "--ui", filepath.Join(o.bundle, "web/dist"))
	cmd.Dir = work
	cmd.Env = env
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	start := time.Now()
	if cmd.Start() != nil {
		return errCheck
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait(); close(done) }()
	defer func() {
		stopped, mode := stopOwned(cmd, done)
		r.ProcessStopped = stopped
		r.StopMode = mode
		r.Commands = append(r.Commands, commandResult{Command: []string{"bundle/bin/sifruno", "--listen", "127.0.0.1:EPHEMERAL", "--sites-listen", "", "--state", "run/server-state", "--ui", "bundle/web/dist"}, ExitCode: exitCode(cmd), DurationMS: time.Since(start).Milliseconds(), OutputBounded: true})
		if !stopped {
			result = errCheck
		}
		if mode == "already_exited" {
			result = errCheck
		}
	}()
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, ResponseHeaderTimeout: 2 * time.Second, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	base := "http://" + address
	startup, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	ready := false
	for !ready {
		status, b, err := httpCall(startup, client, base, "GET", "/api/v1/status", "", "")
		if err == nil && status == 200 {
			var s gate
			if json.Unmarshal(b, &s) == nil && !s.Ready && s.Passed == 0 && s.Total == 30 && s.Untested == 30 {
				r.CompatibilityGate = s
				ready = true
				break
			}
		}
		select {
		case <-startup.Done():
			return errCheck
		case <-done:
			return errCheck
		case <-time.After(100 * time.Millisecond):
		}
	}
	r.ServerStarted = true
	checks := []struct {
		method, path, host, origin, variant string
		want                                int
	}{{"GET", "/api/v1/status", "", "", "local", 200}, {"GET", "/", "", "", "local", 200}, {"GET", "/openapi.json", "", "", "local", 200}, {"GET", "/api/v1/status", "evil.example", "", "foreign_host", 403}, {"GET", "/api/v1/server", "", "https://evil.example", "foreign_origin", 403}, {"GET", "/api/v1/services", "evil.example", "", "foreign_host", 403}, {"POST", "/api/v1/server", "", "", "mutation", 405}, {"POST", "/api/v1/services", "", "", "mutation", 405}, {"GET", "/api/v1/server?range_seconds=4", "", "", "invalid_range", 422}, {"GET", "/.state/key", "", "", "private_path", 404}, {"GET", "/api/v1/sites", "", "", "unauthenticated", 401}, {"GET", "/cpsess1234567890/json-api/createacct", "", "", "unimplemented_vendor", 501}}
	for _, check := range checks {
		status, _, err := httpCall(ctx, client, base, check.method, check.path, check.host, check.origin)
		passed := err == nil && status == check.want
		r.HTTP = append(r.HTTP, httpResult{check.method, check.path, check.variant, status, passed})
		if !passed {
			return errCheck
		}
	}
	observation, stop := context.WithTimeout(ctx, 18*time.Second)
	defer stop()
	var observed serverinfo.Report
	for {
		status, b, err := httpCall(observation, client, base, "GET", "/api/v1/server?range_seconds=600", "", "")
		if err == nil && status == 200 && json.Unmarshal(b, &observed) == nil && observed.OS == "linux" && observed.Arch == runtime.GOARCH && observed.CPU.Available && observed.Memory.Available && observed.CPU.LogicalCores != nil && *observed.CPU.LogicalCores > 0 && observed.Memory.TotalBytes != nil && *observed.Memory.TotalBytes > 0 && observed.CPU.UsagePercent != nil && *observed.CPU.UsagePercent >= 0 && *observed.CPU.UsagePercent <= 100 && len(observed.History) >= 2 {
			break
		}
		select {
		case <-observation.Done():
			return errCheck
		case <-time.After(250 * time.Millisecond):
		}
	}
	r.Telemetry = telemetry{Observed: true, LogicalCores: observed.CPU.LogicalCores, MemoryBytes: observed.Memory.TotalBytes, CPUPercent: observed.CPU.UsagePercent, SampledAt: timestamp(observed.SampledAt), HistorySamples: len(observed.History), StorageAvailable: observed.Storage.Available, UptimeAvailable: observed.Uptime.Available, NetworkAvailable: observed.Network.Available}
	status, b, err := httpCall(ctx, client, base, "GET", "/api/v1/services", "", "")
	var services serverinfo.Services
	if err != nil || status != 200 || json.Unmarshal(b, &services) != nil || services.Manager != "systemd" || len(services.Items) > serverinfo.ServiceLimit {
		return errCheck
	}
	// OpenRC/Alpine is expected to report unavailable systemd inventory. An
	// unavailable result remains explicitly unavailable; no success is invented.
	r.Telemetry.ServicesAvailable = services.Available
	r.Telemetry.ServiceManager = services.Manager
	r.Telemetry.ServiceCount = len(services.Items)
	r.Telemetry.ServicesTruncated = services.Truncated
	if !services.Available && len(services.Items) != 0 {
		return errCheck
	}
	if checkPrivatePermissions(filepath.Join(work, "server-state")) != nil {
		return errCheck
	}
	r.OwnedStatePermissions = true
	return nil
}
func exitCode(cmd *exec.Cmd) int {
	if cmd.ProcessState == nil {
		return -1
	}
	return cmd.ProcessState.ExitCode()
}
func stopOwned(cmd *exec.Cmd, done <-chan error) (bool, string) {
	select {
	case <-done:
		return true, "already_exited"
	default:
	}
	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	if err != nil || pgid != cmd.Process.Pid {
		return false, "ownership_check_failed"
	}
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	select {
	case <-done:
		return true, "sigterm"
	case <-time.After(8 * time.Second):
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	select {
	case <-done:
		return true, "sigkill"
	case <-time.After(2 * time.Second):
		return false, "stop_timeout"
	}
}
func httpCall(ctx context.Context, client *http.Client, base, method, path, host, origin string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, base+path, nil)
	if err != nil {
		return 0, nil, errCheck
	}
	if host != "" {
		req.Host = host
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	response, err := client.Do(req)
	if err != nil {
		return 0, nil, errCheck
	}
	defer response.Body.Close()
	b, err := io.ReadAll(io.LimitReader(response.Body, maxJSON+1))
	if err != nil || len(b) > maxJSON {
		return response.StatusCode, nil, errCheck
	}
	return response.StatusCode, b, nil
}
func checkPrivatePermissions(state string) error {
	count := 0
	return filepath.WalkDir(state, func(p string, d os.DirEntry, err error) error {
		count++
		if err != nil || count > 1000 || d.Type()&os.ModeSymlink != 0 {
			return errCheck
		}
		info, e := d.Info()
		if e != nil {
			return errCheck
		}
		s, ok := info.Sys().(*syscall.Stat_t)
		if !ok || s.Uid != uint32(os.Geteuid()) {
			return errCheck
		}
		if d.IsDir() {
			if info.Mode().Perm() != 0700 {
				return errCheck
			}
		} else if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || s.Nlink != 1 {
			return errCheck
		}
		return nil
	})
}
func observePlatform(work string, p *platform) error {
	var u syscall.Utsname
	if syscall.Uname(&u) != nil {
		return errCheck
	}
	p.OS, p.Arch = "linux", runtime.GOARCH
	p.KernelRelease = uts(u.Release[:])
	p.KernelVersion = uts(u.Version[:])
	p.KernelMachine = uts(u.Machine[:])
	var fs syscall.Statfs_t
	if syscall.Statfs(work, &fs) != nil {
		return errCheck
	}
	p.FilesystemMagic = fmt.Sprintf("0x%x", uint64(fs.Type))
	p.FilesystemBlockSize = fs.Bsize
	p.FilesystemNameLimit = fs.Namelen
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return errCheck
	}
	defer f.Close()
	scanner := bufio.NewScanner(io.LimitReader(f, 64<<10))
	scanner.Buffer(make([]byte, 4096), 4096)
	values := map[string]string{}
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok || (key != "ID" && key != "VERSION_ID" && key != "PRETTY_NAME") {
			continue
		}
		if strings.HasPrefix(value, "\"") {
			var e error
			value, e = strconv.Unquote(value)
			if e != nil {
				return errCheck
			}
		}
		if len(value) > 256 || strings.ContainsAny(value, "\x00\r\n") {
			return errCheck
		}
		values[key] = value
	}
	if scanner.Err() != nil || values["ID"] == "" {
		return errCheck
	}
	p.Distribution = values["ID"]
	p.VersionID = values["VERSION_ID"]
	p.PrettyName = values["PRETTY_NAME"]
	return nil
}
func uts(v []int8) string {
	b := make([]byte, 0, len(v))
	for _, x := range v {
		if x == 0 {
			break
		}
		b = append(b, byte(x))
	}
	return string(b)
}
func writeReport(work string, r report) error {
	f, e := os.OpenFile(filepath.Join(work, "report.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return errCheck
	}
	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	e = encoder.Encode(r)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		return errCheck
	}
	return nil
}
