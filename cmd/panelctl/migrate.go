package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"sifruno/internal/migrateverify"
)

const (
	migrateVerifyTimeout  = 30 * time.Minute
	migrateGateClosedExit = 3
	maxProbesFileBytes    = 1 << 20
)

var errMigrateUsage = errors.New("usage: panelctl migrate verify --old URL --new URL [--new-connect HOST:PORT] [--pages N] [--path /x ...] [--probe auth:/private/ --probe deny:/wp-config.php ...] [--probes-file FILE] [--insecure-new-tls] [--accept-warnings] [--json] [--out NEW.json]")

// runMigrate exits with status 3 when the verify ran but the cutover gate is
// closed, so scripts can tell a locked gate from usage and I/O errors, which
// main reports with status 1.
func runMigrate(args []string, out, errs io.Writer) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, migrateVerifyTimeout)
	defer cancel()
	allowed, err := migrateVerify(ctx, args, out, errs)
	if err != nil {
		return err
	}
	if !allowed {
		// os.Exit skips deferred calls; release the signal handler and timer first.
		cancel()
		stop()
		os.Exit(migrateGateClosedExit)
	}
	return nil
}

// migrateVerify runs the verify and reports whether cutover is allowed. It
// only reads both sites; the single local write is the optional new report file.
func migrateVerify(ctx context.Context, args []string, out, errs io.Writer) (bool, error) {
	if len(args) == 0 || args[0] != "verify" {
		return false, errMigrateUsage
	}
	flags := flag.NewFlagSet("migrate verify", flag.ContinueOnError)
	flags.SetOutput(errs)
	oldURL := flags.String("old", "", "Bare origin of the live old site")
	newURL := flags.String("new", "", "Bare origin of the new copy")
	connect := flags.String("new-connect", "", "HOST:PORT for new-site requests, keeping the site Host header and TLS name")
	pages := flags.Int("pages", migrateverify.DefaultPageLimit, "Pages to compare, 1 to 200")
	var paths, probeFlags repeatedFlag
	flags.Var(&paths, "path", "Extra path to compare; repeatable")
	flags.Var(&probeFlags, "probe", "Closed URL as auth:/path (401) or deny:/path (403); repeatable")
	probesFile := flags.String("probes-file", "", "JSON array of {\"path\", \"kind\"} closed URLs")
	insecure := flags.Bool("insecure-new-tls", false, "Skip TLS verification for the new site only; reported as a warning")
	acceptWarnings := flags.Bool("accept-warnings", false, "Allow cutover with warnings a person has checked; recorded in the report")
	asJSON := flags.Bool("json", false, "Print the JSON report instead of text")
	outPath := flags.String("out", "", "Write the JSON report to this new file (0600)")
	if err := flags.Parse(args[1:]); err != nil {
		return false, errMigrateUsage
	}
	if flags.NArg() != 0 || *oldURL == "" || *newURL == "" || *pages < 1 {
		return false, errMigrateUsage
	}
	probes, err := parseProbeFlags(probeFlags)
	if err != nil {
		return false, err
	}
	if *probesFile != "" {
		fromFile, e := readProbesFile(*probesFile)
		if e != nil {
			return false, e
		}
		probes = append(probes, fromFile...)
	}
	opts := migrateverify.Options{
		Old:            *oldURL,
		New:            *newURL,
		NewConnect:     *connect,
		PageLimit:      *pages,
		Paths:          paths,
		Probes:         probes,
		InsecureNewTLS: *insecure,
		AcceptWarnings: *acceptWarnings,
	}
	var file *reportFile
	if *outPath != "" {
		if file, err = createReportFile(*outPath); err != nil {
			return false, err
		}
		defer file.discard()
	}
	report, err := migrateverify.Run(ctx, opts)
	if err != nil {
		return false, err
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return false, errors.New("verify report could not be encoded")
	}
	encoded = append(encoded, '\n')
	if *asJSON {
		_, err = out.Write(encoded)
	} else {
		_, err = io.WriteString(out, report.Text())
	}
	if err != nil {
		return false, errors.New("verify report could not be printed")
	}
	if file != nil {
		if err = file.commit(encoded); err != nil {
			return false, err
		}
	}
	return report.CutoverAllowed, nil
}

type repeatedFlag []string

func (r *repeatedFlag) String() string { return strings.Join(*r, ",") }

func (r *repeatedFlag) Set(value string) error {
	*r = append(*r, value)
	return nil
}

func parseProbeFlags(values []string) ([]migrateverify.Probe, error) {
	probes := make([]migrateverify.Probe, 0, len(values))
	for _, v := range values {
		kind, path, ok := strings.Cut(v, ":")
		if !ok {
			return nil, errors.New("--probe must be auth:/path or deny:/path")
		}
		probes = append(probes, migrateverify.Probe{Path: path, Kind: migrateverify.ProbeKind(kind)})
	}
	return probes, nil
}

// readProbesFile accepts the output of an .htaccess pre-flight. Unknown fields
// are tolerated so the pre-flight can carry detail such as the rule's origin.
func readProbesFile(path string) ([]migrateverify.Probe, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("probes file is unavailable")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxProbesFileBytes+1))
	if err != nil {
		return nil, errors.New("probes file could not be read")
	}
	if len(raw) > maxProbesFileBytes {
		return nil, errors.New("probes file is larger than 1 MiB")
	}
	var probes []migrateverify.Probe
	if err = json.Unmarshal(raw, &probes); err != nil {
		return nil, errors.New(`probes file must be a JSON array of {"path": "...", "kind": "auth"|"deny"|"allow"} objects`)
	}
	return probes, nil
}

// reportFile is reserved before any request is sent, so an existing file is
// refused up front instead of after a long run.
type reportFile struct {
	root   *os.Root
	name   string
	file   *os.File
	info   os.FileInfo
	closed bool
	kept   bool
}

func createReportFile(path string) (*reportFile, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, errors.New("report output path is invalid")
	}
	name := filepath.Base(absolute)
	if name == "." || name == ".." || name == string(os.PathSeparator) {
		return nil, errors.New("report output path is invalid")
	}
	root, err := os.OpenRoot(filepath.Dir(absolute))
	if err != nil {
		return nil, errors.New("report output directory is unavailable")
	}
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		_ = root.Close()
		if errors.Is(err, fs.ErrExist) {
			return nil, errors.New("report output file already exists; refusing to overwrite it")
		}
		return nil, errors.New("report output file could not be created")
	}
	info, err := file.Stat()
	if err != nil {
		// The file was created exclusively a moment ago, so removing it by name
		// cannot touch a file this run did not create.
		_ = file.Close()
		_ = root.Remove(name)
		_ = root.Close()
		return nil, errors.New("report output file identity is unavailable")
	}
	return &reportFile{root: root, name: name, file: file, info: info}, nil
}

func (r *reportFile) commit(data []byte) error {
	if _, err := r.file.Write(data); err != nil {
		return errors.New("report output could not be written")
	}
	if err := r.file.Sync(); err != nil {
		return errors.New("report output could not be persisted")
	}
	err := r.file.Close()
	r.closed = true
	if err != nil {
		return errors.New("report output could not be closed")
	}
	r.kept = true
	return nil
}

// discard removes an unfinished report, but only while the path still names
// the file this run created.
func (r *reportFile) discard() {
	if !r.closed {
		_ = r.file.Close()
		r.closed = true
	}
	if !r.kept {
		if current, err := r.root.Lstat(r.name); err == nil && os.SameFile(current, r.info) {
			_ = r.root.Remove(r.name)
		}
	}
	_ = r.root.Close()
}
