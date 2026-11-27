// Package cpmove characterizes local TAR streams (Inspect) and reads a cPanel
// account backup into a website model (Read, read.go). Neither restores an
// account by itself or establishes compatibility with any cPanel version or
// licensed reference.
package cpmove

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"path"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrInvalid     = errors.New("invalid inspection request")
	ErrArchive     = errors.New("invalid archive")
	ErrLimit       = errors.New("archive limit exceeded")
	ErrUnsupported = errors.New("unsupported archive encoding")
	ErrCanceled    = errors.New("inspection canceled")
	ErrIO          = errors.New("inspection input or output failed")
)

type Limits struct {
	MaxArchiveBytes  int64 `json:"max_archive_bytes"`
	MaxExpandedBytes int64 `json:"max_expanded_bytes"`
	MaxFileBytes     int64 `json:"max_file_bytes"`
	MaxEntries       int   `json:"max_entries"`
	MaxPathBytes     int   `json:"max_path_bytes"`
}

func DefaultLimits() Limits { return Limits{32 << 30, 128 << 30, 32 << 30, 100000, 4096} }

func (l Limits) valid() bool {
	d := DefaultLimits()
	return l.MaxArchiveBytes > 0 && l.MaxArchiveBytes <= d.MaxArchiveBytes && l.MaxExpandedBytes > 0 && l.MaxExpandedBytes <= d.MaxExpandedBytes && l.MaxFileBytes > 0 && l.MaxFileBytes <= d.MaxFileBytes && l.MaxEntries > 0 && l.MaxEntries <= d.MaxEntries && l.MaxPathBytes > 0 && l.MaxPathBytes <= d.MaxPathBytes
}

type Entry struct {
	Index            int      `json:"index"`
	NameBase64       string   `json:"name_base64"`
	LinkNameBase64   string   `json:"link_name_base64"`
	Type             string   `json:"type"`
	PhysicalTypeFlag uint8    `json:"physical_type_flag"`
	Size             int64    `json:"size"`
	Mode             int64    `json:"mode"`
	UID              int      `json:"uid"`
	GID              int      `json:"gid"`
	DevMajor         int64    `json:"dev_major"`
	DevMinor         int64    `json:"dev_minor"`
	UnameBase64      string   `json:"uname_base64"`
	GnameBase64      string   `json:"gname_base64"`
	ModTime          string   `json:"mod_time"`
	AccessTime       string   `json:"access_time"`
	ChangeTime       string   `json:"change_time"`
	Format           string   `json:"format"`
	SHA256           string   `json:"sha256"`
	PAXKeys          []string `json:"pax_keys"`
	PAXSHA256        string   `json:"pax_sha256"`
	RestoreBlockers  []string `json:"restore_blockers"`
	Component        string   `json:"component"`
}

type Summary struct {
	SchemaVersion          int    `json:"schema_version"`
	Format                 string `json:"format"`
	ArchiveBytes           int64  `json:"archive_bytes"`
	ExpandedBytes          int64  `json:"expanded_bytes"`
	FileBytes              int64  `json:"file_bytes"`
	Entries                int    `json:"entries"`
	ArchiveSHA256          string `json:"archive_sha256"`
	CatalogSHA256          string `json:"catalog_sha256"`
	Complete               bool   `json:"complete"`
	CompatibilityCertified bool   `json:"compatibility_certified"`
	ReferenceObserved      bool   `json:"reference_observed"`
	RestoreImplemented     bool   `json:"restore_implemented"`
	BlockerCount           int    `json:"blocker_count"`
}

func catalogHeader(l Limits) any {
	return struct {
		Type                   string `json:"type"`
		SchemaVersion          int    `json:"schema_version"`
		EvidenceKind           string `json:"evidence_kind"`
		CompatibilityCertified bool   `json:"compatibility_certified"`
		RestoreImplemented     bool   `json:"restore_implemented"`
		Limits                 Limits `json:"limits"`
	}{"header", 1, "local_archive_characterization", false, false, l}
}

func entryRecord(e Entry) any {
	return struct {
		Type  string `json:"type"`
		Entry Entry  `json:"entry"`
	}{"entry", e}
}
func line(v any) []byte { b, _ := json.Marshal(v); return append(b, '\n') }

// Inspect streams one logical TAR, including its mandatory two zero end records.
// ExpandedBytes counts all decoded bytes, including headers, metadata and padding.
// Concatenated gzip members are allowed only if their combined decoded stream is
// one TAR followed by zero record padding. All members' checksums are validated.
// Name bytes are the exact logical archive/tar Header.Name bytes after GNU/PAX
// expansion, never filesystem-normalized. CatalogSHA256 uses the same canonical
// JSONL header and entry encoding as WriteCatalog, excluding its footer.
func Inspect(ctx context.Context, r io.Reader, limits Limits, emit func(Entry) error) (Summary, error) {
	if ctx == nil || r == nil || emit == nil || !limits.valid() {
		return Summary{}, ErrInvalid
	}
	if ctx.Err() != nil {
		return Summary{}, ErrCanceled
	}
	source := &boundedReader{ctx: ctx, r: r, max: limits.MaxArchiveBytes, digest: sha256.New()}
	buffered := bufio.NewReaderSize(source, 32768)
	magic, err := buffered.Peek(2)
	if err != nil {
		return Summary{}, sanitize(err)
	}
	var decoded io.Reader = buffered
	format := "tar"
	if magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(buffered)
		if err != nil {
			return Summary{}, sanitize(err)
		}
		defer gz.Close()
		decoded, format = gz, "tar.gz"
	}
	expanded := &boundedReader{ctx: ctx, r: decoded, max: limits.MaxExpandedBytes}
	guard := &tarGuard{r: expanded, limits: limits}
	tr := tar.NewReader(guard)
	catalog := sha256.New()
	catalog.Write(line(catalogHeader(limits)))
	summary := Summary{SchemaVersion: 1, Format: format}
	seen := make(map[string]string)
	type hardlink struct{ name, target string }
	var hardlinks []hardlink
	for {
		if ctx.Err() != nil {
			return Summary{}, ErrCanceled
		}
		h, err := tr.Next()
		// Ignore the host-dependent SDK path policy; validate POSIX paths below.
		if err == tar.ErrInsecurePath && h != nil {
			err = nil
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return Summary{}, sanitize(err)
		}
		if summary.Entries >= limits.MaxEntries {
			return Summary{}, ErrLimit
		}
		if h.Size < 0 || h.Size > limits.MaxFileBytes {
			return Summary{}, ErrLimit
		}
		if len(h.Name) > limits.MaxPathBytes || len(h.Linkname) > limits.MaxPathBytes || len(h.Uname) > limits.MaxPathBytes || len(h.Gname) > limits.MaxPathBytes {
			return Summary{}, ErrLimit
		}
		name, ok := canonicalName(h.Name, h.Typeflag == tar.TypeDir)
		if !ok {
			return Summary{}, ErrArchive
		}
		if _, exists := seen[name]; exists {
			return Summary{}, ErrArchive
		}
		e := Entry{Index: summary.Entries, NameBase64: b64(h.Name), LinkNameBase64: b64(h.Linkname), Type: entryType(h.Typeflag), PhysicalTypeFlag: guard.logicalType, Size: h.Size, Mode: h.Mode, UID: h.Uid, GID: h.Gid, DevMajor: h.Devmajor, DevMinor: h.Devminor, UnameBase64: b64(h.Uname), GnameBase64: b64(h.Gname), ModTime: stamp(h.ModTime), AccessTime: stamp(h.AccessTime), ChangeTime: stamp(h.ChangeTime), Format: h.Format.String(), PAXKeys: []string{}, RestoreBlockers: []string{}, Component: component(name)}
		seen[name] = e.Type
		keys, digest, err := paxDigest(h.PAXRecords, limits)
		if err != nil {
			return Summary{}, err
		}
		retained := len(h.Name) + len(h.Linkname) + len(h.Uname) + len(h.Gname)
		for k, v := range h.PAXRecords {
			retained += len(k) + len(v)
		}
		if retained > maxRetainedMetadata {
			return Summary{}, ErrLimit
		}
		e.PAXKeys, e.PAXSHA256 = keys, digest
		if strings.ContainsAny(name, "\\:") {
			e.RestoreBlockers = append(e.RestoreBlockers, "nonportable_path")
		}
		switch e.Type {
		case "file":
			digest := sha256.New()
			n, err := io.CopyBuffer(digest, tr, make([]byte, 32768))
			if err != nil {
				return Summary{}, sanitize(err)
			}
			if n != h.Size {
				return Summary{}, ErrArchive
			}
			e.SHA256 = hex.EncodeToString(digest.Sum(nil))
			summary.FileBytes += n
		case "symlink", "hardlink":
			target, internal := linkTarget(name, h.Linkname, e.Type == "hardlink")
			if !internal {
				e.RestoreBlockers = append(e.RestoreBlockers, "external_or_unsafe_link")
			}
			if e.Type == "hardlink" && internal {
				hardlinks = append(hardlinks, hardlink{name, target})
			}
			if e.Type == "hardlink" {
				e.RestoreBlockers = append(e.RestoreBlockers, "hardlink_requires_restore_validation")
			} else {
				e.RestoreBlockers = append(e.RestoreBlockers, "symlink_requires_restore_validation")
			}
		case "character", "block", "fifo":
			e.RestoreBlockers = append(e.RestoreBlockers, "special_file")
		case "other":
			e.RestoreBlockers = append(e.RestoreBlockers, "unknown_entry_type")
		}
		if e.Type != "file" {
			if _, err := io.CopyBuffer(io.Discard, tr, make([]byte, 32768)); err != nil {
				return Summary{}, sanitize(err)
			}
		}
		if ctx.Err() != nil {
			return Summary{}, ErrCanceled
		}
		encoded := line(entryRecord(e))
		if err := emit(e); err != nil {
			if ctx.Err() != nil {
				return Summary{}, ErrCanceled
			}
			return Summary{}, ErrIO
		}
		if ctx.Err() != nil {
			return Summary{}, ErrCanceled
		}
		catalog.Write(encoded)
		summary.Entries++
		summary.BlockerCount += len(e.RestoreBlockers)
	}
	if err := guard.finish(); err != nil {
		return Summary{}, sanitize(err)
	}
	for _, link := range hardlinks {
		if link.name == link.target || seen[link.target] != "file" {
			return Summary{}, ErrArchive
		}
	}
	if ctx.Err() != nil {
		return Summary{}, ErrCanceled
	}
	summary.ArchiveBytes, summary.ExpandedBytes = source.n, expanded.n
	summary.ArchiveSHA256 = hex.EncodeToString(source.digest.Sum(nil))
	summary.CatalogSHA256 = hex.EncodeToString(catalog.Sum(nil))
	summary.Complete = true
	return summary, nil
}

// WriteCatalog emits incomplete characterization progressively. Only a fully
// validated input and successful output can produce a complete footer. Consumers
// must require that footer; emitted entries alone are not validated evidence.
func WriteCatalog(ctx context.Context, r io.Reader, w io.Writer, limits Limits) (Summary, error) {
	if ctx == nil || r == nil || w == nil || !limits.valid() {
		return Summary{}, ErrInvalid
	}
	write := func(v any) error {
		if ctx.Err() != nil {
			return ErrCanceled
		}
		b := line(v)
		n, err := w.Write(b)
		if err != nil || n != len(b) {
			return ErrIO
		}
		if ctx.Err() != nil {
			return ErrCanceled
		}
		return nil
	}
	if err := write(catalogHeader(limits)); err != nil {
		return Summary{}, err
	}
	summary, err := Inspect(ctx, r, limits, func(e Entry) error { return write(entryRecord(e)) })
	if err != nil {
		return Summary{}, err
	}
	if err := write(struct {
		Type    string  `json:"type"`
		Summary Summary `json:"summary"`
	}{"footer", summary}); err != nil {
		return Summary{}, err
	}
	return summary, nil
}

func sanitize(err error) error {
	for _, sentinel := range []error{ErrInvalid, ErrArchive, ErrLimit, ErrUnsupported, ErrCanceled, ErrIO} {
		if errors.Is(err, sentinel) {
			return sentinel
		}
	}
	return ErrArchive
}

type boundedReader struct {
	ctx    context.Context
	r      io.Reader
	max, n int64
	digest hash.Hash
	stalls int
}

func (r *boundedReader) Read(p []byte) (int, error) {
	if r.ctx.Err() != nil {
		return 0, ErrCanceled
	}
	if len(p) == 0 {
		return 0, nil
	}
	if int64(len(p)) > r.max-r.n+1 {
		p = p[:r.max-r.n+1]
	}
	n, err := r.r.Read(p)
	if n < 0 || n > len(p) {
		return 0, ErrIO
	}
	if n > 0 {
		r.n += int64(n)
		if r.digest != nil {
			r.digest.Write(p[:n])
		}
		r.stalls = 0
	} else if err == nil {
		r.stalls++
		if r.stalls >= 100 {
			return 0, ErrIO
		}
	}
	if r.n > r.max {
		return n, ErrLimit
	}
	if r.ctx.Err() != nil {
		return n, ErrCanceled
	}
	return n, err
}

func canonicalName(s string, directory bool) (string, bool) {
	if strings.ContainsRune(s, 0) || strings.HasPrefix(s, "/") {
		return "", false
	}
	if directory && (s == "./" || s == ".") {
		return ".", true
	}
	s = strings.TrimPrefix(s, "./")
	if directory {
		s = strings.TrimSuffix(s, "/")
	}
	for _, p := range strings.Split(s, "/") {
		if p == "" || p == "." || p == ".." {
			return "", false
		}
	}
	return s, true
}
func linkTarget(name, target string, hard bool) (string, bool) {
	if target == "" || strings.ContainsAny(target, "\x00\\") || strings.HasPrefix(target, "/") || (len(target) > 1 && target[1] == ':') {
		return "", false
	}
	if !hard {
		target = path.Join(path.Dir(name), target)
	} else {
		target = path.Clean(target)
	}
	if target == ".." || strings.HasPrefix(target, "../") {
		return "", false
	}
	return target, true
}
func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
func entryType(t byte) string {
	switch t {
	case tar.TypeReg, tar.TypeRegA:
		return "file"
	case tar.TypeDir:
		return "directory"
	case tar.TypeSymlink:
		return "symlink"
	case tar.TypeLink:
		return "hardlink"
	case tar.TypeChar:
		return "character"
	case tar.TypeBlock:
		return "block"
	case tar.TypeFifo:
		return "fifo"
	default:
		return "other"
	}
}

// This is a documentation-derived location hint, never identity or proof that
// the entry is a vendor component. Unknown/custom components remain cataloged.
func component(name string) string {
	first := strings.SplitN(strings.TrimPrefix(name, "./"), "/", 2)[0]
	switch first {
	case "homedir", "cp", "userdata", "mysql", "psql", "dnszones", "mail":
		return first
	default:
		return "unclassified"
	}
}

// PAXSHA256 canonicalization: sorted exact keys, followed by each key/value's
// uint64 big-endian byte length then exact bytes. Values never enter the catalog.
func paxDigest(records map[string]string, l Limits) ([]string, string, error) {
	keys := make([]string, 0, len(records))
	total := 0
	for k, v := range records {
		if !utf8.ValidString(k) {
			return nil, "", ErrUnsupported
		}
		total += len(k) + len(v)
		if len(k) > l.MaxPathBytes || len(v) > maxRetainedMetadata || total > maxRetainedMetadata {
			return nil, "", ErrLimit
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	var n [8]byte
	for _, k := range keys {
		for _, s := range []string{k, records[k]} {
			binary.BigEndian.PutUint64(n[:], uint64(len(s)))
			h.Write(n[:])
			h.Write([]byte(s))
		}
	}
	return keys, hex.EncodeToString(h.Sum(nil)), nil
}
