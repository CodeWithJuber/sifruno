package cpmove

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

// All fixtures in this package are synthetic. No licensed vendor backup or
// reference extraction was observed; these tests do not certify compatibility.
type syntheticEntry struct {
	h       tar.Header
	payload string
}

func syntheticTar(t *testing.T, entries ...syntheticEntry) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range entries {
		h := e.h
		if h.Typeflag == 0 {
			h.Typeflag = tar.TypeReg
		}
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(e.payload))
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.payload)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func syntheticGzip(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	z := gzip.NewWriter(&out)
	if _, err := z.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func collect(t *testing.T, b []byte) (Summary, []Entry, error) {
	t.Helper()
	var entries []Entry
	s, err := Inspect(context.Background(), bytes.NewReader(b), DefaultLimits(), func(e Entry) error { entries = append(entries, e); return nil })
	return s, entries, err
}
func requireFailure(t *testing.T, b []byte, want error) {
	t.Helper()
	var output bytes.Buffer
	s, err := WriteCatalog(context.Background(), bytes.NewReader(b), &output, DefaultLimits())
	if !errors.Is(err, want) || s != (Summary{}) {
		t.Fatalf("summary=%+v err=%v want=%v", s, err, want)
	}
	if bytes.Contains(output.Bytes(), []byte(`"complete":true`)) {
		t.Fatal("failure produced complete footer")
	}
}

func TestSyntheticHashesAndCatalog(t *testing.T) {
	secret := "synthetic-secret-payload-never-cataloged"
	stamp := time.Date(2026, 10, 4, 12, 34, 56, 123456789, time.FixedZone("synthetic", 7200))
	plain := syntheticTar(t, syntheticEntry{tar.Header{Name: "./homedir/data", Mode: 0640, Uid: 42, Gid: 43, Uname: "owner", Gname: "group", ModTime: stamp, AccessTime: stamp, ChangeTime: stamp, Format: tar.FormatPAX, PAXRecords: map[string]string{"vendor.note": "synthetic-private-value", "vendor.other": "x"}}, secret})
	for _, compressed := range []bool{false, true} {
		t.Run(fmt.Sprint(compressed), func(t *testing.T) {
			input := plain
			format := "tar"
			if compressed {
				input = syntheticGzip(t, plain)
				format = "tar.gz"
			}
			var output bytes.Buffer
			s, err := WriteCatalog(context.Background(), bytes.NewReader(input), &output, DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			if !s.Complete || s.CompatibilityCertified || s.ReferenceObserved || s.RestoreImplemented || s.ArchiveSHA256 != sum(input) || s.ArchiveBytes != int64(len(input)) || s.ExpandedBytes != int64(len(plain)) || s.FileBytes != int64(len(secret)) || s.Entries != 1 || s.Format != format {
				t.Fatalf("bad summary %+v", s)
			}
			lines := bytes.Split(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), []byte{'\n'})
			if len(lines) != 3 {
				t.Fatalf("lines=%d", len(lines))
			}
			if s.CatalogSHA256 != sum(append(append(append([]byte{}, lines[0]...), '\n'), append(lines[1], '\n')...)) {
				t.Fatal("catalog hash mismatch")
			}
			var rec struct {
				Type  string `json:"type"`
				Entry Entry  `json:"entry"`
			}
			if err := json.Unmarshal(lines[1], &rec); err != nil {
				t.Fatal(err)
			}
			e := rec.Entry
			if e.Index != 0 || e.NameBase64 != base64.StdEncoding.EncodeToString([]byte("./homedir/data")) || e.Type != "file" || e.SHA256 != sum([]byte(secret)) || e.Mode != 0640 || e.UID != 42 || e.GID != 43 || e.ModTime != stamp.UTC().Format(time.RFC3339Nano) || e.AccessTime != e.ModTime || e.ChangeTime != e.ModTime || e.Component != "homedir" {
				t.Fatalf("bad entry %+v", e)
			}
			if strings.Contains(output.String(), secret) || strings.Contains(output.String(), "synthetic-private-value") {
				t.Fatal("payload/PAX value leaked")
			}
			_, entries, err := collect(t, input)
			if err != nil || len(entries) != 1 {
				t.Fatal(err)
			}
			if entries[0].PAXSHA256 != e.PAXSHA256 {
				t.Fatal("PAX hash unstable")
			}
		})
	}
}

func TestSyntheticGNUAndPAXNames(t *testing.T) {
	for _, format := range []tar.Format{tar.FormatGNU, tar.FormatPAX} {
		t.Run(format.String(), func(t *testing.T) {
			name := strings.Repeat("segment/", 20) + "資料"
			if format == tar.FormatGNU {
				name = strings.Repeat("segment/", 20) + string([]byte{0xff, 0xfe})
			}
			input := syntheticTar(t, syntheticEntry{tar.Header{Name: name, Format: format}, "long"}, syntheticEntry{tar.Header{Name: "Case"}, "A"}, syntheticEntry{tar.Header{Name: "case"}, "a"}, syntheticEntry{tar.Header{Name: "custom/unknown"}, "unknown"})
			s, entries, err := collect(t, input)
			if err != nil {
				t.Fatal(err)
			}
			if s.Entries != 4 || entries[0].NameBase64 != b64(name) || entries[0].SHA256 != sum([]byte("long")) || entries[3].Component != "unclassified" {
				t.Fatal("name/content fidelity lost")
			}
		})
	}
}

func TestSyntheticPAXDigestExactBytes(t *testing.T) {
	records := map[string]string{"z": string([]byte{0xff, 0xfe}), "a": "b\x00c"}
	keys, digest, err := paxDigest(records, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(keys, []string{"a", "z"}) {
		t.Fatal(keys)
	}
	var canonical bytes.Buffer
	for _, key := range keys {
		for _, s := range []string{key, records[key]} {
			if err := binary.Write(&canonical, binary.BigEndian, uint64(len(s))); err != nil {
				t.Fatal(err)
			}
			canonical.WriteString(s)
		}
	}
	if digest != sum(canonical.Bytes()) {
		t.Fatal("not exact length-prefixed bytes")
	}
	_, different, _ := paxDigest(map[string]string{"z": "��", "a": "b\x00c"}, DefaultLimits())
	if digest == different {
		t.Fatal("invalid UTF8 collapsed")
	}
}

func TestSyntheticPathsAndLinks(t *testing.T) {
	for _, name := range []string{"/absolute", "../escape", "x/../alias", "x/./alias", "x//alias", "././alias", ""} {
		t.Run(fmt.Sprintf("path-%x", name), func(t *testing.T) {
			requireFailure(t, syntheticTar(t, syntheticEntry{tar.Header{Name: name}, ""}), ErrArchive)
		})
	}
	for _, names := range [][2]string{{"a", "./a"}, {"dir/", "dir"}} {
		firstType := byte(tar.TypeReg)
		if strings.HasSuffix(names[0], "/") {
			firstType = tar.TypeDir
		}
		requireFailure(t, syntheticTar(t, syntheticEntry{tar.Header{Name: names[0], Typeflag: firstType}, ""}, syntheticEntry{tar.Header{Name: names[1]}, ""}), ErrArchive)
	}
	input := syntheticTar(t, syntheticEntry{tar.Header{Name: "./", Typeflag: tar.TypeDir}, ""}, syntheticEntry{tar.Header{Name: "./dir/", Typeflag: tar.TypeDir}, ""}, syntheticEntry{tar.Header{Name: "forward", Typeflag: tar.TypeLink, Linkname: "./target"}, ""}, syntheticEntry{tar.Header{Name: "target"}, "x"}, syntheticEntry{tar.Header{Name: "dir/internal", Typeflag: tar.TypeSymlink, Linkname: "../target"}, ""}, syntheticEntry{tar.Header{Name: "external", Typeflag: tar.TypeSymlink, Linkname: "../../etc/passwd"}, ""}, syntheticEntry{tar.Header{Name: "absolute", Typeflag: tar.TypeLink, Linkname: "/etc/passwd"}, ""}, syntheticEntry{tar.Header{Name: "device", Typeflag: tar.TypeChar}, ""}, syntheticEntry{tar.Header{Name: "windows\\literal"}, ""})
	s, entries, err := collect(t, input)
	if err != nil {
		t.Fatal(err)
	}
	if s.BlockerCount != 8 || len(entries[5].RestoreBlockers) != 2 || entries[2].LinkNameBase64 != b64("./target") || entries[2].RestoreBlockers[0] != "hardlink_requires_restore_validation" {
		t.Fatalf("blockers=%d entries=%+v", s.BlockerCount, entries)
	}
	for _, target := range []string{"missing", "link", "dir"} {
		requireFailure(t, syntheticTar(t, syntheticEntry{tar.Header{Name: "link", Typeflag: tar.TypeLink, Linkname: target}, ""}, syntheticEntry{tar.Header{Name: "dir", Typeflag: tar.TypeDir}, ""}), ErrArchive)
	}
}

func TestSyntheticTrailerAndGzipValidation(t *testing.T) {
	plain := syntheticTar(t, syntheticEntry{tar.Header{Name: "file"}, "payload"})
	for _, bad := range [][]byte{plain[:len(plain)-1024], plain[:len(plain)-512], plain[:len(plain)-1], append(append([]byte{}, plain...), 1), append(append([]byte{}, plain...), make([]byte, 17)...), append(append([]byte{}, plain...), plain...)} {
		requireFailure(t, bad, ErrArchive)
	}
	padding := append(append([]byte{}, plain...), make([]byte, 1024)...)
	if _, _, err := collect(t, padding); err != nil {
		t.Fatal(err)
	}
	corrupt := append([]byte{}, plain...)
	corrupt[0] ^= 1
	requireFailure(t, corrupt, ErrArchive)
	z := syntheticGzip(t, plain)
	for _, bad := range [][]byte{z[:len(z)-1], z[:len(z)-8], append(append([]byte{}, z...), 1), append(append([]byte{}, z...), syntheticGzip(t, plain)...)} {
		requireFailure(t, bad, ErrArchive)
	}
	badCRC := append([]byte{}, z...)
	badCRC[len(badCRC)-8] ^= 1
	requireFailure(t, badCRC, ErrArchive)
	// A member boundary may occur anywhere within the single decoded TAR.
	combined := append(syntheticGzip(t, plain[:700]), syntheticGzip(t, plain[700:])...)
	s, _, err := collect(t, combined)
	if err != nil || s.ArchiveSHA256 != sum(combined) {
		t.Fatalf("combined: %+v %v", s, err)
	}
	badSecond := append([]byte{}, combined...)
	badSecond[len(badSecond)-8] ^= 1
	requireFailure(t, badSecond, ErrArchive)
}

func physicalFrame(t *testing.T, kind byte, payload string) []byte {
	t.Helper()
	header := append([]byte{}, syntheticTar(t, syntheticEntry{tar.Header{Name: "synthetic-physical", Format: tar.FormatUSTAR}, ""})[:512]...)
	header[156] = kind
	copy(header[124:136], fmt.Sprintf("%011o\x00", len(payload)))
	for i := 148; i < 156; i++ {
		header[i] = ' '
	}
	checksum := 0
	for _, b := range header {
		checksum += int(b)
	}
	copy(header[148:156], fmt.Sprintf("%06o\x00 ", checksum))
	frame := append(header, []byte(payload)...)
	return append(frame, make([]byte, (512-len(payload)%512)%512)...)
}
func paxRecord(k, v string) string {
	body := " " + k + "=" + v + "\n"
	n := len(body) + 1
	for {
		next := len(body) + len(fmt.Sprint(n))
		if n == next {
			return fmt.Sprint(n) + body
		}
		n = next
	}
}

func TestSyntheticPhysicalMetadataUnsupported(t *testing.T) {
	valid := syntheticTar(t, syntheticEntry{tar.Header{Name: "regular"}, "x"})
	for _, key := range []string{"GNU.sparse.map", "GNU.sparse.major", "GNU.sparse.unknown", "SCHILY.realsize"} {
		requireFailure(t, append(physicalFrame(t, tar.TypeXHeader, paxRecord(key, "0")), valid...), ErrUnsupported)
	}
	requireFailure(t, append(physicalFrame(t, tar.TypeXHeader, paxRecord("SCHILY.filetype", "sparse")), valid...), ErrUnsupported)
	for _, kind := range []byte{tar.TypeGNUSparse, tar.TypeXGlobalHeader} {
		requireFailure(t, append(valid[:len(valid)-1024], physicalFrame(t, kind, "")...), ErrUnsupported)
	}
	duplicate := paxRecord("vendor.key", "first") + paxRecord("vendor.key", "second")
	requireFailure(t, append(physicalFrame(t, tar.TypeXHeader, duplicate), valid...), ErrUnsupported)
	one := physicalFrame(t, tar.TypeXHeader, paxRecord("vendor.key", "x"))
	requireFailure(t, append(append(append([]byte{}, one...), one...), valid...), ErrUnsupported)
	requireFailure(t, append(one, make([]byte, 1024)...), ErrArchive)
	requireFailure(t, append(physicalFrame(t, tar.TypeXHeader, "malformed"), valid...), ErrArchive)
	requireFailure(t, append(physicalFrame(t, tar.TypeXHeader, paxRecord("vendor.large", strings.Repeat("x", maxRetainedMetadata))), valid...), ErrLimit)
	requireFailure(t, append(physicalFrame(t, tar.TypeXHeader, strings.Repeat("x", maxMetadata+1)), valid...), ErrLimit)
	for _, kind := range []byte{tar.TypeGNULongName, tar.TypeGNULongLink} {
		requireFailure(t, append(physicalFrame(t, kind, "ordinary\x00hidden"), valid...), ErrUnsupported)
		requireFailure(t, append(physicalFrame(t, kind, ""), valid...), ErrUnsupported)
	}
}

func TestSyntheticPhysicalTypesAndDeviceNumbers(t *testing.T) {
	for _, kind := range []byte{tar.TypeRegA, tar.TypeReg, 'Z'} {
		input := append(physicalFrame(t, kind, "x"), make([]byte, 1024)...)
		_, entries, err := collect(t, input)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || entries[0].PhysicalTypeFlag != kind {
			t.Fatalf("physical type lost: %+v", entries)
		}
	}
	for _, kind := range []byte{tar.TypeChar, tar.TypeBlock} {
		input := syntheticTar(t, syntheticEntry{tar.Header{Name: "device", Typeflag: kind, Devmajor: 12, Devminor: 34, Mode: 0600}, ""})
		_, entries, err := collect(t, input)
		if err != nil {
			t.Fatal(err)
		}
		if entries[0].PhysicalTypeFlag != kind || entries[0].DevMajor != 12 || entries[0].DevMinor != 34 || len(entries[0].RestoreBlockers) != 1 {
			t.Fatalf("device fidelity: %+v", entries[0])
		}
	}
	for _, name := range []string{"", "././", "./././", "x//"} {
		if _, ok := canonicalName(name, true); ok {
			t.Fatalf("directory alias accepted: %q", name)
		}
	}
}

func TestSyntheticPAXSizeAndUnknownPayload(t *testing.T) {
	file := physicalFrame(t, tar.TypeReg, "synthetic")
	// SDK precedence uses PAX size; physical guard must use it as well.
	copy(file[124:136], "00000000000\x00")
	for i := 148; i < 156; i++ {
		file[i] = ' '
	}
	checksum := 0
	for _, b := range file[:512] {
		checksum += int(b)
	}
	copy(file[148:156], fmt.Sprintf("%06o\x00 ", checksum))
	input := append(physicalFrame(t, tar.TypeXHeader, paxRecord("size", "9")), file...)
	input = append(input, make([]byte, 1024)...)
	s, entries, err := collect(t, input)
	if err != nil || s.FileBytes != 9 || entries[0].SHA256 != sum([]byte("synthetic")) {
		t.Fatalf("PAX precedence %v %+v", err, s)
	}
	unknown := append(physicalFrame(t, 'Z', "secret-unknown-content"), make([]byte, 1024)...)
	s, entries, err = collect(t, unknown)
	if err != nil || s.ArchiveSHA256 != sum(unknown) || entries[0].Type != "other" || entries[0].SHA256 != "" || entries[0].RestoreBlockers[0] != "unknown_entry_type" {
		t.Fatalf("unknown: %v %+v", err, entries)
	}
}

func TestSyntheticLimits(t *testing.T) {
	plain := syntheticTar(t, syntheticEntry{tar.Header{Name: "long/path"}, "12345"}, syntheticEntry{tar.Header{Name: "second"}, "x"})
	for _, mutate := range []func(*Limits){func(l *Limits) { l.MaxArchiveBytes = int64(len(plain) - 1) }, func(l *Limits) { l.MaxExpandedBytes = int64(len(plain) - 1) }, func(l *Limits) { l.MaxFileBytes = 4 }, func(l *Limits) { l.MaxEntries = 1 }, func(l *Limits) { l.MaxPathBytes = 4 }} {
		l := DefaultLimits()
		mutate(&l)
		s, err := Inspect(context.Background(), bytes.NewReader(plain), l, func(Entry) error { return nil })
		if err != ErrLimit || s != (Summary{}) {
			t.Fatalf("limits=%+v s=%+v err=%v", l, s, err)
		}
	}
	for _, mutate := range []func(*Limits){func(l *Limits) { l.MaxArchiveBytes = 0 }, func(l *Limits) { l.MaxExpandedBytes = -1 }, func(l *Limits) { l.MaxFileBytes++ }, func(l *Limits) { l.MaxEntries++ }, func(l *Limits) { l.MaxPathBytes++ }} {
		l := DefaultLimits()
		mutate(&l)
		if _, err := Inspect(context.Background(), bytes.NewReader(plain), l, func(Entry) error { return nil }); err != ErrInvalid {
			t.Fatal(err)
		}
	}
	for _, compressed := range []bool{false, true} {
		input := plain
		if compressed {
			input = syntheticGzip(t, plain)
		}
		l := DefaultLimits()
		l.MaxArchiveBytes = int64(len(input))
		l.MaxExpandedBytes = int64(len(plain))
		if _, err := Inspect(context.Background(), bytes.NewReader(input), l, func(Entry) error { return nil }); err != nil {
			t.Fatalf("exact limit: %v", err)
		}
	}
}

type syntheticFailWriter struct{}

func (syntheticFailWriter) Write([]byte) (int, error) {
	return 0, errors.New("synthetic-output-secret")
}

type syntheticShortWriter struct{}

func (syntheticShortWriter) Write(b []byte) (int, error) { return len(b) - 1, nil }

type syntheticFailReader struct{}

func (syntheticFailReader) Read([]byte) (int, error) { return 0, errors.New("synthetic-input-secret") }

type syntheticCancelReader struct {
	r      io.Reader
	cancel context.CancelFunc
}

func (r syntheticCancelReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.cancel()
	return n, err
}
func TestSyntheticFailuresAndCancellation(t *testing.T) {
	plain := syntheticTar(t, syntheticEntry{tar.Header{Name: "file"}, "payload"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Inspect(ctx, bytes.NewReader(plain), DefaultLimits(), func(Entry) error { return nil }); err != ErrCanceled {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	if _, err := Inspect(ctx, syntheticCancelReader{bytes.NewReader(plain), cancel}, DefaultLimits(), func(Entry) error { return nil }); err != ErrCanceled {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	if s, err := Inspect(ctx, bytes.NewReader(plain), DefaultLimits(), func(Entry) error { cancel(); return nil }); err != ErrCanceled || s != (Summary{}) {
		t.Fatal(s, err)
	}
	if s, err := Inspect(context.Background(), bytes.NewReader(plain), DefaultLimits(), func(Entry) error { return errors.New("synthetic-callback-secret") }); err != ErrIO || s != (Summary{}) {
		t.Fatal(s, err)
	}
	for _, writer := range []io.Writer{syntheticFailWriter{}, syntheticShortWriter{}} {
		if s, err := WriteCatalog(context.Background(), bytes.NewReader(plain), writer, DefaultLimits()); err != ErrIO || s != (Summary{}) {
			t.Fatal(s, err)
		}
	}
	if _, err := Inspect(context.Background(), syntheticFailReader{}, DefaultLimits(), func(Entry) error { return nil }); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal(err)
	}
	if _, err := Inspect(nil, bytes.NewReader(plain), DefaultLimits(), func(Entry) error { return nil }); err != ErrInvalid {
		t.Fatal(err)
	}
	if _, err := Inspect(context.Background(), nil, DefaultLimits(), func(Entry) error { return nil }); err != ErrInvalid {
		t.Fatal(err)
	}
	if _, err := Inspect(context.Background(), bytes.NewReader(plain), DefaultLimits(), nil); err != ErrInvalid {
		t.Fatal(err)
	}
	if _, err := WriteCatalog(context.Background(), bytes.NewReader(plain), nil, DefaultLimits()); err != ErrInvalid {
		t.Fatal(err)
	}
}
