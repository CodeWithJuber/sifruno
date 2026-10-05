package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"sifruno/internal/cpmove"
)

const cpmovePayloadSentinel = "CPMOVE_CONTENT_MUST_NOT_APPEAR_IN_CATALOG"

func makeCPMoveTAR(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	if err := w.WriteHeader(&tar.Header{Name: "public_html/index.html", Mode: 0600, Size: int64(len(cpmovePayloadSentinel)), Typeflag: tar.TypeReg, Uid: 12, Gid: 34, Uname: "owner-private", Gname: "group-private"}); err != nil {
		t.Fatal("could not create local TAR fixture")
	}
	if _, err := io.WriteString(w, cpmovePayloadSentinel); err != nil || w.Close() != nil {
		t.Fatal("could not finish local TAR fixture")
	}
	return b.Bytes()
}

func makeCPMoveGZIP(t *testing.T, raw []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write(raw); err != nil || w.Close() != nil {
		t.Fatal("could not create local GZIP fixture")
	}
	return b.Bytes()
}

func writeCPMoveFixture(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal("could not write temporary archive fixture")
	}
}

func runCPMoveInspect(t *testing.T, source, output string) (cpmove.Summary, []byte, error) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := run([]string{"backup", "inspect", "--from", source, "--out", output}, &stdout, &stderr)
	if stderr.Len() != 0 {
		t.Fatal("backup command wrote diagnostics")
	}
	var summary cpmove.Summary
	if err == nil {
		if decodeErr := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &summary); decodeErr != nil {
			t.Fatal("backup command did not return a JSON summary")
		}
	} else if stdout.Len() != 0 {
		t.Fatal("failed backup command wrote a success summary")
	}
	return summary, stdout.Bytes(), err
}

func TestCPMoveBackupInspectCatalogsTARAndGZIPWithoutChangingSource(t *testing.T) {
	tarBytes := makeCPMoveTAR(t)
	for _, tc := range []struct {
		name   string
		format string
		bytes  []byte
	}{{"tar", "tar", tarBytes}, {"tar-gz", "tar.gz", makeCPMoveGZIP(t, tarBytes)}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			source := filepath.Join(dir, "source.archive")
			catalog := filepath.Join(dir, "catalog.jsonl")
			writeCPMoveFixture(t, source, tc.bytes)
			before, err := os.ReadFile(source)
			if err != nil {
				t.Fatal("could not read temporary source fixture")
			}
			summary, stdout, err := runCPMoveInspect(t, source, catalog)
			if err != nil || !summary.Complete || summary.Format != tc.format || summary.ArchiveBytes != int64(len(tc.bytes)) || summary.Entries != 1 {
				t.Fatal("valid local archive was not cataloged")
			}
			archiveHash := sha256.Sum256(tc.bytes)
			if summary.ArchiveSHA256 != hex.EncodeToString(archiveHash[:]) || len(stdout) > 4096 {
				t.Fatal("summary hash or output bound mismatch")
			}
			after, err := os.ReadFile(source)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("read-only inspection changed the source archive")
			}
			catalogBytes, err := os.ReadFile(catalog)
			if err != nil || len(catalogBytes) == 0 || int64(len(catalogBytes)) > maxCPMoveCatalogBytes || bytes.Contains(catalogBytes, []byte(cpmovePayloadSentinel)) || bytes.Contains(catalogBytes, []byte("owner-private")) {
				t.Fatal("catalog leaked archive contents or exceeded its bound")
			}
			if runtime.GOOS != "windows" {
				info, statErr := os.Stat(catalog)
				if statErr != nil || info.Mode().Perm() != 0600 {
					t.Fatal("catalog output permissions were not private")
				}
			}
			lines := bytes.Split(catalogBytes, []byte{'\n'})
			if len(lines) != summary.Entries+3 || len(lines[len(lines)-1]) != 0 {
				t.Fatal("catalog header, entries, footer, or final newline mismatch")
			}
			catalogHashInput := append(bytes.Join(lines[:len(lines)-2], []byte{'\n'}), '\n')
			catalogHash := sha256.Sum256(catalogHashInput)
			if summary.CatalogSHA256 != hex.EncodeToString(catalogHash[:]) {
				t.Fatal("catalog seal did not match header and entry lines")
			}
			if !summary.CompatibilityCertified && !summary.ReferenceObserved && !summary.RestoreImplemented {
				return
			}
			t.Fatal("native inspection incorrectly certified original cPanel compatibility")
		})
	}
}

func TestCPMoveBackupInspectRejectsMalformedArchivesAndCleansNewOutput(t *testing.T) {
	validTar := makeCPMoveTAR(t)
	validGzip := makeCPMoveGZIP(t, validTar)
	badCRC := append([]byte(nil), validGzip...)
	badCRC[len(badCRC)-8] ^= 0xff
	for _, tc := range []struct {
		name string
		data []byte
	}{{"bad-tar", []byte("CPMOVE_BAD_ARCHIVE_SECRET")}, {"bad-gzip-crc", badCRC}, {"trailing-gzip-data", append(append([]byte(nil), validGzip...), []byte("extra")...)}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			source := filepath.Join(dir, "bad.archive")
			catalog := filepath.Join(dir, "new.jsonl")
			writeCPMoveFixture(t, source, tc.data)
			_, stdout, err := runCPMoveInspect(t, source, catalog)
			if err == nil || len(stdout) != 0 {
				t.Fatal("malformed archive was accepted")
			}
			if _, statErr := os.Lstat(catalog); !os.IsNotExist(statErr) {
				t.Fatal("failed catalog left a partial output")
			}
		})
	}
}

func TestCPMoveBackupInspectRefusesExistingAndLinkedPaths(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.tar")
	archive := makeCPMoveTAR(t)
	writeCPMoveFixture(t, source, archive)
	existing := filepath.Join(dir, "existing.jsonl")
	const existingContent = "PRESERVE_EXISTING_OUTPUT"
	writeCPMoveFixture(t, existing, []byte(existingContent))
	if _, _, err := runCPMoveInspect(t, source, existing); err == nil {
		t.Fatal("existing output was overwritten")
	}
	got, err := os.ReadFile(existing)
	if err != nil || string(got) != existingContent {
		t.Fatal("existing output changed after refusal")
	}
	hardlink := filepath.Join(dir, "hardlink.jsonl")
	if os.Link(source, hardlink) == nil {
		if _, _, err := runCPMoveInspect(t, hardlink, filepath.Join(dir, "hard-output.jsonl")); err == nil {
			t.Fatal("hard-linked input was accepted")
		}
		if err := os.Remove(hardlink); err != nil {
			t.Fatal("temporary hardlink cleanup failed")
		}
	}
	symlink := filepath.Join(dir, "symlink.tar")
	if os.Symlink(source, symlink) == nil {
		if _, _, err := runCPMoveInspect(t, symlink, filepath.Join(dir, "symlink-output.jsonl")); err == nil {
			t.Fatal("symbolic-link input was accepted")
		}
	}
	if _, _, err := runCPMoveInspect(t, dir, filepath.Join(dir, "directory-output.jsonl")); err == nil {
		t.Fatal("directory input was accepted")
	}
}

func TestCPMoveBackupInspectHasFixedErrorsAndDoesNotInitializeState(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, ".state", "must-not-exist")
	secret := "SECRET_FLAG_SENTINEL"
	var stdout, stderr bytes.Buffer
	err := run([]string{"--state", state, "backup", "inspect", "--from", "input", "--out", "output", "--" + secret}, &stdout, &stderr)
	if err == nil || strings.Contains(err.Error()+stdout.String()+stderr.String(), secret) || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatal("bad flags were echoed or produced output")
	}
	if _, err := os.Lstat(filepath.Join(dir, ".state")); !os.IsNotExist(err) {
		t.Fatal("backup inspect initialized application state")
	}
	if err := run([]string{"backup", "not-inspect", "--from", secret, "--out", secret}, &stdout, &stderr); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("invalid subcommand leaked an argument")
	}
}

func TestCPMoveCatalogWriterStopsAtItsConfiguredBound(t *testing.T) {
	var output bytes.Buffer
	writer := &boundedCatalogWriter{w: &output, remaining: 5}
	n, err := writer.Write([]byte("123456"))
	if err == nil || n != 5 || !writer.exceeded || output.String() != "12345" {
		t.Fatal("catalog writer did not enforce its configured bound")
	}
}
