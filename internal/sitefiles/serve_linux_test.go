//go:build linux

package sitefiles

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// The helper runs fine as the test user: these tests use a temporary
// folder as the home, the way the broker runs it as a site's user.

func newHome(t *testing.T) (string, *os.File) {
	t.Helper()
	dir := t.TempDir()
	f, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return dir, f
}

// call runs one request through Serve and returns the parsed answer and the
// bytes after the answer line.
func call(t *testing.T, home *os.File, r Request, body []byte) (Answer, []byte) {
	t.Helper()
	line, err := EncodeLine(r)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Serve(home, bytes.NewReader(append(line, body...)), &out); err != nil {
		t.Fatalf("%s %s: %v", r.Op, r.Path, err)
	}
	br := bufio.NewReader(&out)
	answerLine, err := ReadLine(br, MaxAnswerLine)
	if err != nil {
		t.Fatal(err)
	}
	a, err := ParseAnswer(r, answerLine)
	if err != nil {
		t.Fatalf("%s %s: answer %s does not check: %v", r.Op, r.Path, answerLine, err)
	}
	rest := new(bytes.Buffer)
	rest.ReadFrom(br)
	return a, rest.Bytes()
}

func wantError(t *testing.T, a Answer, code string) {
	t.Helper()
	if a.Error != code {
		t.Fatalf("answer %+v, want error %q", a, code)
	}
}

func write(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func TestListShowsLinksWithoutFollowing(t *testing.T) {
	dir, home := newHome(t)
	write(t, filepath.Join(dir, "public_html", "index.php"), "<?php echo 1;", 0o644)
	os.Symlink("/etc/shadow", filepath.Join(dir, "public_html", "shadow"))
	os.Symlink("/etc", filepath.Join(dir, "public_html", "etc"))
	os.Mkdir(filepath.Join(dir, "public_html", "wp-content"), 0o755)
	syscall.Mkfifo(filepath.Join(dir, "public_html", "pipe"), 0o600)
	write(t, filepath.Join(dir, "public_html", "bad\nname"), "x", 0o644)
	write(t, filepath.Join(dir, "public_html", "bad\xffname"), "x", 0o644)
	a, _ := call(t, home, Request{Op: OpList, Path: "public_html"}, nil)
	got := map[string]Entry{}
	for _, e := range a.Entries {
		got[e.Name] = e
	}
	if len(a.Entries) != 5 || a.Skipped != 2 || a.Truncated {
		t.Fatalf("list %+v", a)
	}
	if e := got["index.php"]; e.Type != "file" || e.Size != 13 || e.Mode != "0644" {
		t.Fatalf("file %+v", e)
	}
	if got["shadow"].Type != "link" || got["etc"].Type != "link" || got["shadow"].Size != 0 {
		t.Fatalf("links must be listed as links: %+v %+v", got["shadow"], got["etc"])
	}
	if got["wp-content"].Type != "folder" || got["pipe"].Type != "other" {
		t.Fatalf("folder and pipe %+v %+v", got["wp-content"], got["pipe"])
	}
	if a.Entries[0].Name > a.Entries[1].Name {
		t.Fatal("entries must be sorted by name")
	}
	home0, _ := call(t, home, Request{Op: OpList}, nil)
	if len(home0.Entries) != 1 || home0.Entries[0].Name != "public_html" {
		t.Fatalf("home list %+v", home0)
	}
	// A path through a link is refused, so /etc is never listed.
	a, _ = call(t, home, Request{Op: OpList, Path: "public_html/etc"}, nil)
	wantError(t, a, ErrIsLink)
	a, _ = call(t, home, Request{Op: OpList, Path: "public_html/index.php"}, nil)
	wantError(t, a, ErrNotAFolder)
	a, _ = call(t, home, Request{Op: OpList, Path: "missing"}, nil)
	wantError(t, a, ErrNotFound)
}

func TestListStopsAtTheBound(t *testing.T) {
	dir, home := newHome(t)
	for i := range MaxEntries + 3 {
		f, err := os.Create(filepath.Join(dir, "f"+strconv.Itoa(i)))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	a, _ := call(t, home, Request{Op: OpList}, nil)
	if len(a.Entries) != MaxEntries || !a.Truncated {
		t.Fatalf("listed %d, truncated %v", len(a.Entries), a.Truncated)
	}
}

func TestReadIsBoundedTextAndRefusesLinks(t *testing.T) {
	dir, home := newHome(t)
	write(t, filepath.Join(dir, "public_html", "index.php"), "<?php echo 'héllo';\n", 0o644)
	write(t, filepath.Join(dir, "public_html", "logo.png"), "\x89PNG\x00\x00", 0o644)
	write(t, filepath.Join(dir, "big.txt"), strings.Repeat("a", MaxTextBytes+1), 0o644)
	write(t, filepath.Join(dir, "exact.txt"), strings.Repeat("a", MaxTextBytes), 0o644)
	os.Symlink("/etc/shadow", filepath.Join(dir, "shadow"))
	os.Symlink("/etc/passwd", filepath.Join(dir, "passwd"))
	os.Symlink("/etc", filepath.Join(dir, "etc"))
	syscall.Mkfifo(filepath.Join(dir, "pipe"), 0o600)
	a, rest := call(t, home, Request{Op: OpRead, Path: "public_html/index.php"}, nil)
	if a.Error != "" || string(rest) != "<?php echo 'héllo';\n" || a.File.Size != int64(len(rest)) {
		t.Fatalf("read %+v %q", a, rest)
	}
	a, rest = call(t, home, Request{Op: OpRead, Path: "exact.txt"}, nil)
	if a.Error != "" || len(rest) != MaxTextBytes {
		t.Fatalf("a file of exactly the bound must read: %+v", a)
	}
	for path, code := range map[string]string{
		"public_html/logo.png": ErrBinary,
		"big.txt":              ErrTooLarge,
		"shadow":               ErrIsLink,
		"passwd":               ErrIsLink,
		"etc/passwd":           ErrIsLink,
		"public_html":          ErrIsAFolder,
		"pipe":                 ErrNotAFile,
		"missing.txt":          ErrNotFound,
	} {
		a, rest := call(t, home, Request{Op: OpRead, Path: path}, nil)
		wantError(t, a, code)
		if len(rest) != 0 {
			t.Fatalf("%s: a refusal must send no bytes", path)
		}
	}
	a, _ = call(t, home, Request{Op: OpRead, Path: "../etc/passwd"}, nil)
	wantError(t, a, ErrInvalid)
}

func TestDownloadStreamsTheWholeFile(t *testing.T) {
	dir, home := newHome(t)
	data := bytes.Repeat([]byte{0, 1, 2, 0xff}, 3<<18)
	if err := os.WriteFile(filepath.Join(dir, "backup.zip"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	os.Symlink("/etc/shadow", filepath.Join(dir, "shadow.zip"))
	a, rest := call(t, home, Request{Op: OpDownload, Path: "backup.zip"}, nil)
	if a.Error != "" || a.File.Size != int64(len(data)) || !bytes.Equal(rest, data) {
		t.Fatalf("download %+v, %d bytes", a, len(rest))
	}
	a, _ = call(t, home, Request{Op: OpDownload, Path: "shadow.zip"}, nil)
	wantError(t, a, ErrIsLink)
}

func noTemporaries(t *testing.T, dir string) {
	t.Helper()
	matches, _ := filepath.Glob(filepath.Join(dir, ".sifruno-*.tmp"))
	if len(matches) != 0 {
		t.Fatalf("temporary files left: %v", matches)
	}
}

func TestWriteIsAtomicAndKeepsTheMode(t *testing.T) {
	dir, home := newHome(t)
	index := filepath.Join(dir, "public_html", "index.php")
	write(t, index, "old", 0o640)
	old, err := os.Open(index)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	listed, _ := call(t, home, Request{Op: OpList, Path: "public_html"}, nil)
	loaded := listed.Entries[0].Version
	body := []byte("<?php echo 'new';\n")
	a, _ := call(t, home, Request{Op: OpWrite, Path: "public_html/index.php", Size: int64(len(body)), ExpectedVersion: loaded}, body)
	if a.Error != "" || a.File.Mode != "0640" || a.File.Version == loaded {
		t.Fatalf("write %+v", a)
	}
	after, _ := os.Stat(index)
	if got, _ := os.ReadFile(index); string(got) != string(body) || after.Mode().Perm() != 0o640 {
		t.Fatalf("written %q %v", got, after.Mode())
	}
	// The new content is a new file renamed into place: a reader that had
	// the old file open keeps the old bytes, and nobody sees half a file.
	if kept, _ := io.ReadAll(old); string(kept) != "old" {
		t.Fatalf("a write must replace the file by rename, not rewrite it in place: %q", kept)
	}
	// The version a save answers with is the one the file now has, so the
	// editor can save again straight away.
	again, _ := call(t, home, Request{Op: OpWrite, Path: "public_html/index.php", Size: int64(len(body)), ExpectedVersion: a.File.Version}, body)
	if again.Error != "" {
		t.Fatalf("second save %+v", again)
	}
	reread, _ := call(t, home, Request{Op: OpRead, Path: "public_html/index.php"}, nil)
	if reread.File.Version != again.File.Version {
		t.Fatalf("a read after a save shows version %s, the save answered %s", reread.File.Version, again.File.Version)
	}
	noTemporaries(t, filepath.Join(dir, "public_html"))
	// The page that loaded the old version cannot overwrite the new one.
	a, _ = call(t, home, Request{Op: OpWrite, Path: "public_html/index.php", Size: 1, ExpectedVersion: loaded}, []byte("x"))
	wantError(t, a, ErrChanged)
	// A new file is made 0644.
	a, _ = call(t, home, Request{Op: OpWrite, Path: "public_html/new.css", Size: 4}, []byte("a{} "))
	if a.Error != "" || a.File.Mode != "0644" {
		t.Fatalf("new file %+v", a)
	}
	a, _ = call(t, home, Request{Op: OpWrite, Path: "public_html/bin.txt", Size: 3}, []byte("a\x00b"))
	wantError(t, a, ErrBinary)
	if _, err := os.Stat(filepath.Join(dir, "public_html", "bin.txt")); !os.IsNotExist(err) {
		t.Fatal("a refused write must make nothing")
	}
	noTemporaries(t, filepath.Join(dir, "public_html"))
}

func TestWriteNeverFollowsALink(t *testing.T) {
	dir, home := newHome(t)
	outside := t.TempDir()
	target := filepath.Join(outside, "victim.txt")
	write(t, target, "untouched", 0o644)
	os.Symlink(target, filepath.Join(dir, "link.txt"))
	os.Symlink(outside, filepath.Join(dir, "linkdir"))
	a, _ := call(t, home, Request{Op: OpWrite, Path: "link.txt", Size: 5}, []byte("owned"))
	wantError(t, a, ErrIsLink)
	a, _ = call(t, home, Request{Op: OpWrite, Path: "linkdir/victim.txt", Size: 5}, []byte("owned"))
	wantError(t, a, ErrIsLink)
	a, _ = call(t, home, Request{Op: OpUpload, Path: "link.txt", Size: 5, Overwrite: true}, []byte("owned"))
	wantError(t, a, ErrIsLink)
	if got, _ := os.ReadFile(target); string(got) != "untouched" {
		t.Fatalf("a link's target changed: %q", got)
	}
	if fi, err := os.Lstat(filepath.Join(dir, "link.txt")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the link must stay a link")
	}
}

func TestUploadNeedsOverwriteAndTheExactSize(t *testing.T) {
	dir, home := newHome(t)
	data := bytes.Repeat([]byte{0xde, 0xad, 0, 0xbe, 0xef}, 1<<16)
	a, _ := call(t, home, Request{Op: OpUpload, Path: "photo.jpg", Size: int64(len(data))}, data)
	if a.Error != "" || a.File.Size != int64(len(data)) {
		t.Fatalf("upload %+v", a)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "photo.jpg")); !bytes.Equal(got, data) {
		t.Fatal("uploaded bytes differ")
	}
	a, _ = call(t, home, Request{Op: OpUpload, Path: "photo.jpg", Size: 3}, []byte("new"))
	wantError(t, a, ErrExists)
	a, _ = call(t, home, Request{Op: OpUpload, Path: "photo.jpg", Size: 3, Overwrite: true}, []byte("new"))
	if a.Error != "" {
		t.Fatalf("overwrite %+v", a)
	}
	os.Mkdir(filepath.Join(dir, "folder"), 0o755)
	a, _ = call(t, home, Request{Op: OpUpload, Path: "folder", Size: 1, Overwrite: true}, []byte("x"))
	wantError(t, a, ErrIsAFolder)
	a, _ = call(t, home, Request{Op: OpUpload, Path: "missing/x", Size: 1}, []byte("x"))
	wantError(t, a, ErrNotFound)
	// Fewer bytes than the size, or more, is a broken request: nothing is
	// made and the helper fails rather than answer.
	for _, body := range [][]byte{[]byte("ab"), []byte("abcd")} {
		line, _ := EncodeLine(Request{Op: OpUpload, Path: "short.bin", Size: 3})
		if err := Serve(home, bytes.NewReader(append(line, body...)), new(bytes.Buffer)); err == nil {
			t.Fatalf("%d bytes for a size of 3 must fail", len(body))
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "short.bin")); !os.IsNotExist(err) {
		t.Fatal("a broken upload must leave nothing")
	}
	noTemporaries(t, dir)
}

func TestMkdirRenameAndMode(t *testing.T) {
	dir, home := newHome(t)
	a, _ := call(t, home, Request{Op: OpMkdir, Path: "images"}, nil)
	if a.Error != "" || a.File.Type != "folder" || a.File.Mode != "0755" {
		t.Fatalf("mkdir %+v", a)
	}
	a, _ = call(t, home, Request{Op: OpMkdir, Path: "images"}, nil)
	wantError(t, a, ErrExists)
	write(t, filepath.Join(dir, "a.txt"), "a", 0o644)
	write(t, filepath.Join(dir, "b.txt"), "b", 0o644)
	a, _ = call(t, home, Request{Op: OpRename, Path: "a.txt", To: "images/a.txt"}, nil)
	if a.Error != "" || a.File.Name != "a.txt" {
		t.Fatalf("rename %+v", a)
	}
	a, _ = call(t, home, Request{Op: OpRename, Path: "b.txt", To: "images/a.txt"}, nil)
	wantError(t, a, ErrExists)
	if got, _ := os.ReadFile(filepath.Join(dir, "images", "a.txt")); string(got) != "a" {
		t.Fatal("a rename must never replace a name")
	}
	// A link is renamed as itself; its target stays where it is.
	outside := t.TempDir()
	write(t, filepath.Join(outside, "keep"), "keep", 0o644)
	os.Symlink(filepath.Join(outside, "keep"), filepath.Join(dir, "link"))
	a, _ = call(t, home, Request{Op: OpRename, Path: "link", To: "images/link"}, nil)
	if a.Error != "" || a.File.Type != "link" {
		t.Fatalf("rename link %+v", a)
	}
	if _, err := os.Stat(filepath.Join(outside, "keep")); err != nil {
		t.Fatal("the link's target moved")
	}
	a, _ = call(t, home, Request{Op: OpMode, Path: "b.txt", Mode: "0600"}, nil)
	if a.Error != "" || a.File.Mode != "0600" {
		t.Fatalf("mode %+v", a)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "b.txt")); fi.Mode().Perm() != 0o600 {
		t.Fatal("mode not set")
	}
	a, _ = call(t, home, Request{Op: OpMode, Path: "images/link", Mode: "0777"}, nil)
	wantError(t, a, ErrIsLink)
	if fi, _ := os.Stat(filepath.Join(outside, "keep")); fi.Mode().Perm() != 0o644 {
		t.Fatal("a mode change through a link changed its target")
	}
	a, _ = call(t, home, Request{Op: OpMode, Path: "b.txt", Mode: "4755"}, nil)
	wantError(t, a, ErrInvalid)
}

func TestDeleteNeverFollowsALink(t *testing.T) {
	dir, home := newHome(t)
	outside := t.TempDir()
	write(t, filepath.Join(outside, "important", "data.txt"), "keep me", 0o644)
	write(t, filepath.Join(dir, "old", "a", "b", "c.txt"), "c", 0o644)
	os.Symlink(filepath.Join(outside, "important"), filepath.Join(dir, "old", "a", "linkdir"))
	os.Symlink(filepath.Join(outside, "important", "data.txt"), filepath.Join(dir, "old", "linkfile"))
	a, _ := call(t, home, Request{Op: OpDelete, Path: "old"}, nil)
	if a.Error != "" || a.File.Type != "folder" {
		t.Fatalf("delete %+v", a)
	}
	if _, err := os.Lstat(filepath.Join(dir, "old")); !os.IsNotExist(err) {
		t.Fatal("the folder must be gone")
	}
	if got, err := os.ReadFile(filepath.Join(outside, "important", "data.txt")); err != nil || string(got) != "keep me" {
		t.Fatal("a delete went through a link")
	}
	// A link to a folder is removed as itself.
	os.Symlink(outside, filepath.Join(dir, "shortcut"))
	a, _ = call(t, home, Request{Op: OpDelete, Path: "shortcut"}, nil)
	if a.Error != "" || a.File.Type != "link" {
		t.Fatalf("delete link %+v", a)
	}
	if _, err := os.Stat(filepath.Join(outside, "important", "data.txt")); err != nil {
		t.Fatal("deleting a link removed its target")
	}
	a, _ = call(t, home, Request{Op: OpDelete, Path: "shortcut"}, nil)
	wantError(t, a, ErrNotFound)
}

func TestPermissionsAreTheUsersOwn(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores permission bits")
	}
	dir, home := newHome(t)
	write(t, filepath.Join(dir, "locked", "private.txt"), "x", 0o644)
	os.Chmod(filepath.Join(dir, "locked"), 0)
	t.Cleanup(func() { os.Chmod(filepath.Join(dir, "locked"), 0o755) })
	a, _ := call(t, home, Request{Op: OpRead, Path: "locked/private.txt"}, nil)
	wantError(t, a, ErrPermission)
	a, _ = call(t, home, Request{Op: OpList, Path: "locked"}, nil)
	wantError(t, a, ErrPermission)
}

func TestServeRefusesAHomeOfAnotherUser(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns the test folders")
	}
	root, err := os.Open("/")
	if err != nil {
		t.Skip(err)
	}
	defer root.Close()
	line, _ := EncodeLine(Request{Op: OpList})
	if Serve(root, bytes.NewReader(line), new(bytes.Buffer)) == nil {
		t.Fatal("a folder the user does not own must be refused as the home")
	}
}

func TestBrokenRequestLineIsInvalid(t *testing.T) {
	_, home := newHome(t)
	var out bytes.Buffer
	if err := Serve(home, strings.NewReader(`{"op":"read","path":"/etc/shadow"}`+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != `{"error":"invalid"}` {
		t.Fatalf("answer %q", out.String())
	}
	if err := Serve(home, strings.NewReader(strings.Repeat("x", MaxRequestLine+1)+"\n"), &out); err == nil {
		t.Fatal("an over-long request line must fail")
	}
}
