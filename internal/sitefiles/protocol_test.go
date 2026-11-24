package sitefiles

import (
	"bufio"
	"strings"
	"testing"
)

func TestSplitPathRefusesWhatLeavesTheHome(t *testing.T) {
	long := strings.Repeat("a", MaxNameBytes)
	deep := strings.TrimSuffix(strings.Repeat("a/", MaxDepth), "/")
	for _, p := range []string{"public_html", "public_html/index.php", ".htaccess", "a b/ç.txt", long, deep, "...", "a..b"} {
		if _, ok := SplitPath(p); !ok {
			t.Errorf("%q must be accepted", p)
		}
	}
	for _, p := range []string{
		"/etc/shadow", "../x", "a/../../b", "..", ".", "./a", "a/.", "a//b", "a/", "/", "a\x00b", "a\nb", "a\tb", "a\x7fb", "a\u0085b",
		long + "a", deep + "/a", strings.Repeat("ab/", 400) + "c", "\xff\xfe", "a\\..",
	} {
		if p == "a\\.." {
			// A backslash is an ordinary character in a Linux name.
			if _, ok := SplitPath(p); !ok {
				t.Errorf("%q must be accepted", p)
			}
			continue
		}
		if _, ok := SplitPath(p); ok {
			t.Errorf("%q must be refused", p)
		}
	}
	if names, ok := SplitPath(""); !ok || names != nil {
		t.Fatal("the empty path is the home")
	}
}

func TestValidateTakesOnlyEachOperationsFields(t *testing.T) {
	ok := []Request{
		{Op: OpList},
		{Op: OpList, Path: "public_html"},
		{Op: OpRead, Path: "a.txt"},
		{Op: OpDownload, Path: "a.zip"},
		{Op: OpWrite, Path: "a.txt", Size: MaxTextBytes},
		{Op: OpWrite, Path: "a.txt", Size: 3, ExpectedVersion: "0123456789abcdef"},
		{Op: OpUpload, Path: "a.zip", Size: MaxUploadBytes, Overwrite: true},
		{Op: OpMkdir, Path: "new"},
		{Op: OpRename, Path: "a", To: "b/a"},
		{Op: OpRename, Path: "a", To: "ab"},
		{Op: OpDelete, Path: "a"},
		{Op: OpMode, Path: "a", Mode: "0640"},
		{Op: OpMode, Path: "a", Mode: "755"},
	}
	for _, r := range ok {
		if err := Validate(r); err != nil {
			t.Errorf("%+v must be accepted", r)
		}
	}
	bad := []Request{
		{Op: "exec", Path: "a"},
		{Op: OpRead},
		{Op: OpDelete},
		{Op: OpMkdir},
		{Op: OpList, Size: 1},
		{Op: OpRead, Path: "a", Mode: "0644"},
		{Op: OpWrite, Path: "a", Size: MaxTextBytes + 1},
		{Op: OpWrite, Path: "a", Size: -1},
		{Op: OpWrite, Path: "a", Overwrite: true},
		{Op: OpWrite, Path: "a", ExpectedVersion: "yesterday"},
		{Op: OpWrite, Path: "a", ExpectedVersion: "0123456789ABCDEF"},
		{Op: OpUpload, Path: "a", Size: MaxUploadBytes + 1},
		{Op: OpUpload, Path: "a", ExpectedVersion: "0123456789abcdef"},
		{Op: OpRename, Path: "a"},
		{Op: OpRename, Path: "a", To: "a"},
		{Op: OpRename, Path: "a", To: "a/b"},
		{Op: OpRename, Path: "a", To: "../b"},
		{Op: OpMode, Path: "a", Mode: "4755"},
		{Op: OpMode, Path: "a", Mode: "2755"},
		{Op: OpMode, Path: "a", Mode: "1777"},
		{Op: OpMode, Path: "a", Mode: "0778"},
		{Op: OpMode, Path: "a", Mode: "+x"},
		{Op: OpMode, Path: "a"},
		{Op: OpDownload, Path: "/etc/shadow"},
	}
	for _, r := range bad {
		if err := Validate(r); err == nil {
			t.Errorf("%+v must be refused", r)
		}
	}
}

func TestParseRequestIsStrict(t *testing.T) {
	for _, line := range []string{
		`{"op":"list","path":"","extra":1}`,
		`{"op":"list","path":""} {"op":"list"}`,
		`{"op":"list","path":""}}`,
		`{"op":"list","path":""}]`,
		`{"op":"read","path":"../x"}`,
		`["list"]`,
		"{\"op\":\"read\",\"path\":\"a\xff\"}",
	} {
		if _, err := ParseRequest([]byte(line)); err == nil {
			t.Errorf("%s must be refused", line)
		}
	}
	if r, err := ParseRequest([]byte(`{"op":"read","path":"public_html/index.php"}`)); err != nil || r.Path != "public_html/index.php" {
		t.Fatal(r, err)
	}
}

func TestReadLineIsBounded(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", 100)+"\nrest"), 16)
	if _, err := ReadLine(r, 50); err == nil {
		t.Fatal("a line over the bound must be refused")
	}
	r = bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", 40)+"\nrest"), 16)
	line, err := ReadLine(r, 50)
	if err != nil || len(line) != 40 {
		t.Fatal(len(line), err)
	}
	if rest, _ := r.ReadString(0); rest != "rest" {
		t.Fatalf("the bytes after the line must stay: %q", rest)
	}
	if _, err := ReadLine(bufio.NewReader(strings.NewReader("no newline")), 50); err == nil {
		t.Fatal("a line without its newline must be refused")
	}
}

func TestParseAnswerChecksTheHelpersWords(t *testing.T) {
	const when = "2026-11-24T10:00:00.5Z"
	list := Request{Op: OpList}
	read := Request{Op: OpRead, Path: "public_html/index.php"}
	write := Request{Op: OpWrite, Path: "a.txt", Size: 5}
	rename := Request{Op: OpRename, Path: "a", To: "b/c"}
	mode := Request{Op: OpMode, Path: "a", Mode: "0600"}
	good := []struct {
		r    Request
		line string
	}{
		{list, `{}`},
		{list, `{"entries":[{"name":"a","type":"file","size":3,"mode":"0644","modified":"` + when + `","version":"0123456789abcdef"},{"name":"l","type":"link","size":0,"mode":"0777","modified":"` + when + `"}],"skipped":2,"truncated":true}`},
		{read, `{"file":{"name":"index.php","type":"file","size":10,"mode":"0644","modified":"` + when + `","version":"0123456789abcdef"}}`},
		{write, `{"file":{"name":"a.txt","type":"file","size":5,"mode":"0644","modified":"` + when + `","version":"0123456789abcdef"}}`},
		{rename, `{"file":{"name":"c","type":"folder","size":0,"mode":"0755","modified":"` + when + `"}}`},
		{mode, `{"file":{"name":"a","type":"file","size":1,"mode":"0600","modified":"` + when + `","version":"0123456789abcdef"}}`},
		{read, `{"error":"is_link"}`},
	}
	for _, g := range good {
		if _, err := ParseAnswer(g.r, []byte(g.line)); err != nil {
			t.Errorf("%s: %s must be accepted", g.r.Op, g.line)
		}
	}
	bad := []struct {
		r    Request
		line string
	}{
		{list, `{"entries":[{"name":"../etc","type":"file","size":3,"mode":"0644","modified":"` + when + `","version":"0123456789abcdef"}]}`},
		{list, `{"entries":[{"name":"a","type":"file","size":3,"mode":"0644","modified":"` + when + `","version":"0123456789abcdef"},{"name":"a","type":"file","size":3,"mode":"0644","modified":"` + when + `","version":"0123456789abcdef"}]}`},
		{list, `{"entries":[{"name":"a","type":"device","size":0,"mode":"0644","modified":"` + when + `"}]}`},
		{list, `{"entries":[{"name":"a","type":"folder","size":9,"mode":"0644","modified":"` + when + `"}]}`},
		{list, `{"entries":[{"name":"a","type":"folder","size":0,"mode":"0755","modified":"` + when + `","version":"0123456789abcdef"}]}`},
		{list, `{"entries":[{"name":"a","type":"file","size":1,"mode":"0644","modified":"` + when + `"}]}`},
		{list, `{"entries":[{"name":"a","type":"file","size":-1,"mode":"0644","modified":"` + when + `","version":"0123456789abcdef"}]}`},
		{list, `{"entries":[{"name":"a","type":"file","size":1,"mode":"644","modified":"` + when + `","version":"0123456789abcdef"}]}`},
		{list, `{"file":{"name":"a","type":"file","size":1,"mode":"0644","modified":"` + when + `","version":"0123456789abcdef"}}`},
		{read, `{"file":{"name":"other.php","type":"file","size":10,"mode":"0644","modified":"` + when + `","version":"0123456789abcdef"}}`},
		{read, `{"file":{"name":"index.php","type":"file","size":1048577,"mode":"0644","modified":"` + when + `","version":"0123456789abcdef"}}`},
		{read, `{"file":{"name":"index.php","type":"link","size":0,"mode":"0777","modified":"` + when + `"}}`},
		{read, `{}`},
		{write, `{"file":{"name":"a.txt","type":"file","size":6,"mode":"0644","modified":"` + when + `","version":"0123456789abcdef"}}`},
		{rename, `{"file":{"name":"a","type":"folder","size":0,"mode":"0755","modified":"` + when + `"}}`},
		{mode, `{"file":{"name":"a","type":"file","size":1,"mode":"0644","modified":"` + when + `","version":"0123456789abcdef"}}`},
		{read, `{"error":"a message the helper made up"}`},
		{read, `{"error":"failed"}}`},
		{list, `{}]`},
		{read, `{"error":"is_link","file":{"name":"index.php","type":"file","size":1,"mode":"0644","modified":"` + when + `","version":"0123456789abcdef"}}`},
		{read, `{"file":{"name":"index.php","type":"file","size":1,"mode":"0644","modified":"` + when + `","version":"0123456789abcdef"},"extra":1}`},
	}
	for _, b := range bad {
		if _, err := ParseAnswer(b.r, []byte(b.line)); err == nil {
			t.Errorf("%s: %s must be refused", b.r.Op, b.line)
		}
	}
}

func TestTextRefusesBinary(t *testing.T) {
	if !Text([]byte("<?php echo 'héllo';\n")) || Text([]byte("a\x00b")) || Text([]byte{0xff, 0xfe}) {
		t.Fatal("text check")
	}
}
