package htaccess

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestParseTokens(t *testing.T) {
	f, err := Parse([]byte("\xef\xbb\xbf  header   set X-Test \"a \\\"quoted\\\" value\" 'single quoted'\r\n" +
		"# comment ending in a backslash \\\n" +
		"Deny from all\n" +
		"RewriteRule ^a$ \\\n    /b \\\n [L]\n" +
		"<FilesMatch \"\\.(env|log)$\">\n" +
		"  <ifmodule mod_authz_core.c>\n" +
		"    Require all denied\n" +
		"  </IFMODULE>\n" +
		"</FilesMatch>\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Problems) != 0 {
		t.Fatalf("unexpected problems %v", f.Problems)
	}
	if len(f.Nodes) != 5 {
		t.Fatalf("got %d top-level nodes", len(f.Nodes))
	}
	h := f.Nodes[0]
	if h.Kind != KindDirective || h.Name != "header" || h.Line != 1 || !reflect.DeepEqual(h.Args, []string{"set", "X-Test", `a "quoted" value`, "single quoted"}) {
		t.Fatalf("header node %+v", h)
	}
	if c := f.Nodes[1]; c.Kind != KindComment || c.Line != 2 {
		t.Fatalf("comment node %+v", c)
	}
	// A comment is never continued, so the deny line stays visible.
	if d := f.Nodes[2]; d.Name != "Deny" || d.Line != 3 || d.Continued {
		t.Fatalf("deny node %+v", d)
	}
	if r := f.Nodes[3]; r.Name != "RewriteRule" || r.Line != 4 || !r.Continued || !reflect.DeepEqual(r.Args, []string{"^a$", "/b", "[L]"}) {
		t.Fatalf("continued node %+v", r)
	}
	fm := f.Nodes[4]
	if fm.Kind != KindSection || fm.Name != "FilesMatch" || fm.Line != 7 || !reflect.DeepEqual(fm.Args, []string{`\.(env|log)$`}) || len(fm.Children) != 1 {
		t.Fatalf("section node %+v", fm)
	}
	inner := fm.Children[0]
	if inner.Name != "ifmodule" || len(inner.Children) != 1 || inner.Children[0].Name != "Require" || inner.Children[0].Line != 9 {
		t.Fatalf("nested section %+v", inner)
	}
	var kinds []LineKind
	for _, l := range f.Lines {
		kinds = append(kinds, l.Kind)
	}
	want := []LineKind{LineDirective, LineComment, LineDirective, LineDirective, LineOpen, LineOpen, LineDirective, LineClose, LineClose}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("line kinds %v, want %v", kinds, want)
	}
}

func TestParseProblems(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
		want []Problem
	}{
		{"unmatched close", "RewriteEngine On\n</Files>\n", []Problem{{2, "closing tag </Files> has no open section"}}},
		{"unclosed section", "<Files a>\nDeny from all\n", []Problem{{1, "section <Files> is not closed"}}},
		{"crossed sections", "<Files a>\n<Limit GET>\n</Files>\n", []Problem{{2, "section <Limit> is not closed"}}},
		{"missing bracket", "<Files a\n</Files>\n", []Problem{{1, "section tag is missing its >"}}},
		{"empty tag", "<>\n", []Problem{{1, "section tag has no name"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := Parse([]byte(tc.data))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(f.Problems, tc.want) {
				t.Fatalf("problems %v, want %v", f.Problems, tc.want)
			}
		})
	}
}

func TestParseBoundsInput(t *testing.T) {
	if _, err := Parse(make([]byte, MaxFileBytes+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversize input: %v", err)
	}
	deep := strings.Repeat("<IfModule a>\n", maxNesting+10) + "RewriteEngine On\n" + strings.Repeat("</IfModule>\n", maxNesting+10)
	f, err := Parse([]byte(deep))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Problems) == 0 {
		t.Fatal("deep nesting was not reported")
	}
	if r := Classify(f, "x", "/"); r.Verdict != VerdictCompat {
		t.Fatalf("deep nesting verdict %s", r.Verdict)
	}
	bad, err := Parse([]byte("Header set X-\xff\xfe \"\xc3\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range bad.Nodes[0].Args {
		if !utf8.ValidString(a) {
			t.Fatalf("invalid UTF-8 kept in %q", a)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		wordpressBlock, cachePluginBlocks, liteSpeedCacheBlock, passwordProtected, cpanelHandler, wordfenceBlock,
		"<Files \"a\\\"b\">\nRequire all denied\n</Files>\n",
		"RewriteCond a\n</IfModule>\n",
		"\\\n\\\n<\n</\n#\\\n\"'\n",
		"<IfModule mod_headers.c>\n<IfModule x>\nRewriteRule a b\n</IfModule>\n</IfModule>\nRewriteCond x y\n",
		"Redirect 403\nRedirectMatch\nOptions\nphp_flag\nRequire not\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		file, err := Parse(data)
		if err != nil {
			if len(data) <= MaxFileBytes {
				t.Fatalf("unexpected error %v", err)
			}
			return
		}
		r := Classify(file, "fuzz/.htaccess", "/fuzz/")
		if r.Verdict != VerdictNative && r.Verdict != VerdictConvertible && r.Verdict != VerdictCompat {
			t.Fatalf("invalid verdict %q", r.Verdict)
		}
		for _, g := range r.Findings {
			if !utf8.ValidString(g.Directive) || g.Line < 1 || g.Reason == "" {
				t.Fatalf("bad finding %+v", g)
			}
			if g.Category == CategoryAccessControl && (g.Access == nil || r.Verdict != VerdictCompat) {
				t.Fatalf("access finding without compat verdict: %+v", g)
			}
			if g.Category == CategoryUnknown && r.Verdict != VerdictCompat {
				t.Fatalf("unknown finding without compat verdict: %+v", g)
			}
		}
		for _, rule := range r.AccessRules {
			if rule.ExpectStatus != 0 && rule.ExpectStatus != 401 && rule.ExpectStatus != 403 {
				t.Fatalf("unexpected status %d", rule.ExpectStatus)
			}
		}
	})
}
