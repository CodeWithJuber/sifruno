package olsweb

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// confShape reads a rendered file the way OpenLiteSpeed's plainconf parser
// does and returns its structure: block depth and key of every directive,
// with values left out. It fails on anything Render never emits on purpose:
// include lines, continuation backslashes, a heredoc other than the rewrite
// rules, unbalanced braces, over-long lines, or structural and expanding
// characters ({ } $ # < quotes) anywhere outside the rules heredoc.
func confShape(data []byte) ([]string, error) {
	text := string(data)
	if !strings.HasSuffix(text, "\n") {
		return nil, errors.New("missing trailing newline")
	}
	var shape []string
	depth, marker := 0, ""
	for n, raw := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		if len(raw)+1 > maxLineBytes {
			return nil, fmt.Errorf("line %d too long", n+1)
		}
		if strings.ContainsAny(raw, "\x00\r") {
			return nil, fmt.Errorf("line %d has NUL or CR", n+1)
		}
		line := strings.Trim(raw, " \t")
		if marker != "" {
			if first, _, _ := strings.Cut(line, " "); strings.EqualFold(first, marker) {
				marker = ""
				shape = append(shape, fmt.Sprintf("%d heredoc-end", depth))
			} else {
				shape = append(shape, fmt.Sprintf("%d heredoc-line", depth))
			}
			continue
		}
		if line == "" || line[0] == '#' {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "include") {
			return nil, fmt.Errorf("line %d is an include", n+1)
		}
		if strings.HasSuffix(line, `\`) {
			return nil, fmt.Errorf("line %d continues", n+1)
		}
		key, value, _ := strings.Cut(line, " ")
		if i := strings.Index(line, "<<<"); i >= 0 {
			if key != "rules" || strings.TrimSpace(value) != "<<<END_rules" {
				return nil, fmt.Errorf("line %d starts an unexpected heredoc", n+1)
			}
			marker = "END_rules"
			shape = append(shape, fmt.Sprintf("%d %s heredoc", depth, key))
			continue
		}
		if line == "}" {
			depth--
			if depth < 0 {
				return nil, fmt.Errorf("line %d closes a block that is not open", n+1)
			}
			shape = append(shape, fmt.Sprintf("%d }", depth))
			continue
		}
		body := strings.TrimSuffix(line, "{")
		if strings.ContainsAny(body, "{}$#<\"'`\\") {
			return nil, fmt.Errorf("line %d has a structural character: %q", n+1, line)
		}
		if body != line {
			shape = append(shape, fmt.Sprintf("%d %s {", depth, key))
			depth++
			continue
		}
		shape = append(shape, fmt.Sprintf("%d %s", depth, key))
	}
	if depth != 0 || marker != "" {
		return nil, errors.New("unbalanced blocks or open heredoc at end of file")
	}
	return shape, nil
}

func TestRenderedGrammar(t *testing.T) {
	files, err := Render(baseServer())
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range files {
		if _, err := confShape(data); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
}

var fuzzListeners = []Listener{
	{Name: "http", Address: "*", Port: 80},
	{Name: "https", Address: "*", Port: 443, Secure: true, CertFile: TLSRoot + "/listener-fullchain.pem", KeyFile: TLSRoot + "/listener-privkey.pem"},
}

// FuzzSite feeds arbitrary strings and numbers through the validators. Any
// refusal must be a FieldError. Any accepted site must render exactly like a
// reference site with distinctive placeholder values once the placeholders
// are replaced by the input values, and both must have the same structure
// under OpenLiteSpeed's grammar: each input value sits only where the
// template put its placeholder, adds no line and opens or closes no block.
func FuzzSite(f *testing.F) {
	f.Add("blog", "blogowner", "blogowner", "example.com", "www.example.com", "/home/blogowner/public_html", "8.3", TLSRoot+"/blog/fullchain.pem", TLSRoot+"/blog/privkey.pem", 0, 0, 0, false, false, false)
	f.Add("a", "abc", "abc", "a.b", "", "/home/abc/x", "8.1", "", "", 1, 256, 0, false, true, true)
	f.Add("wpproof", "wpproof", "wpproof", "wpproof.proof.test", "", "/home/wpproof/public_html", "8.3", "", "", 4, 0, 0, false, true, false)
	f.Add("paused", "pauseduser", "pauseduser", "paused.example.org", "", "/home/pauseduser/public_html", "8.2", "", "", 0, 0, 0, true, false, false)
	f.Add("blog", "blogowner", "blogowner", "example.com\nlistener x {", "", "/home/blogowner/public_html", "8.3", "", "", 0, 0, 0, false, false, false)
	f.Add("blog", "blogowner", "blogowner", "example.com", "", "/home/blogowner/public_html}", "8.3", "", "", 0, 0, 0, false, false, false)
	f.Add("blog", "root", "root", "example.com", "", "/home/root/x", "8.3", "", "", 0, 0, 0, false, false, false)
	f.Add("blog", "blogowner", "blogowner", "example.com", "", "/home/blogowner/a<<<END", "8.3", "/proc/self/root/etc/shadow", "/etc/shadow", 0, 0, 0, false, false, false)
	f.Fuzz(func(t *testing.T, name, user, group, d0, d1, docRoot, php, cert, key string, children, memory, procs int, suspended, namespace, cgroups bool) {
		in := Site{
			Name: name, Username: user, Group: group, Domains: []string{d0}, DocRoot: docRoot, PHPVersion: php,
			Suspended: suspended, Limits: Limits{PHPChildren: children, MemoryMiB: memory, Processes: procs},
			Isolation: Isolation{Namespace: namespace, CGroups: cgroups}, TLS: TLS{CertFile: cert, KeyFile: key},
		}
		if d1 != "" {
			in.Domains = append(in.Domains, d1)
		}
		err := Validate(Server{Listeners: fuzzListeners, Sites: []Site{in}})
		if err != nil {
			var fe *FieldError
			if !errors.As(err, &fe) || fe.Field == "" || !errors.Is(err, ErrInvalid) {
				t.Fatalf("refusal is not a named FieldError: %v", err)
			}
			return
		}
		got, err := Render(Server{Listeners: fuzzListeners, Sites: []Site{in}})
		if err != nil {
			t.Fatalf("validated site failed to render: %v", err)
		}

		// The reference keeps every non-string choice of the input. Group is
		// not a separate placeholder because it must equal the username.
		ref := in
		ref.Name, ref.Username, ref.Group = "qqname", "zzuser", "zzuser"
		ref.DocRoot = "/home/zzuser/qqdocroot"
		ref.Domains = nil
		pairs := []string{}
		if in.TLS.CertFile != "" {
			ref.TLS = TLS{CertFile: TLSRoot + "/qqname/qqcert.pem", KeyFile: TLSRoot + "/qqname/qqkey.pem"}
			pairs = append(pairs, ref.TLS.CertFile, in.TLS.CertFile, ref.TLS.KeyFile, in.TLS.KeyFile)
		}
		pairs = append(pairs, ref.DocRoot, in.DocRoot)
		for i, d := range in.Domains {
			ref.Domains = append(ref.Domains, fmt.Sprintf("qqd%d.qqzone.test", i))
			pairs = append(pairs, ref.Domains[i], d)
		}
		// Longer placeholders first: certificate paths and the docroot
		// contain the name and username placeholders.
		pairs = append(pairs, "qqname", in.Name, "zzuser", in.Username)
		want, err := Render(Server{Listeners: fuzzListeners, Sites: []Site{ref}})
		if err != nil {
			t.Fatalf("reference site failed to render: %v", err)
		}
		r := strings.NewReplacer(pairs...)
		if len(got) != len(want) {
			t.Fatalf("%d files, reference has %d", len(got), len(want))
		}
		for refPath, refData := range want {
			path := r.Replace(refPath)
			data, ok := got[path]
			if !ok {
				t.Fatalf("missing %s", path)
			}
			if string(data) != r.Replace(string(refData)) {
				t.Fatalf("%s: input values landed outside their template positions\n%s", path, data)
			}
			gotShape, err := confShape(data)
			if err != nil {
				t.Fatalf("%s: %v\n%s", path, err, data)
			}
			refShape, err := confShape(refData)
			if err != nil {
				t.Fatalf("reference %s: %v", refPath, err)
			}
			if strings.Join(gotShape, "\n") != strings.Join(refShape, "\n") {
				t.Fatalf("%s: structure differs from the reference\n%s", path, data)
			}
		}
	})
}
