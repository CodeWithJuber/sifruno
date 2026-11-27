// Package sitesource reads a website from a Linux server that is not
// cPanel (docs/migration-design.md, adapter "Another Linux server"): the
// web server's own virtual host files, Apache's or nginx's, and the
// site's wp-config.php; and it converts nginx's rules into what Sifruno's
// OpenLiteSpeed config holds. It runs nothing and reads no file itself:
// the broker reads the files over the migration's SSH and hands the bytes
// here. Every input is untrusted and bounded.
package sitesource

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// ErrNginx wraps every reason an nginx file cannot be read.
var ErrNginx = errors.New("the nginx configuration cannot be read")

// Bounds on one nginx file.
const (
	MaxConfigBytes = 1 << 20
	maxDepth       = 16
	maxDirectives  = 20000
	maxArgs        = 64
	maxToken       = 8192
)

// ParseError names the file and line an nginx file stops being readable at.
type ParseError struct {
	File   string
	Line   int
	Reason string
}

func (e *ParseError) Error() string { return fmt.Sprintf("%s line %d: %s", e.File, e.Line, e.Reason) }
func (e *ParseError) Unwrap() error { return ErrNginx }

// Directive is one nginx directive: its name, its arguments with quotes
// taken off, the line it starts on, and its block when it has one.
type Directive struct {
	Name     string
	Args     []string
	Line     int
	HasBlock bool
	Block    []*Directive
}

// NginxFile is one parsed file. Includes are not followed.
type NginxFile struct {
	Name       string
	Directives []*Directive
}

// Server is one server block: where it is, the names and root it gives,
// and its directives.
type Server struct {
	File  string
	Line  int
	Names []string
	Root  string
	Body  []*Directive
}

// ParseNginx reads one nginx configuration file the way nginx's own
// parser splits it: words and quoted strings, ";" ending a directive, "{"
// and "}" a block, "#" a comment to the end of the line. It refuses a file
// over 1 MiB, one that is not UTF-8 text or holds a NUL, a block left open
// or closed twice, a directive with no ";", and nesting deeper than 16.
func ParseNginx(name string, data []byte) (*NginxFile, error) {
	if len(data) > MaxConfigBytes {
		return nil, &ParseError{File: name, Line: 0, Reason: "the file is larger than 1 MiB"}
	}
	if !utf8.Valid(data) || strings.ContainsRune(string(data), 0) {
		return nil, &ParseError{File: name, Line: 1, Reason: "the file is not plain text"}
	}
	p := &parser{file: name, data: string(data), line: 1}
	dirs, err := p.block(0)
	if err != nil {
		return nil, err
	}
	return &NginxFile{Name: name, Directives: dirs}, nil
}

type parser struct {
	file  string
	data  string
	pos   int
	line  int
	count int
}

type token struct {
	text   string
	quoted bool
	line   int
}

func (p *parser) fail(line int, reason string) error {
	return &ParseError{File: p.file, Line: line, Reason: reason}
}

// next returns the next token, or ok false at the end of the file.
func (p *parser) next() (token, bool, error) {
	for p.pos < len(p.data) {
		c := p.data[p.pos]
		switch {
		case c == '\n':
			p.line++
			p.pos++
		case c == ' ' || c == '\t' || c == '\r':
			p.pos++
		case c == '#':
			for p.pos < len(p.data) && p.data[p.pos] != '\n' {
				p.pos++
			}
		case c == ';' || c == '{' || c == '}':
			p.pos++
			return token{text: string(c), line: p.line}, true, nil
		case c == '"' || c == '\'':
			return p.quoted(c)
		default:
			return p.word()
		}
	}
	return token{}, false, nil
}

func (p *parser) quoted(q byte) (token, bool, error) {
	start := p.line
	p.pos++
	var b strings.Builder
	for p.pos < len(p.data) {
		c := p.data[p.pos]
		switch {
		case c == q:
			p.pos++
			return token{text: b.String(), quoted: true, line: start}, true, nil
		case c == '\\' && p.pos+1 < len(p.data):
			// nginx keeps a backslash before anything but a quote or a
			// backslash, and turns \t, \r and \n into those characters.
			n := p.data[p.pos+1]
			switch n {
			case '"', '\'', '\\':
				b.WriteByte(n)
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case 'n':
				b.WriteByte('\n')
			default:
				b.WriteByte('\\')
				b.WriteByte(n)
			}
			p.pos += 2
		default:
			if c == '\n' {
				p.line++
			}
			b.WriteByte(c)
			p.pos++
		}
		if b.Len() > maxToken {
			return token{}, false, p.fail(start, "a quoted value is longer than 8192 bytes")
		}
	}
	return token{}, false, p.fail(start, "a quoted value is not closed")
}

func (p *parser) word() (token, bool, error) {
	start, from := p.line, p.pos
	for p.pos < len(p.data) {
		c := p.data[p.pos]
		if c == '$' && p.pos+1 < len(p.data) && p.data[p.pos+1] == '{' {
			// ${name}: a variable, whose braces are not a block.
			end := strings.IndexByte(p.data[p.pos:], '}')
			if end < 0 {
				return token{}, false, p.fail(start, "a ${ variable is not closed")
			}
			p.pos += end + 1
			continue
		}
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ';' || c == '{' || c == '}' || c == '"' || c == '\'' {
			break
		}
		p.pos++
	}
	if p.pos-from > maxToken {
		return token{}, false, p.fail(start, "a word is longer than 8192 bytes")
	}
	return token{text: p.data[from:p.pos], line: start}, true, nil
}

// block reads directives up to the end of the file (depth 0) or the "}"
// that closes the block.
func (p *parser) block(depth int) ([]*Directive, error) {
	var out []*Directive
	for {
		t, ok, err := p.next()
		if err != nil {
			return nil, err
		}
		if !ok {
			if depth > 0 {
				return nil, p.fail(p.line, "a block is not closed with }")
			}
			return out, nil
		}
		if !t.quoted && t.text == "}" {
			if depth == 0 {
				return nil, p.fail(t.line, "a } closes no block")
			}
			return out, nil
		}
		if !t.quoted && (t.text == ";" || t.text == "{") {
			return nil, p.fail(t.line, "a "+t.text+" has no directive name before it")
		}
		if p.count++; p.count > maxDirectives {
			return nil, p.fail(t.line, "the file has more than 20000 directives")
		}
		d := &Directive{Name: t.text, Line: t.line}
		for {
			a, ok, err := p.next()
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, p.fail(p.line, "the directive "+d.Name+" does not end with ;")
			}
			if !a.quoted && a.text == ";" {
				break
			}
			if !a.quoted && a.text == "}" {
				return nil, p.fail(a.line, "the directive "+d.Name+" does not end with ;")
			}
			if !a.quoted && a.text == "{" {
				if depth+1 >= maxDepth {
					return nil, p.fail(a.line, "blocks are nested more than 16 deep")
				}
				d.HasBlock = true
				if d.Block, err = p.block(depth + 1); err != nil {
					return nil, err
				}
				break
			}
			if len(d.Args) == maxArgs {
				return nil, p.fail(a.line, "the directive "+d.Name+" has more than 64 values")
			}
			d.Args = append(d.Args, a.text)
		}
		out = append(out, d)
	}
}

// Servers lists the file's server blocks, at the top or inside http.
func (f *NginxFile) Servers() []Server {
	var out []Server
	var walk func([]*Directive)
	walk = func(list []*Directive) {
		for _, d := range list {
			switch {
			case d.Name == "http" && d.HasBlock:
				walk(d.Block)
			case d.Name == "server" && d.HasBlock:
				s := Server{File: f.Name, Line: d.Line, Body: d.Block}
				for _, c := range d.Block {
					switch c.Name {
					case "server_name":
						for _, n := range c.Args {
							s.Names = append(s.Names, strings.ToLower(n))
						}
					case "root":
						if len(c.Args) == 1 {
							s.Root = c.Args[0]
						}
					}
				}
				out = append(out, s)
			}
		}
	}
	walk(f.Directives)
	return out
}
