package htaccess

import (
	"errors"
	"strings"
)

// MaxFileBytes bounds one .htaccess file. Real files are a few kilobytes; a
// larger one is generated junk or an attempt to exhaust the scanner.
const MaxFileBytes = 1 << 20

// maxNesting bounds section depth so a hostile file cannot drive the
// classifier's recursion arbitrarily deep. Apache itself has no such limit,
// so deeper files are reported as malformed and fail closed.
const maxNesting = 64

var ErrTooLarge = errors.New("htaccess file exceeds 1 MiB")

type NodeKind uint8

const (
	KindDirective NodeKind = iota
	KindSection
	KindComment
)

// Node is one directive, container section or comment. Name keeps the
// spelling from the file; Apache matches names case-insensitively.
type Node struct {
	Kind NodeKind
	Name string
	Args []string
	// Line is the first physical line (1-based) of the logical line.
	Line int
	// Continued reports a trailing-backslash continuation. Apache joins the
	// lines; OLS reads physical lines, so a continued rewrite rule differs.
	Continued bool
	Children  []*Node
	// Text holds a comment without its leading '#'.
	Text string
}

type LineKind uint8

const (
	LineDirective LineKind = iota
	LineOpen
	LineClose
	LineComment
)

// Line is one logical line in file order. The classifier replays these to
// mimic OLS's line-oriented loader, which never builds a tree.
type Line struct {
	Num  int
	Kind LineKind
	// Node is nil for LineClose.
	Node *Node
	// Name is the section name of a LineClose.
	Name string
}

// Problem is a structural defect. Apache answers 500 for a directory whose
// .htaccess is malformed, while OLS keeps serving it, so any problem fails
// closed.
type Problem struct {
	Line   int    `json:"line"`
	Reason string `json:"reason"`
}

type File struct {
	Nodes    []*Node
	Lines    []Line
	Problems []Problem
}

const asciiSpace = " \t\r\n\f\v"

// Parse reads .htaccess bytes the way Apache's ap_cfg_getline and
// ap_getword_conf do: a trailing backslash continues a line, '#' starts a
// whole-line comment, single or double quotes group an argument, and <Name>
// ... </Name> nest. It is tolerant: structural defects become Problems rather
// than errors, and invalid UTF-8 is replaced so results are safe to print.
func Parse(data []byte) (*File, error) {
	if len(data) > MaxFileBytes {
		return nil, ErrTooLarge
	}
	text := strings.TrimPrefix(string(data), "\xef\xbb\xbf")
	raw := strings.Split(text, "\n")
	f := &File{}
	top := &Node{Kind: KindSection}
	stack := []*Node{top}
	for i := 0; i < len(raw); i++ {
		num := i + 1
		line := strings.TrimRight(raw[i], "\r")
		continued := false
		// Comments are not continued: joining the next line into a comment
		// could hide a directive, and hiding is the unsafe direction.
		if strings.HasSuffix(line, "\\") && i+1 < len(raw) && !strings.HasPrefix(strings.TrimLeft(line, asciiSpace), "#") {
			continued = true
			var b strings.Builder
			b.WriteString(line[:len(line)-1])
			for i+1 < len(raw) {
				i++
				next := strings.TrimRight(raw[i], "\r")
				if strings.HasSuffix(next, "\\") && i+1 < len(raw) {
					b.WriteString(next[:len(next)-1])
					continue
				}
				b.WriteString(next)
				break
			}
			line = b.String()
		}
		line = strings.ToValidUTF8(strings.Trim(line, asciiSpace), "�")
		if line == "" {
			continue
		}
		parent := stack[len(stack)-1]
		switch {
		case line[0] == '#':
			n := &Node{Kind: KindComment, Line: num, Text: line[1:]}
			parent.Children = append(parent.Children, n)
			f.Lines = append(f.Lines, Line{Num: num, Kind: LineComment, Node: n})
		case strings.HasPrefix(line, "</"):
			body, closed := strings.CutSuffix(line[2:], ">")
			if !closed {
				f.problem(num, "closing tag is missing its >")
			}
			name, _ := splitName(body)
			f.Lines = append(f.Lines, Line{Num: num, Kind: LineClose, Name: name})
			match := -1
			for j := len(stack) - 1; j >= 1; j-- {
				if strings.EqualFold(stack[j].Name, name) {
					match = j
					break
				}
			}
			if match < 0 {
				f.problem(num, "closing tag </"+name+"> has no open section")
				continue
			}
			for j := len(stack) - 1; j > match; j-- {
				f.problem(stack[j].Line, "section <"+stack[j].Name+"> is not closed")
			}
			stack = stack[:match]
		case line[0] == '<':
			body, closed := strings.CutSuffix(line[1:], ">")
			if !closed {
				f.problem(num, "section tag is missing its >")
			}
			name, rest := splitName(body)
			if name == "" {
				f.problem(num, "section tag has no name")
				continue
			}
			n := &Node{Kind: KindSection, Name: name, Args: splitArgs(rest), Line: num, Continued: continued}
			parent.Children = append(parent.Children, n)
			f.Lines = append(f.Lines, Line{Num: num, Kind: LineOpen, Node: n})
			if len(stack) > maxNesting {
				f.problem(num, "sections are nested too deeply")
				continue
			}
			stack = append(stack, n)
		default:
			name, rest := splitName(line)
			n := &Node{Kind: KindDirective, Name: name, Args: splitArgs(rest), Line: num, Continued: continued}
			parent.Children = append(parent.Children, n)
			f.Lines = append(f.Lines, Line{Num: num, Kind: LineDirective, Node: n})
		}
	}
	for j := len(stack) - 1; j >= 1; j-- {
		f.problem(stack[j].Line, "section <"+stack[j].Name+"> is not closed")
	}
	f.Nodes = top.Children
	return f, nil
}

func (f *File) problem(line int, reason string) {
	f.Problems = append(f.Problems, Problem{Line: line, Reason: reason})
}

func splitName(s string) (string, string) {
	s = strings.TrimLeft(s, asciiSpace)
	end := strings.IndexAny(s, asciiSpace)
	if end < 0 {
		return s, ""
	}
	return s[:end], s[end:]
}

// splitArgs follows ap_getword_conf: a quoted word ends at the matching
// quote, and a backslash only escapes that quote character.
func splitArgs(s string) []string {
	var args []string
	for {
		s = strings.TrimLeft(s, asciiSpace)
		if s == "" {
			return args
		}
		quote := s[0]
		if quote != '"' && quote != '\'' {
			end := strings.IndexAny(s, asciiSpace)
			if end < 0 {
				end = len(s)
			}
			args = append(args, s[:end])
			s = s[end:]
			continue
		}
		var b strings.Builder
		i := 1
		for ; i < len(s); i++ {
			if s[i] == '\\' && i+1 < len(s) && s[i+1] == quote {
				b.WriteByte(quote)
				i++
				continue
			}
			if s[i] == quote {
				break
			}
			b.WriteByte(s[i])
		}
		args = append(args, b.String())
		if i < len(s) {
			i++
		}
		s = s[i:]
	}
}
