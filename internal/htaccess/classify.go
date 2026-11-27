package htaccess

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type Category string

const (
	CategoryRewrite        Category = "rewrite"
	CategoryAccessControl  Category = "access_control"
	CategoryPHPSettings    Category = "php_settings"
	CategoryHeaders        Category = "headers"
	CategoryCaching        Category = "caching"
	CategoryMIMEHandlers   Category = "mime_handlers"
	CategoryRedirectAlias  Category = "redirect_alias"
	CategoryErrorDocuments Category = "error_documents"
	CategoryCompression    Category = "compression"
	CategoryEnvironment    Category = "environment"
	CategoryVendor         Category = "vendor"
	CategoryOther          Category = "other"
	// CategoryStructure marks container tags such as <IfModule>. They never
	// decide a verdict on their own; their contents do.
	CategoryStructure Category = "structure"
	CategoryUnknown   Category = "unknown"
)

// Categories lists every category in report order.
var Categories = []Category{
	CategoryRewrite, CategoryAccessControl, CategoryPHPSettings, CategoryHeaders,
	CategoryCaching, CategoryMIMEHandlers, CategoryRedirectAlias, CategoryErrorDocuments,
	CategoryCompression, CategoryEnvironment, CategoryVendor, CategoryOther,
	CategoryStructure, CategoryUnknown,
}

type Verdict string

const (
	// VerdictNative: OLS acts on every directive in the file, or Sifruno
	// covers the ones it ignores (handling.go: harmless to ignore, handled
	// by Sifruno, or a warning shown before cutover).
	VerdictNative Verdict = "native"
	// VerdictConvertible: OLS ignores some directives that are not access
	// control, not unknown and in no handling class. A converter would have
	// to move them into vhost config; none exists, so the file is not
	// Native.
	VerdictConvertible Verdict = "convertible"
	// VerdictCompat: keep the site on Apache with PHP-FPM.
	VerdictCompat Verdict = "compat"
)

var Verdicts = []Verdict{VerdictNative, VerdictConvertible, VerdictCompat}

func (v Verdict) rank() int {
	switch v {
	case VerdictConvertible:
		return 1
	case VerdictCompat:
		return 2
	}
	return 0
}

// Causes explain a compat verdict.
const (
	CauseAccessControl      = "access_control"
	CauseUnknown            = "unknown"
	CauseMalformed          = "malformed"
	CauseUnreadableFile     = "unreadable_file"
	CauseOversizeFile       = "oversize_file"
	CauseIrregularFile      = "irregular_file"
	CauseSymlinkNotFollowed = "symlink_not_followed"
	CauseScanTruncated      = "scan_truncated"
	CauseUnreadableDir      = "unreadable_dir"
)

// Causes lists every compat cause in report order.
var Causes = []string{
	CauseAccessControl, CauseUnknown, CauseMalformed, CauseUnreadableFile,
	CauseOversizeFile, CauseIrregularFile, CauseSymlinkNotFollowed,
	CauseScanTruncated, CauseUnreadableDir,
}

type AccessKind string

const (
	AccessPassword  AccessKind = "password"
	AccessDenyAllow AccessKind = "deny_allow"
	AccessListing   AccessKind = "listing"
	AccessExec      AccessKind = "exec"
	AccessTLS       AccessKind = "tls"
)

// Access is what a migration verify step needs to probe an access rule.
type Access struct {
	// Path is the URL path prefix the rule covers, relative to the site root.
	Path string     `json:"path"`
	Kind AccessKind `json:"kind"`
	// Files narrows the rule to file names (<Files>/<FilesMatch>).
	Files      string `json:"files,omitempty"`
	FilesRegex bool   `json:"files_regex,omitempty"`
	// Methods narrows the rule to HTTP methods (<Limit>/<LimitExcept>).
	Methods string `json:"methods,omitempty"`
	// Conditional is set inside <If>, <Require*> and similar containers whose
	// outcome depends on request details.
	Conditional bool `json:"conditional,omitempty"`
	// URLRegex and Status describe a RedirectMatch/Redirect with a 4xx/5xx
	// status.
	URLRegex string `json:"url_regex,omitempty"`
	Status   int    `json:"status,omitempty"`
}

type Finding struct {
	File      string   `json:"file"`
	Line      int      `json:"line"`
	Directive string   `json:"directive"`
	Category  Category `json:"category"`
	Honoured  bool     `json:"ols_honoured"`
	Reason    string   `json:"reason"`
	Access    *Access  `json:"access,omitempty"`
	// Handling is what Sifruno does about a directive OLS does not act on
	// (handling.go); empty when OLS acts on it or no class covers it.
	Handling Handling `json:"handling,omitempty"`
	// Label is the directive with the first arguments safe to show
	// (handling.go label), for messages that name the line.
	Label string `json:"label"`
	// PHP is the PHP package a handler line names (PHPHandler).
	PHP string `json:"php_handler,omitempty"`
}

// AccessRule groups access findings that a verify step would test together.
// ExpectStatus is 401 or 403 only for plain whole-directory rules whose
// outcome does not depend on the client; 0 means the verify step must work it
// out.
type AccessRule struct {
	Access
	Line         int `json:"line"`
	ExpectStatus int `json:"expect_status"`
}

type FileResult struct {
	// Path is relative to the scanned root.
	Path string `json:"path"`
	// URLPath is the URL path of the directory holding the file.
	URLPath     string       `json:"url_path"`
	Verdict     Verdict      `json:"verdict"`
	Causes      []string     `json:"causes,omitempty"`
	Error       string       `json:"error,omitempty"`
	Problems    []Problem    `json:"problems,omitempty"`
	Findings    []Finding    `json:"findings"`
	AccessRules []AccessRule `json:"access_rules,omitempty"`
	// Conversion is the converter's answer for a file that is compat for
	// access control alone (convert.go); nil for every other file.
	Conversion *Conversion `json:"conversion,omitempty"`
	// RewriteToPath is the line of the first rewrite rule or RewriteBase
	// whose result OpenLiteSpeed could take as a file path (convert.go,
	// rewriteToPath); 0 when there is none.
	RewriteToPath int `json:"rewrite_to_path_line,omitempty"`
}

// ClassifyFile parses and classifies one .htaccess. name is recorded in each
// finding; urlPath is the URL path of the directory holding the file, "/" at
// the site root.
func ClassifyFile(name, urlPath string, data []byte) FileResult {
	f, err := Parse(data)
	if err != nil {
		return unreadFile(name, urlPath, CauseOversizeFile, "larger than 1 MiB")
	}
	return Classify(f, name, urlPath)
}

func unreadFile(name, urlPath, cause, reason string) FileResult {
	return FileResult{Path: name, URLPath: urlPath, Verdict: VerdictCompat, Causes: []string{cause}, Error: reason, Findings: []Finding{}}
}

// Classify assigns every directive a category and the file a verdict.
func Classify(f *File, name, urlPath string) FileResult {
	c := &classifier{file: name, urlPath: urlPath, root: urlPath == "/", problems: append([]Problem(nil), f.Problems...)}
	c.envFeedsAccess = feedsAccess(f.Nodes)
	c.envRead = rewriteEnvReads(f.Lines)
	c.walk(f.Nodes, scope{})
	if stop := olsStopLine(f.Lines); stop > 0 {
		for i := range c.findings {
			if g := &c.findings[i]; g.Line >= stop && g.Honoured && g.Category != CategoryStructure {
				g.Honoured = false
				g.Reason = fmt.Sprintf("OLS stops reading this file at line %d, where a RewriteCond is not followed by a RewriteRule", stop)
			}
		}
	}
	r := FileResult{Path: name, URLPath: urlPath, Verdict: VerdictNative, Problems: c.problems, Findings: c.findings, AccessRules: c.rules()}
	if r.Findings == nil {
		r.Findings = []Finding{}
	}
	causes := map[string]bool{}
	if len(c.problems) > 0 {
		causes[CauseMalformed] = true
	}
	for _, g := range c.findings {
		switch {
		case g.Category == CategoryAccessControl:
			causes[CauseAccessControl] = true
		case g.Category == CategoryUnknown:
			causes[CauseUnknown] = true
		case g.Category != CategoryStructure && !g.Honoured && g.Handling == "":
			r.Verdict = VerdictConvertible
		}
	}
	if len(causes) > 0 {
		r.Verdict = VerdictCompat
		r.Causes = sortedCauses(causes)
	}
	if convertible(r) {
		skip := map[int]bool{}
		for _, g := range r.Findings {
			if g.Handling != "" {
				skip[g.Line] = true
			}
		}
		r.Conversion = convert(f, urlPath, skip)
	}
	r.RewriteToPath = rewriteToPath(f.Lines)
	return r
}

func sortedCauses(set map[string]bool) []string {
	var out []string
	for _, cause := range Causes {
		if set[cause] {
			out = append(out, cause)
		}
	}
	return out
}

type scope struct {
	files       string
	filesRegex  bool
	methods     string
	conditional bool
	// scoped marks a container OLS does not understand, so a rewrite line
	// inside it runs unconditionally on OLS.
	scoped bool
	// negated marks <IfModule !mod>: Apache skips it when the module is
	// loaded, OLS reads it anyway.
	negated bool
	// headers marks an <IfModule> line naming mod_headers, which OLS 1.8.4+
	// skips as a whole.
	headers bool
	vendor  bool
}

func (s scope) plain() bool { return s.files == "" && s.methods == "" && !s.conditional }

// facts records plain whole-directory access directives, from which the
// expected verify status is derived.
type facts struct {
	authType, requireUser, requireOther, requireDenied, denyAll, allowAny bool
}

type classifier struct {
	file           string
	urlPath        string
	root           bool
	findings       []Finding
	problems       []Problem
	marker         bool
	envFeedsAccess bool
	// envRead holds the environment variables rewrite lines read.
	envRead    map[string]bool
	satisfyAny bool
	plain      facts
}

func (c *classifier) walk(nodes []*Node, sc scope) {
	for _, n := range nodes {
		switch n.Kind {
		case KindComment:
			if begin, end := vendorMarker(n.Text); begin {
				c.marker = true
			} else if end {
				c.marker = false
			}
		case KindSection:
			c.section(n, sc)
		case KindDirective:
			c.note(n, sc)
			c.findings = append(c.findings, c.directive(n, sc))
		}
	}
}

// vendorMarker recognises comment-delimited blocks that tools generate:
// LiteSpeed Cache, cPanel handler/php.ini/directory-privacy sections and the
// Wordfence firewall loader.
func vendorMarker(text string) (begin, end bool) {
	t := strings.ToLower(text)
	switch {
	case strings.Contains(t, "end lscache"), strings.Contains(t, "end non_lscache"),
		strings.Contains(t, "php -- end cpanel-generated handler"),
		strings.Contains(t, "end cpanel-generated php ini directives"),
		strings.Contains(t, "end section managed by cpanel"),
		strings.Contains(t, "end wordfence waf"):
		return false, true
	case strings.Contains(t, "begin lscache"), strings.Contains(t, "begin non_lscache"),
		strings.Contains(t, "php -- begin cpanel-generated handler"),
		strings.Contains(t, "begin cpanel-generated php ini directives"),
		strings.Contains(t, "section managed by cpanel"),
		strings.Contains(t, "wordfence waf"):
		return true, false
	}
	return false, false
}

func (c *classifier) section(n *Node, sc scope) {
	name := strings.ToLower(n.Name)
	arg := ""
	if len(n.Args) > 0 {
		arg = n.Args[0]
	}
	f := Finding{File: c.file, Line: n.Line, Directive: "<" + n.Name + ">", Label: unknownPlaceholder, Category: CategoryStructure}
	if directiveName.MatchString(n.Name) {
		f.Label = "<" + n.Name + ">"
	}
	inner := sc
	switch name {
	case "ifmodule":
		f.Honoured = true
		f.Reason = "module wrapper; OLS reads through it without testing the module"
		if strings.HasPrefix(arg, "!") {
			inner.negated = true
			f.Reason = "negated module wrapper; Apache skips it when the module is loaded, OLS reads through it"
		}
		// OLS matches the substring on the raw line, case-sensitively.
		if strings.Contains(strings.Join(n.Args, " "), "mod_headers") {
			inner.headers = true
			f.Reason = "mod_headers wrapper; OLS 1.8.4 and later skip the whole block"
		}
		if strings.EqualFold(strings.TrimPrefix(arg, "!"), "litespeed") {
			inner.vendor = true
			f.Category = CategoryVendor
			f.Reason = "LiteSpeed-only block; Apache skips it, OLS applies the rewrite lines inside"
		}
	case "ifdefine", "ifversion", "ifdirective", "ifsection", "iffile":
		inner.scoped, inner.conditional = true, true
		f.Reason = "Apache condition that OLS does not evaluate; contents classified on their own"
	case "files", "filesmatch":
		inner.files, inner.filesRegex, inner.scoped = arg, name == "filesmatch", true
		if name == "files" && arg == "~" && len(n.Args) > 1 {
			inner.files, inner.filesRegex = n.Args[1], true
		}
		f.Reason = "file scope that OLS ignores; contents classified on their own"
		if kind, ok := c.accessInside(n.Children); ok {
			f.Category = CategoryAccessControl
			f.Reason = "file-scoped access rule that OLS does not enforce from .htaccess"
			f.Access = c.access(inner, kind)
		}
	case "limit", "limitexcept":
		inner.methods, inner.scoped = strings.TrimSpace(n.Name+" "+strings.Join(n.Args, " ")), true
		kind, ok := c.accessInside(n.Children)
		if !ok {
			kind = AccessDenyAllow
		}
		f.Category = CategoryAccessControl
		f.Reason = "method-scoped access rule that OLS does not enforce from .htaccess"
		f.Access = c.access(inner, kind)
	case "requireall", "requireany", "requirenone":
		inner.conditional, inner.scoped = true, true
		kind, ok := c.accessInside(n.Children)
		if !ok {
			kind = AccessDenyAllow
		}
		f.Category = CategoryAccessControl
		f.Reason = "authorization container that OLS does not enforce from .htaccess"
		f.Access = c.access(inner, kind)
	case "if", "elseif", "else":
		inner.conditional, inner.scoped = true, true
		f.Reason = "expression condition that OLS does not evaluate; contents classified on their own"
	case "directory", "directorymatch", "location", "locationmatch", "virtualhost", "proxy", "proxymatch":
		inner.conditional, inner.scoped = true, true
		f.Reason = "not permitted in .htaccess; Apache rejects the file"
		c.problems = append(c.problems, Problem{Line: n.Line, Reason: "<" + n.Name + "> is not permitted in .htaccess"})
	default:
		inner.conditional, inner.scoped = true, true
		f.Category = CategoryUnknown
		f.Reason = "unrecognised section; fail closed"
	}
	c.findings = append(c.findings, f)
	c.walk(n.Children, inner)
}

// accessInside reports whether a container holds an access-control
// directive, preferring password over other kinds.
func (c *classifier) accessInside(nodes []*Node) (AccessKind, bool) {
	var found AccessKind
	for _, n := range nodes {
		var kind AccessKind
		switch n.Kind {
		case KindDirective:
			if g := c.directive(n, scope{}); g.Access != nil {
				kind = g.Access.Kind
			}
		case KindSection:
			switch strings.ToLower(n.Name) {
			case "limit", "limitexcept", "requireall", "requireany", "requirenone":
				kind = AccessDenyAllow
			}
			if k, ok := c.accessInside(n.Children); ok {
				kind = k
			}
		}
		if kind == AccessPassword {
			return kind, true
		}
		if found == "" {
			found = kind
		}
	}
	return found, found != ""
}

func (c *classifier) access(sc scope, kind AccessKind) *Access {
	return &Access{Path: c.urlPath, Kind: kind, Files: sc.files, FilesRegex: sc.filesRegex, Methods: sc.methods, Conditional: sc.conditional}
}

// directive classifies one directive. It has no side effects so containers
// can probe their contents with it.
func (c *classifier) directive(n *Node, sc scope) Finding {
	name := strings.ToLower(n.Name)
	f := Finding{File: c.file, Line: n.Line, Directive: n.Name, Label: label(n)}
	e, ok := lookup(name)
	if !ok {
		f.Category = CategoryUnknown
		f.Reason = "unrecognised directive; fail closed"
		return f
	}
	f.Category, f.Honoured = e.category, e.honoured
	kind := e.access
	arg := func(i int) string {
		if i < len(n.Args) {
			return n.Args[i]
		}
		return ""
	}
	var redirect *Access
	switch name {
	case "rewriteengine", "rewritecond", "rewriterule", "cachekeymodify":
		f.Honoured, f.Reason = rewriteHonoured(n, sc)
	case "rewritebase":
		f.Honoured, f.Reason = rewriteHonoured(n, sc)
		if f.Honoured && dirPath(arg(0)) != c.urlPath {
			f.Honoured = false
			f.Reason = "RewriteBase differs from this directory's URL path; OLS result unverified"
		}
	case "rewritefile":
		f.Reason = "loads another rule file that this scan does not read"
	case "options":
		// The Options lines handle.go covers only turn listings and content
		// negotiation off, or follow links the vhost follows anyway
		// (optionsHandled): none of them opens anything when OLS ignores it.
		if optionsHandled(n.Args) {
			break
		}
		if kind = optionsAccess(n.Args); kind != "" {
			f.Category = CategoryAccessControl
		}
	case "php_value", "php_flag", "php_admin_value", "php_admin_flag":
		if strings.EqualFold(arg(0), "engine") && isOff(arg(1)) {
			f.Category, kind = CategoryAccessControl, AccessExec
		}
	case "sethandler":
		if v := strings.ToLower(arg(0)); v == "none" || v == "default-handler" {
			f.Category, kind = CategoryAccessControl, AccessExec
		}
	case "redirect", "redirectmatch":
		if status := redirectStatus(arg(0)); status >= 400 {
			f.Category, kind = CategoryAccessControl, AccessDenyAllow
			redirect = c.access(sc, kind)
			redirect.Status = status
			if name == "redirectmatch" {
				redirect.URLRegex = arg(1)
			} else if target := arg(1); strings.HasPrefix(target, "/") && (c.root || strings.HasPrefix(dirPath(target), c.urlPath)) {
				redirect.Path = target
			}
		}
	case "setenvif", "setenvifnocase", "setenvifexpr", "browsermatch", "browsermatchnocase":
		if c.envFeedsAccess {
			f.Category, kind = CategoryAccessControl, AccessDenyAllow
		}
	case "require":
		kind = requireKind(n.Args)
	case "addoutputfilterbytype", "addoutputfilter", "setoutputfilter":
		if upper := strings.ToUpper(strings.Join(n.Args, " ")); strings.Contains(upper, "DEFLATE") || strings.Contains(upper, "BROTLI_COMPRESS") {
			f.Category = CategoryCompression
		}
	}
	switch {
	case f.Category == CategoryAccessControl:
		f.Honoured = false
		f.Access = redirect
		if f.Access == nil {
			f.Access = c.access(sc, kind)
		}
		f.Reason = accessReason(f.Access.Kind)
		return f
	case sc.vendor || c.marker:
		f.Category = CategoryVendor
	}
	if !f.Honoured {
		var reason string
		f.Handling, reason, f.PHP = handle(name, n.Args, c.envRead)
		if f.Handling != "" {
			f.Reason = reason
		}
	}
	if f.Reason == "" {
		f.Reason = defaultReason(e.category, f.Honoured)
	}
	return f
}

func rewriteHonoured(n *Node, sc scope) (bool, string) {
	switch {
	case sc.headers:
		return false, "inside an <IfModule> naming mod_headers, which OLS 1.8.4 and later skip"
	case sc.negated:
		return false, "inside a negated <IfModule>; Apache skips it, OLS applies it"
	case sc.scoped:
		return false, "inside a container OLS ignores, so the rule loses its scope"
	case n.Continued:
		return false, "continued over several lines; OLS reads one physical line"
	}
	for _, a := range n.Args {
		if u := strings.ToUpper(a); strings.Contains(u, "%{LA-U:") || strings.Contains(u, "%{LA-F:") {
			return false, "uses %{LA-U:} or %{LA-F:}, which OLS ignores"
		}
	}
	return true, "rewrite directive OLS applies from .htaccess"
}

func defaultReason(cat Category, honoured bool) string {
	switch {
	case honoured:
		return "OLS applies this from .htaccess"
	case cat == CategoryPHPSettings:
		return "PHP setting; OLS takes PHP settings only from vhost php.ini override"
	case cat == CategoryVendor:
		return "LiteSpeed Enterprise directive that OLS ignores"
	}
	return "OLS ignores this in .htaccess and this server does not convert it, so the site would change"
}

func accessReason(kind AccessKind) string {
	switch kind {
	case AccessPassword:
		return "password protection that OLS does not enforce from .htaccess"
	case AccessListing:
		return "directory listing control that OLS ignores in .htaccess"
	case AccessExec:
		return "script execution control that OLS ignores in .htaccess"
	case AccessTLS:
		return "TLS requirement that OLS ignores in .htaccess"
	}
	return "deny/allow rule that OLS does not enforce from .htaccess"
}

// note collects facts about plain whole-directory access rules.
func (c *classifier) note(n *Node, sc scope) {
	name := strings.ToLower(n.Name)
	first := ""
	if len(n.Args) > 0 {
		first = strings.ToLower(n.Args[0])
	}
	if name == "satisfy" && first == "any" {
		c.satisfyAny = true
	}
	if !sc.plain() {
		return
	}
	switch name {
	case "authtype":
		c.plain.authType = c.plain.authType || first == "basic" || first == "digest" || first == "form"
	case "require":
		switch {
		case requireKind(n.Args) == AccessPassword && first != "not":
			c.plain.requireUser = true
		case first == "all" && len(n.Args) == 2 && strings.EqualFold(n.Args[1], "denied"):
			c.plain.requireDenied = true
		default:
			c.plain.requireOther = true
		}
	case "deny":
		if len(n.Args) == 2 && first == "from" && strings.EqualFold(n.Args[1], "all") {
			c.plain.denyAll = true
		}
	case "allow":
		c.plain.allowAny = true
	}
}

func (c *classifier) rules() []AccessRule {
	var out []AccessRule
	seen := map[Access]int{}
	for _, f := range c.findings {
		if f.Access == nil {
			continue
		}
		if _, ok := seen[*f.Access]; ok {
			continue
		}
		seen[*f.Access] = len(out)
		out = append(out, AccessRule{Access: *f.Access, Line: f.Line})
	}
	for i := range out {
		out[i].ExpectStatus = c.expect(out[i].Access)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Line < out[j].Line })
	return out
}

func (c *classifier) expect(a Access) int {
	if a.Files != "" || a.Methods != "" || a.Conditional || a.URLRegex != "" {
		return 0
	}
	if a.Status != 0 {
		// A nested file only sees requests that reach its directory, so its
		// Redirect cannot promise a status for the URL it names.
		if c.root && (a.Status == 401 || a.Status == 403) {
			return a.Status
		}
		return 0
	}
	p := c.plain
	switch a.Kind {
	case AccessPassword:
		if p.authType && p.requireUser && !p.requireOther && !p.requireDenied && !p.denyAll && !p.allowAny && !c.satisfyAny {
			return 401
		}
	case AccessDenyAllow:
		if (p.denyAll || p.requireDenied) && !p.allowAny && !p.requireOther && !p.requireUser && !p.authType && !c.satisfyAny {
			return 403
		}
	}
	return 0
}

// feedsAccess reports whether allow/deny/require rules test environment
// variables, in which case SetEnvIf and BrowserMatch are part of the access
// decision.
func feedsAccess(nodes []*Node) bool {
	for _, n := range nodes {
		switch strings.ToLower(n.Name) {
		case "allow", "deny":
			for _, a := range n.Args {
				if strings.HasPrefix(strings.ToLower(a), "env=") {
					return true
				}
			}
		case "require":
			args := n.Args
			if len(args) > 0 && strings.EqualFold(args[0], "not") {
				args = args[1:]
			}
			if len(args) > 0 && strings.EqualFold(args[0], "env") {
				return true
			}
		}
		if n.Kind == KindSection && feedsAccess(n.Children) {
			return true
		}
	}
	return false
}

func requireKind(args []string) AccessKind {
	if len(args) > 0 && strings.EqualFold(args[0], "not") {
		args = args[1:]
	}
	if len(args) > 0 {
		switch strings.ToLower(args[0]) {
		case "valid-user", "user", "group", "file-owner", "file-group", "ldap-user", "ldap-group", "ldap-dn", "ldap-attribute", "ldap-filter", "dbd-group", "dbm-group":
			return AccessPassword
		}
	}
	return AccessDenyAllow
}

// optionsAccess returns the exposure an Options line changes. An unsigned
// option replaces the whole set and so switches Indexes and ExecCGI as well.
func optionsAccess(args []string) AccessKind {
	var kind AccessKind
	for _, a := range args {
		v := strings.ToLower(a)
		signed := strings.HasPrefix(v, "+") || strings.HasPrefix(v, "-")
		switch strings.TrimLeft(v, "+-") {
		case "execcgi", "includes", "includesnoexec":
			return AccessExec
		case "indexes", "all", "none":
			kind = AccessListing
		default:
			if !signed {
				kind = AccessListing
			}
		}
	}
	return kind
}

func redirectStatus(arg string) int {
	switch strings.ToLower(arg) {
	case "permanent":
		return 301
	case "temp":
		return 302
	case "seeother":
		return 303
	case "gone":
		return 410
	}
	if n, err := strconv.Atoi(arg); err == nil && n >= 100 && n <= 999 {
		return n
	}
	return 0
}

func isOff(v string) bool {
	switch strings.ToLower(v) {
	case "off", "0", "false", "no":
		return true
	}
	return false
}

// dirPath normalises a URL directory path to a leading and trailing slash.
func dirPath(p string) string {
	p = "/" + strings.Trim(p, "/")
	if p != "/" {
		p += "/"
	}
	return p
}

// olsStopLine replays OLS 1.9.4's RewriteEngine::parseRules over the logical
// lines and returns the first line it never applies, or 0 when it reads the
// whole file. A RewriteCond must be followed, comments aside, by more
// RewriteCond lines and then RewriteRule or CacheKeyModify; otherwise OLS
// drops that rule and everything after it.
func olsStopLine(lines []Line) int {
	skip := 0
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		switch {
		case l.Kind == LineComment:
			continue
		case l.Kind == LineOpen && strings.EqualFold(l.Node.Name, "IfModule"):
			if skip > 0 || strings.Contains(strings.Join(l.Node.Args, " "), "mod_headers") {
				skip++
			}
			continue
		case l.Kind == LineClose && strings.EqualFold(l.Name, "IfModule"):
			if skip > 0 {
				skip--
			}
			continue
		}
		if skip > 0 || l.Kind != LineDirective || !strings.EqualFold(l.Node.Name, "RewriteCond") {
			continue
		}
		j := i + 1
		for ; j < len(lines); j++ {
			next := lines[j]
			if next.Kind == LineComment || (next.Kind == LineDirective && strings.EqualFold(next.Node.Name, "RewriteCond")) {
				continue
			}
			if next.Kind == LineDirective && (strings.EqualFold(next.Node.Name, "RewriteRule") || strings.EqualFold(next.Node.Name, "CacheKeyModify")) {
				break
			}
			return l.Num
		}
		if j == len(lines) {
			return l.Num
		}
		i = j
	}
	return 0
}
