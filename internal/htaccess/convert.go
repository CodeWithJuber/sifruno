package htaccess

import (
	"net/netip"
	"reflect"
	"regexp"
	"regexp/syntax"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// The converter turns the access rules of one .htaccess into one
// OpenLiteSpeed rule, or refuses. It recognises only the patterns in the
// table below; anything else, and anything whose Apache meaning depends on
// what this package cannot see, refuses, so a site with it stays off
// OpenLiteSpeed. doc.go ("Converting access rules") gives the Apache and
// OpenLiteSpeed semantics each pattern relies on, with sources.
//
//	pattern                                         rule
//	Deny from all, Require all denied               Hosts none
//	  ... plus <Files>/<FilesMatch> granting names  Hosts none, Allow names
//	Order/Allow/Deny with IP or CIDR lists          Hosts only or except
//	Require ip ..., Require all granted             Hosts only, Hosts all
//	<IfModule [!]mod_authz_core.c> pairs            both branches must agree
//	AuthType Basic, AuthName, AuthUserFile,
//	  Require valid-user | Require user ...         Realm
//	Options -Indexes                                nothing: listings are off
//
// A file that holds any other directive or section, a rewrite rule among
// them, refuses: the converted folder's rule turns rewriting off below it.

// HostKind says which clients a converted folder admits.
type HostKind string

const (
	// HostsAll admits every client.
	HostsAll HostKind = "all"
	// HostsNone admits no client: 403.
	HostsNone HostKind = "none"
	// HostsOnly admits only clients in Networks.
	HostsOnly HostKind = "only"
	// HostsExcept admits every client outside Networks.
	HostsExcept HostKind = "except"
)

// MaxRuleNetworks and MaxRuleNames bound one rule; a larger list refuses.
const (
	MaxRuleNetworks = 64
	MaxRuleNames    = 64
	MaxRealmUsers   = 64
)

// Hosts is a folder's client-address rule. Networks are canonical prefixes
// ("192.0.2.0/24", "198.51.100.7/32", "2001:db8::/32"), sorted, each once.
type Hosts struct {
	Kind     HostKind `json:"kind"`
	Networks []string `json:"networks,omitempty"`
}

// Realm is a folder's HTTP Basic password check. UserFile is the
// AuthUserFile path as the old server named it; Users lists the accounts
// Require user names, or is empty for Require valid-user.
type Realm struct {
	Name     string   `json:"name"`
	UserFile string   `json:"user_file"`
	Users    []string `json:"users,omitempty"`
}

// FolderRule is one converted .htaccess: who may reach the folder at Path
// (a URL path with a leading and trailing slash) and everything below it.
// Allow names files every client may fetch anywhere below a folder whose
// Hosts kind is none; Realm, when set, asks for a password after the host
// check passes.
type FolderRule struct {
	Path  string   `json:"path"`
	Hosts Hosts    `json:"hosts"`
	Allow []string `json:"allow,omitempty"`
	Realm *Realm   `json:"realm,omitempty"`
}

// Open reports a rule that admits everyone without a password: nothing to
// enforce, so no OpenLiteSpeed config is needed for it.
func (r FolderRule) Open() bool { return r.Hosts.Kind == HostsAll && r.Realm == nil }

// Conversion is the converter's answer for one file: Rule, or Refused with
// the line it stopped at.
type Conversion struct {
	Rule    *FolderRule `json:"rule,omitempty"`
	Line    int         `json:"line,omitempty"`
	Refused string      `json:"refused,omitempty"`
}

func refuse(line int, reason string) *Conversion { return &Conversion{Line: line, Refused: reason} }

// convertible reports whether a classified file is one the converter may
// try: compat for access control and for nothing else.
func convertible(r FileResult) bool {
	return r.Verdict == VerdictCompat && len(r.Causes) == 1 && r.Causes[0] == CauseAccessControl
}

// Convert converts one parsed .htaccess at the folder with URL path
// urlPath ("/" for the site root).
func Convert(f *File, urlPath string) *Conversion {
	if len(f.Problems) > 0 {
		return refuse(f.Problems[0].Line, "the file has lines Apache cannot read")
	}
	if !validRulePath(urlPath) {
		return refuse(0, "the folder's name has characters this server does not put in its rules")
	}
	// Apache 2.4 loads mod_authz_core; 2.2 does not have it. A file that asks
	// which one runs must mean the same in both.
	worlds := []bool{true}
	if asksAuthzCore(f.Nodes) {
		worlds = append(worlds, false)
	}
	var first *FolderRule
	for _, authzCore := range worlds {
		e := &evaluator{authzCore: authzCore}
		e.walk(f.Nodes, &e.dir)
		if e.err != nil {
			return e.err
		}
		rule, c := e.rule(urlPath)
		if c != nil {
			return c
		}
		if first == nil {
			first = rule
		} else if !reflect.DeepEqual(first, rule) {
			return refuse(0, "the Apache 2.2 and 2.4 branches (<IfModule mod_authz_core.c>) give different access")
		}
	}
	return &Conversion{Rule: first}
}

// authzCoreNames are the two names <IfModule> accepts for mod_authz_core:
// its source file and its module identifier.
var authzCoreNames = map[string]bool{"mod_authz_core.c": true, "authz_core_module": true}

func asksAuthzCore(nodes []*Node) bool {
	for _, n := range nodes {
		if n.Kind == KindSection {
			if strings.EqualFold(n.Name, "IfModule") && len(n.Args) == 1 && authzCoreNames[strings.TrimPrefix(n.Args[0], "!")] {
				return true
			}
			if asksAuthzCore(n.Children) {
				return true
			}
		}
	}
	return false
}

// compatConf is one section's mod_access_compat configuration. Apache
// creates it only when the section holds one of its directives, and the
// module has no merger, so the nearest section with one replaces the
// others whole.
type compatConf struct {
	set, orderSet     bool
	allowThenDeny     bool
	allowAll, denyAll bool
	allows, denies    []netip.Prefix
}

// authzConf is one section's mod_authz_core requirements: Require lines in
// one section are alternatives (an implicit <RequireAny>). With the default
// AuthMerging Off the nearest section with a Require line replaces the
// others.
type authzConf struct {
	set             bool
	granted, denied bool
	ips             []netip.Prefix
	validUser       bool
	users           []string
}

type section struct {
	line   int
	names  []string
	compat compatConf
	authz  authzConf
}

type evaluator struct {
	authzCore bool
	dir       section
	files     []*section
	authType  string
	authName  string
	userFile  string
	authLine  int
	err       *Conversion
}

func (e *evaluator) fail(line int, reason string) {
	if e.err == nil {
		e.err = refuse(line, reason)
	}
}

func (e *evaluator) walk(nodes []*Node, sec *section) {
	for _, n := range nodes {
		if e.err != nil {
			return
		}
		switch n.Kind {
		case KindComment:
		case KindSection:
			e.section(n, sec)
		case KindDirective:
			e.directive(n, sec)
		}
	}
}

func (e *evaluator) section(n *Node, sec *section) {
	switch strings.ToLower(n.Name) {
	case "ifmodule":
		if len(n.Args) != 1 || !authzCoreNames[strings.TrimPrefix(n.Args[0], "!")] {
			e.fail(n.Line, "<IfModule> around access rules names a module other than mod_authz_core")
			return
		}
		if negated := strings.HasPrefix(n.Args[0], "!"); e.authzCore != negated {
			e.walk(n.Children, sec)
		}
	case "files", "filesmatch":
		if sec != &e.dir {
			e.fail(n.Line, "a <Files> section inside another section")
			return
		}
		names, reason := filesNames(n)
		if reason != "" {
			e.fail(n.Line, reason)
			return
		}
		s := &section{line: n.Line, names: names}
		e.files = append(e.files, s)
		e.walk(n.Children, s)
	default:
		e.fail(n.Line, "<"+n.Name+"> is not one of the converted sections")
	}
}

func (e *evaluator) directive(n *Node, sec *section) {
	name := strings.ToLower(n.Name)
	inDir := sec == &e.dir
	switch name {
	case "order":
		if len(n.Args) != 1 || sec.compat.orderSet {
			e.fail(n.Line, "Order must name one order, once per section")
			return
		}
		switch strings.ToLower(n.Args[0]) {
		case "deny,allow":
		case "allow,deny":
			sec.compat.allowThenDeny = true
		default:
			e.fail(n.Line, "Order "+n.Args[0]+" is not Deny,Allow or Allow,Deny")
			return
		}
		sec.compat.set, sec.compat.orderSet = true, true
	case "allow", "deny":
		if len(n.Args) < 2 || !strings.EqualFold(n.Args[0], "from") {
			e.fail(n.Line, n.Name+" must be followed by from and a list")
			return
		}
		sec.compat.set = true
		for _, a := range n.Args[1:] {
			if strings.EqualFold(a, "all") {
				if name == "allow" {
					sec.compat.allowAll = true
				} else {
					sec.compat.denyAll = true
				}
				continue
			}
			p, ok := parseApacheNet(a)
			if !ok {
				e.fail(n.Line, n.Name+" from names "+quoteArg(a)+", which is not an IP address or network")
				return
			}
			if name == "allow" {
				sec.compat.allows = append(sec.compat.allows, p)
			} else {
				sec.compat.denies = append(sec.compat.denies, p)
			}
		}
	case "require":
		e.require(n, sec)
	case "authtype", "authname", "authuserfile", "authbasicprovider":
		if !inDir {
			e.fail(n.Line, n.Name+" inside a <Files> section")
			return
		}
		e.auth(n, name)
	case "options":
		if !inDir || len(n.Args) != 1 || !strings.EqualFold(n.Args[0], "-Indexes") {
			e.fail(n.Line, "Options other than -Indexes")
		}
	default:
		e.fail(n.Line, n.Name+" is not one of the converted directives")
	}
}

func (e *evaluator) require(n *Node, sec *section) {
	if len(n.Args) == 0 {
		e.fail(n.Line, "Require without a requirement")
		return
	}
	z := &sec.authz
	kind := strings.ToLower(n.Args[0])
	if (kind == "all" || kind == "ip") && !e.authzCore {
		e.fail(n.Line, "Require "+n.Args[0]+" outside an <IfModule mod_authz_core.c> branch, which Apache 2.2 does not read")
		return
	}
	switch {
	case kind == "all" && len(n.Args) == 2 && strings.EqualFold(n.Args[1], "granted"):
		z.granted = true
	case kind == "all" && len(n.Args) == 2 && strings.EqualFold(n.Args[1], "denied"):
		z.denied = true
	case kind == "ip" && len(n.Args) >= 2:
		for _, a := range n.Args[1:] {
			p, ok := parseApacheNet(a)
			if !ok {
				e.fail(n.Line, "Require ip names "+quoteArg(a)+", which is not an IP address or network")
				return
			}
			z.ips = append(z.ips, p)
		}
	case kind == "valid-user" && len(n.Args) == 1:
		z.validUser = true
	case kind == "user" && len(n.Args) >= 2:
		for _, u := range n.Args[1:] {
			if !realmUserPattern.MatchString(u) {
				e.fail(n.Line, "Require user names "+quoteArg(u)+", which is not a plain user name")
				return
			}
			z.users = append(z.users, u)
		}
	default:
		e.fail(n.Line, "Require "+n.Args[0]+" is not all granted, all denied, ip, valid-user or user")
		return
	}
	z.set = true
}

func (e *evaluator) auth(n *Node, name string) {
	if len(n.Args) != 1 {
		e.fail(n.Line, n.Name+" must have one value")
		return
	}
	v := n.Args[0]
	e.authLine = n.Line
	switch name {
	case "authtype":
		if !strings.EqualFold(v, "Basic") || e.authType != "" {
			e.fail(n.Line, "AuthType must be Basic, once")
			return
		}
		e.authType = "basic"
	case "authname":
		if !realmNamePattern.MatchString(v) || strings.Contains(v, "  ") || e.authName != "" {
			e.fail(n.Line, "AuthName must be up to 64 letters, digits, single spaces and . _ , : ( ) ! ? @ -, once")
			return
		}
		e.authName = v
	case "authuserfile":
		if !strings.HasPrefix(v, "/") || e.userFile != "" {
			e.fail(n.Line, "AuthUserFile must be an absolute path, once")
			return
		}
		e.userFile = v
	case "authbasicprovider":
		if v != "file" {
			e.fail(n.Line, "AuthBasicProvider other than file")
		}
	}
}

// rule reduces the evaluated sections to one rule.
func (e *evaluator) rule(urlPath string) (*FolderRule, *Conversion) {
	hosts, users, valid, c := e.effective(e.dir.compat, e.dir.authz, e.dir.line)
	if c != nil {
		return nil, c
	}
	rule := &FolderRule{Path: urlPath, Hosts: hosts}
	authSet := e.authType != "" || e.authName != "" || e.userFile != ""
	switch {
	case valid || len(users) > 0:
		if e.authType == "" || e.authName == "" || e.userFile == "" {
			return nil, refuse(e.authLine, "a password requirement needs AuthType Basic, AuthName and AuthUserFile together")
		}
		rule.Realm = &Realm{Name: e.authName, UserFile: e.userFile}
		if !valid {
			rule.Realm.Users = sortedUnique(users)
			if len(rule.Realm.Users) > MaxRealmUsers {
				return nil, refuse(0, "Require user names more users than this server converts")
			}
		}
	case authSet:
		return nil, refuse(e.authLine, "AuthType, AuthName or AuthUserFile without Require valid-user or Require user")
	}
	// Apache checks the address first (Satisfy All) and answers 403 before
	// it asks for a password, so a folder closed to every address never
	// reaches its realm.
	if hosts.Kind == HostsNone {
		rule.Realm = nil
	}
	if len(e.files) == 0 {
		return rule, nil
	}
	if hosts.Kind != HostsNone || rule.Realm != nil {
		return nil, refuse(e.files[0].line, "a <Files> section is converted only as a list of files open to everyone in a folder closed to everyone")
	}
	for _, f := range e.files {
		compat, authz := e.dir.compat, e.dir.authz
		if f.compat.set {
			compat = f.compat
		}
		if f.authz.set {
			authz = f.authz
		}
		h, u, v, c := e.effective(compat, authz, f.line)
		switch {
		case c != nil:
			return nil, c
		case v || len(u) > 0:
			return nil, refuse(f.line, "a password requirement inside a <Files> section")
		case h.Kind == HostsAll:
			rule.Allow = append(rule.Allow, f.names...)
		case h.Kind != HostsNone:
			return nil, refuse(f.line, "a <Files> section that opens files to some clients only")
		}
	}
	rule.Allow = sortedUnique(rule.Allow)
	if len(rule.Allow) > MaxRuleNames {
		return nil, refuse(0, "the <Files> sections open more files than this server converts")
	}
	return rule, nil
}

// effective is the access of one section: mod_access_compat's verdict and
// mod_authz_core's, both of which must admit a client (Satisfy All, the
// default; any Satisfy line refuses).
func (e *evaluator) effective(c compatConf, z authzConf, line int) (Hosts, []string, bool, *Conversion) {
	a, ok := compatHosts(c)
	if !ok {
		return Hosts{}, nil, false, refuse(line, "Allow and Deny name networks on both sides, which this server does not convert")
	}
	b, users, valid, ok := authzHosts(z)
	if !ok {
		return Hosts{}, nil, false, refuse(line, "Require lines that mix all, ip and user requirements")
	}
	h, ok := andHosts(a, b)
	if !ok {
		return Hosts{}, nil, false, refuse(line, "Allow/Deny and Require ip both name networks, which this server does not convert")
	}
	if len(h.Networks) > MaxRuleNetworks {
		return Hosts{}, nil, false, refuse(line, "more networks than this server converts")
	}
	return h, users, valid, nil
}

// compatHosts follows mod_access_compat's check_dir_access. Deny,Allow
// (the default) admits a client unless a Deny matches and no Allow does;
// Allow,Deny admits a client only if an Allow matches and no Deny does.
func compatHosts(c compatConf) (Hosts, bool) {
	if !c.set {
		return Hosts{Kind: HostsAll}, true
	}
	allows, denies := len(c.allows) > 0, len(c.denies) > 0
	if !c.allowThenDeny {
		switch {
		case c.allowAll, !c.denyAll && !denies:
			return Hosts{Kind: HostsAll}, true
		case c.denyAll && !allows:
			return Hosts{Kind: HostsNone}, true
		case c.denyAll:
			return networks(HostsOnly, c.allows), true
		case !allows:
			return networks(HostsExcept, c.denies), true
		}
		return Hosts{}, false
	}
	switch {
	case c.denyAll, !c.allowAll && !allows:
		return Hosts{Kind: HostsNone}, true
	case c.allowAll && !denies:
		return Hosts{Kind: HostsAll}, true
	case c.allowAll:
		return networks(HostsExcept, c.denies), true
	case !denies:
		return networks(HostsOnly, c.allows), true
	}
	return Hosts{}, false
}

// authzHosts reads one section's Require lines. Only one kind of
// requirement per section converts: all granted, all denied, ip, or users.
func authzHosts(z authzConf) (Hosts, []string, bool, bool) {
	if !z.set {
		return Hosts{Kind: HostsAll}, nil, false, true
	}
	kinds := 0
	for _, k := range []bool{z.granted, z.denied, len(z.ips) > 0, z.validUser || len(z.users) > 0} {
		if k {
			kinds++
		}
	}
	switch {
	case kinds != 1:
		return Hosts{}, nil, false, false
	case z.granted:
		return Hosts{Kind: HostsAll}, nil, false, true
	case z.denied:
		return Hosts{Kind: HostsNone}, nil, false, true
	case len(z.ips) > 0:
		return networks(HostsOnly, z.ips), nil, false, true
	}
	// Require lines are alternatives, so valid-user covers any user line.
	return Hosts{Kind: HostsAll}, z.users, z.validUser, true
}

// andHosts admits a client both rules admit, for the shapes that stay one
// rule.
func andHosts(a, b Hosts) (Hosts, bool) {
	switch {
	case a.Kind == HostsNone || b.Kind == HostsNone:
		return Hosts{Kind: HostsNone}, true
	case a.Kind == HostsAll:
		return b, true
	case b.Kind == HostsAll:
		return a, true
	}
	return Hosts{}, false
}

func networks(kind HostKind, list []netip.Prefix) Hosts {
	out := make([]string, 0, len(list))
	for _, p := range list {
		out = append(out, p.String())
	}
	return Hosts{Kind: kind, Networks: sortedUnique(out)}
}

func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := slices.Clone(in)
	sort.Strings(out)
	return slices.Compact(out)
}

// parseApacheNet reads one address of Allow from, Deny from or Require ip:
// a full IPv4 or IPv6 address, a network in CIDR form, or a partial IPv4
// address of one to three octets ("10.1" is 10.1.0.0/16). The netmask form
// and hosts are refused, and so is a network with host bits set.
func parseApacheNet(s string) (netip.Prefix, bool) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil || p != p.Masked() || p.Bits() == 0 || p.Addr().Zone() != "" || p.Addr().Is4In6() {
			return netip.Prefix{}, false
		}
		return p, true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		if a.Zone() != "" || a.Is4In6() {
			return netip.Prefix{}, false
		}
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	parts := strings.Split(s, ".")
	if len(parts) > 3 {
		return netip.Prefix{}, false
	}
	var b [4]byte
	for i, part := range parts {
		if part == "" || len(part) > 3 || (len(part) > 1 && part[0] == '0') {
			return netip.Prefix{}, false
		}
		v, err := strconv.Atoi(part)
		if err != nil || v < 0 || v > 255 {
			return netip.Prefix{}, false
		}
		b[i] = byte(v)
	}
	return netip.PrefixFrom(netip.AddrFrom4(b), 8*len(parts)), true
}

var (
	// realmNamePattern is an AuthName this server writes into OpenLiteSpeed
	// config and the WWW-Authenticate header.
	realmNamePattern = regexp.MustCompile(`^[A-Za-z0-9._,:()!?@-][A-Za-z0-9 ._,:()!?@-]{0,62}[A-Za-z0-9._,:()!?@-]$|^[A-Za-z0-9._,:()!?@-]$`)
	// realmUserPattern is a user name in Require user and the user file.
	realmUserPattern = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)
	// allowNamePattern is a file name a <Files> allow-list may open.
	allowNamePattern = regexp.MustCompile(`^[A-Za-z0-9_@-][A-Za-z0-9._@-]{0,126}$`)
	// rulePathPart is one folder name of a converted folder's URL path.
	rulePathPart = regexp.MustCompile(`^[A-Za-z0-9_@~-][A-Za-z0-9._@~-]{0,126}$`)
)

// staticSuffixes are the file types an allow-list may open. OpenLiteSpeed
// serves them as static files, and it refuses a static file with a path
// after it (PATH_INFO), so an opened name cannot reach a script.
var staticSuffixes = map[string]bool{
	"css": true, "js": true, "mjs": true, "map": true, "json": true, "txt": true, "xml": true,
	"png": true, "jpg": true, "jpeg": true, "gif": true, "webp": true, "avif": true, "svg": true,
	"ico": true, "bmp": true, "woff": true, "woff2": true, "ttf": true, "otf": true, "eot": true,
	"pdf": true, "mp3": true, "mp4": true, "webm": true, "ogg": true, "wav": true,
}

func allowName(name string) bool {
	dot := strings.LastIndexByte(name, '.')
	return allowNamePattern.MatchString(name) && dot > 0 && staticSuffixes[strings.ToLower(name[dot+1:])]
}

// validRulePath is a URL folder path below the site root whose folder names
// this server writes into a rule.
func validRulePath(p string) bool {
	if len(p) < 3 || len(p) > 200 || !strings.HasPrefix(p, "/") || !strings.HasSuffix(p, "/") {
		return false
	}
	for _, part := range strings.Split(strings.Trim(p, "/"), "/") {
		if !rulePathPart.MatchString(part) {
			return false
		}
	}
	return true
}

// filesNames lists the exact file names a <Files> or <FilesMatch> section
// matches. <Files name> takes a name without wildcards; <FilesMatch re>
// and <Files ~ re> take a regular expression anchored at both ends whose
// language is finite (literals, groups, alternation, ?, small character
// classes), expanded to its names.
func filesNames(n *Node) ([]string, string) {
	var re string
	switch {
	case strings.EqualFold(n.Name, "Files") && len(n.Args) == 1:
		if strings.ContainsAny(n.Args[0], "?*[") {
			return nil, "<Files> with a wildcard"
		}
		if !allowName(n.Args[0]) {
			return nil, "<Files> names " + quoteArg(n.Args[0]) + ", which is not a static file name"
		}
		return []string{n.Args[0]}, ""
	case strings.EqualFold(n.Name, "Files") && len(n.Args) == 2 && n.Args[0] == "~":
		re = n.Args[1]
	case strings.EqualFold(n.Name, "FilesMatch") && len(n.Args) == 1:
		re = n.Args[0]
	default:
		return nil, "<" + n.Name + "> must name one file or one pattern"
	}
	names, ok := expandAnchored(re)
	if !ok {
		return nil, "<" + n.Name + "> pattern " + quoteArg(re) + " is not an anchored list of file names"
	}
	if len(names) > MaxRuleNames {
		return nil, "<" + n.Name + "> pattern matches more names than this server converts"
	}
	for _, name := range names {
		if !allowName(name) {
			return nil, "<" + n.Name + "> pattern matches " + quoteArg(name) + ", which is not a static file name"
		}
	}
	return names, ""
}

// expandAnchored expands ^...$ with a finite language into its strings.
// Go's parser with Perl flags reads ^ and $ as text anchors; PCRE's $ also
// matches before a final newline, which the expansion leaves out, so the
// result is the stricter of the two.
func expandAnchored(expr string) ([]string, bool) {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil || re.Op != syntax.OpConcat || len(re.Sub) < 3 {
		return nil, false
	}
	if re.Sub[0].Op != syntax.OpBeginText || re.Sub[len(re.Sub)-1].Op != syntax.OpEndText {
		return nil, false
	}
	out := []string{""}
	for _, sub := range re.Sub[1 : len(re.Sub)-1] {
		part, ok := expand(sub)
		if !ok {
			return nil, false
		}
		out, ok = product(out, part)
		if !ok {
			return nil, false
		}
	}
	return sortedUnique(out), true
}

const maxExpansion = 256

func expand(re *syntax.Regexp) ([]string, bool) {
	if re.Flags&syntax.FoldCase != 0 {
		return nil, false
	}
	switch re.Op {
	case syntax.OpLiteral:
		return []string{string(re.Rune)}, true
	case syntax.OpEmptyMatch:
		return []string{""}, true
	case syntax.OpCharClass:
		var out []string
		for i := 0; i+1 < len(re.Rune); i += 2 {
			for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
				if len(out) >= 8 {
					return nil, false
				}
				out = append(out, string(r))
			}
		}
		return out, len(out) > 0
	case syntax.OpCapture:
		return expand(re.Sub[0])
	case syntax.OpQuest:
		inner, ok := expand(re.Sub[0])
		return append(inner, ""), ok
	case syntax.OpConcat:
		out := []string{""}
		for _, sub := range re.Sub {
			part, ok := expand(sub)
			if !ok {
				return nil, false
			}
			if out, ok = product(out, part); !ok {
				return nil, false
			}
		}
		return out, true
	case syntax.OpAlternate:
		var out []string
		for _, sub := range re.Sub {
			part, ok := expand(sub)
			if !ok || len(out)+len(part) > maxExpansion {
				return nil, false
			}
			out = append(out, part...)
		}
		return out, true
	}
	return nil, false
}

func product(a, b []string) ([]string, bool) {
	if len(a)*len(b) > maxExpansion {
		return nil, false
	}
	out := make([]string, 0, len(a)*len(b))
	for _, x := range a {
		for _, y := range b {
			out = append(out, x+y)
		}
	}
	return out, true
}

// quoteArg shows a value from the file in a refusal, bounded and printable.
func quoteArg(s string) string {
	if len(s) > 60 {
		s = s[:60] + "..."
	}
	return strconv.Quote(s)
}

// SiteConversion is the converter's answer for a scanned site: the rules to
// enforce, or the files it refused. Native reports a site OpenLiteSpeed
// serves as Apache did: every file native or converted.
type SiteConversion struct {
	Native  bool          `json:"native"`
	Rules   []FolderRule  `json:"rules"`
	Refused []FileRefusal `json:"refused,omitempty"`
}

// FileRefusal is why a site is not Native: a file, or the site itself
// (File empty) for a cause such as a link the scan did not follow.
type FileRefusal struct {
	File   string `json:"file,omitempty"`
	Line   int    `json:"line,omitempty"`
	Reason string `json:"reason"`
}

// ConvertSite decides whether a scanned site is Native with its converted
// rules. Beyond each file's own conversion it refuses what the rules cannot
// carry: a rule at the site root (its rule would cover every path, the
// certificate challenge among them), and any .htaccess below a converted
// folder, because the converted folder's rule turns rewriting off for
// everything below it and Apache would have applied that file.
func ConvertSite(site SiteResult) SiteConversion {
	out := SiteConversion{Rules: []FolderRule{}}
	for _, cause := range site.Causes {
		switch cause {
		case CauseAccessControl:
		case CauseSymlinkNotFollowed, CauseScanTruncated, CauseUnreadableDir:
			out.Refused = append(out.Refused, FileRefusal{Reason: causeReason[cause]})
		}
	}
	for _, f := range site.Files {
		switch {
		case f.Verdict == VerdictNative:
		case convertible(f) && f.Conversion != nil && f.Conversion.Rule != nil:
			if f.Conversion.Rule.Open() {
				continue
			}
			if f.Conversion.Rule.Path == "/" {
				out.Refused = append(out.Refused, FileRefusal{File: f.Path, Reason: "access rules for the whole site, which this server does not convert"})
				continue
			}
			out.Rules = append(out.Rules, *f.Conversion.Rule)
		case convertible(f) && f.Conversion != nil:
			out.Refused = append(out.Refused, FileRefusal{File: f.Path, Line: f.Conversion.Line, Reason: f.Conversion.Refused})
		default:
			out.Refused = append(out.Refused, FileRefusal{File: f.Path, Reason: fileReason(f)})
		}
	}
	for _, rule := range out.Rules {
		for _, f := range site.Files {
			if f.URLPath != rule.Path && strings.HasPrefix(f.URLPath, rule.Path) {
				out.Refused = append(out.Refused, FileRefusal{File: f.Path, Reason: "an .htaccess below the converted folder " + rule.Path})
			}
		}
	}
	sort.Slice(out.Rules, func(i, j int) bool { return out.Rules[i].Path < out.Rules[j].Path })
	out.Native = len(out.Refused) == 0
	if !out.Native {
		out.Rules = []FolderRule{}
	}
	return out
}

var causeReason = map[string]string{
	CauseSymlinkNotFollowed: "a folder reached through a link, which the check does not follow",
	CauseScanTruncated:      "more files or folders than the check reads",
	CauseUnreadableDir:      "a folder the check could not read",
}

func fileReason(f FileResult) string {
	switch {
	case f.Error != "":
		return "the file " + f.Error
	case f.Verdict == VerdictConvertible:
		return "directives OpenLiteSpeed ignores (headers, caching, PHP settings or similar)"
	case slices.Contains(f.Causes, CauseUnknown):
		return "directives this panel does not know"
	case slices.Contains(f.Causes, CauseMalformed):
		return "lines Apache cannot read"
	}
	return "access rules mixed with other directives"
}
