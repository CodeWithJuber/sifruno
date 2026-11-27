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
//	<Files>/<FilesMatch> closed to every client     Deny names, in a folder
//	  in a folder not closed to everyone              or at the site root
//	Options -Indexes                                nothing: listings are off
//	lines with a handling class (handling.go),      passed over: OpenLiteSpeed
//	  and <IfModule>/<Files> holding only them        ignores them either way
//
// A file that holds any other directive or section refuses. Lines
// OpenLiteSpeed applies from .htaccess (its rewrite lines) are kept beside
// a rule that only closes file names, whose contexts cover those names
// alone; beside any other rule they refuse, because the converted folder's
// context turns rewriting off below it.
//
// The names a <Files> or <FilesMatch> section closes (filesDenyNames):
// <Files name> is one whole name (Apache compares the last part of the
// file's path with strcmp, server/request.c ap_file_walk); <Files *end>
// every name that ends with end (apr_fnmatch: '*' matches any text without
// a '/'); <FilesMatch re> and <Files ~ re> a regular expression Apache
// searches the name for, unanchored unless the expression says so
// (modules ap_regexec on the name, AP_REG_EXTENDED only). Only two shapes
// of expression convert, each to the exact same set of names: ^...$ over a
// finite list (whole names), and ...$ without ^ over a finite list (name
// endings).

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
// check passes. Deny closes file names below Path to every client (403)
// whatever the rest of the rule says; a rule with Deny alone (Hosts all,
// no Realm) leaves the folder itself open and may be at the site root.
type FolderRule struct {
	// File is the .htaccess the rule came from, set by ConvertSite.
	File  string   `json:"file,omitempty"`
	Path  string   `json:"path"`
	Hosts Hosts    `json:"hosts"`
	Allow []string `json:"allow,omitempty"`
	Realm *Realm   `json:"realm,omitempty"`
	Deny  *Names   `json:"deny,omitempty"`
}

// Names are the file names a deny closes: a path part named one of Exact,
// or ending with one of Endings, and everything below such a part. Both
// lists are sorted, each name once.
type Names struct {
	Exact   []string `json:"exact,omitempty"`
	Endings []string `json:"endings,omitempty"`
}

// Match reports whether a file name (one path part) is closed.
func (n Names) Match(name string) bool {
	if slices.Contains(n.Exact, name) {
		return true
	}
	for _, e := range n.Endings {
		if strings.HasSuffix(name, e) {
			return true
		}
	}
	return false
}

// indexFiles are the names every Sifruno vhost serves for a folder's own
// address (olsweb render.go, indexFiles).
var indexFiles = []string{"index.php", "index.html"}

// CoversIndex reports whether the names include a folder's index file:
// OpenLiteSpeed serves that file for the folder's address too, so the
// rule must close the folder's address as well (olsweb access.go).
func (n Names) CoversIndex() bool {
	return slices.ContainsFunc(indexFiles, n.Match)
}

// Open reports a rule that admits everyone without a password and closes
// no name: nothing to enforce, so no OpenLiteSpeed config is needed for it.
func (r FolderRule) Open() bool { return r.Hosts.Kind == HostsAll && r.Realm == nil && r.Deny == nil }

// Folder reports a rule that limits who may reach the folder itself, not
// only file names in it. Its context takes the whole folder, with
// rewriting off below it.
func (r FolderRule) Folder() bool { return r.Hosts.Kind != HostsAll || r.Realm != nil }

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
	return convert(f, urlPath, nil, nil)
}

// convert is Convert passing over the lines in skip: lines the classifier
// gave a handling class (handling.go), which OpenLiteSpeed ignores whether
// or not the folder is converted and which are never access control. A
// section is passed over only when every line in it is. The lines in kept
// are ones OpenLiteSpeed applies from .htaccess (rewrite lines): they stay
// in force beside a rule that only closes file names, and refuse any other
// rule.
func convert(f *File, urlPath string, skip, kept map[int]bool) *Conversion {
	if len(f.Problems) > 0 {
		return refuse(f.Problems[0].Line, "the file has lines Apache cannot read")
	}
	if urlPath != "/" && !validRulePath(urlPath) {
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
		e := &evaluator{authzCore: authzCore, skip: skip, kept: kept}
		e.walk(f.Nodes, &e.dir)
		if e.err != nil {
			return e.err
		}
		rule, c := e.rule(urlPath)
		if c != nil {
			return c
		}
		// A folder's context turns rewriting off below it, so the lines
		// OpenLiteSpeed would apply from this file refuse such a rule.
		if rule.Folder() && e.keptLine > 0 {
			return refuse(e.keptLine, e.keptName+" is not one of the converted directives")
		}
		if first == nil {
			first = rule
		} else if !reflect.DeepEqual(first, rule) {
			return refuse(0, "the Apache 2.2 and 2.4 branches (<IfModule mod_authz_core.c>) give different access")
		}
	}
	// A rule for the folder at the site root would cover every path, the
	// certificate challenge among them; one that closes file names covers
	// those names only.
	if urlPath == "/" && first.Folder() {
		return refuse(0, "access rules for the whole site, which this server does not convert")
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
	node   *Node
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
	// skip holds the lines convert passes over.
	skip map[int]bool
	// kept holds the lines OpenLiteSpeed applies from .htaccess; keptLine
	// and keptName are the first one this file holds.
	kept     map[int]bool
	keptLine int
	keptName string
}

// keep notes a line OpenLiteSpeed applies, for rule to refuse beside a
// folder's rule.
func (e *evaluator) keep(n *Node) {
	if e.keptLine == 0 {
		e.keptLine, e.keptName = n.Line, n.Name
	}
}

// keepable reports an <IfModule> section that holds no access directive,
// only lines OpenLiteSpeed applies or that convert passes over, and such
// sections: the rewrite block of a WordPress .htaccess, for one.
func (e *evaluator) keepable(n *Node) bool {
	if !strings.EqualFold(n.Name, "IfModule") {
		return false
	}
	for _, c := range n.Children {
		switch {
		case c.Kind == KindDirective && !e.skip[c.Line] && !e.kept[c.Line]:
			return false
		case c.Kind == KindSection && !e.skippable(c) && !e.keepable(c):
			return false
		}
	}
	return true
}

// unconverted is the first directive below nodes that convert neither
// passes over nor keeps, or nil.
func (e *evaluator) unconverted(nodes []*Node) *Node {
	for _, c := range nodes {
		switch {
		case c.Kind == KindDirective && !e.skip[c.Line] && !e.kept[c.Line]:
			return c
		case c.Kind == KindSection:
			if d := e.unconverted(c.Children); d != nil {
				return d
			}
		}
	}
	return nil
}

// accessDirective reports a directive of the access modules or Options.
func accessDirective(n *Node) bool {
	e, ok := lookup(strings.ToLower(n.Name))
	return ok && e.category == CategoryAccessControl || strings.EqualFold(n.Name, "Options")
}

// keepAll notes the first kept line inside a keepable section.
func (e *evaluator) keepAll(nodes []*Node) {
	for _, c := range nodes {
		switch {
		case c.Kind == KindDirective && e.kept[c.Line]:
			e.keep(c)
		case c.Kind == KindSection:
			e.keepAll(c.Children)
		}
	}
}

// skippable reports a section that only scopes what it holds (<IfModule>,
// <Files>, <FilesMatch>) and holds only skipped lines. Apache makes no
// access configuration for a section without an access directive
// (doc.go, "Converting access rules"), so passing over it changes no
// rule.
func (e *evaluator) skippable(n *Node) bool {
	switch strings.ToLower(n.Name) {
	case "ifmodule", "files", "filesmatch":
	default:
		return false
	}
	for _, c := range n.Children {
		switch {
		case c.Kind == KindDirective && !e.skip[c.Line]:
			return false
		case c.Kind == KindSection && !e.skippable(c):
			return false
		}
	}
	return true
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
	if e.skippable(n) {
		return
	}
	if sec == &e.dir && e.keepable(n) {
		e.keepAll(n.Children)
		return
	}
	switch strings.ToLower(n.Name) {
	case "ifmodule":
		if len(n.Args) != 1 || !authzCoreNames[strings.TrimPrefix(n.Args[0], "!")] {
			// Name the line that is not passed over, unless it is an access
			// line: then the module is the reason.
			if c := e.unconverted(n.Children); c != nil && !accessDirective(c) {
				e.fail(c.Line, c.Name+" is not one of the converted directives")
				return
			}
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
		s := &section{line: n.Line, node: n}
		e.files = append(e.files, s)
		e.walk(n.Children, s)
	default:
		e.fail(n.Line, "<"+n.Name+"> is not one of the converted sections")
	}
}

func (e *evaluator) directive(n *Node, sec *section) {
	if e.skip[n.Line] {
		return
	}
	if e.kept[n.Line] && sec == &e.dir {
		e.keep(n)
		return
	}
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
	// Each <Files> section that matches a name replaces the folder's
	// configuration for it, the later one the earlier (doc.go). In a folder
	// closed to everyone a section either opens names or adds nothing; in
	// any other folder it either closes names or refuses.
	closed := hosts.Kind == HostsNone
	var deny []*section
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
		case h.Kind == HostsNone && closed && len(rule.Allow) > 0:
			// It could close again a name an earlier section opened.
			return nil, refuse(f.line, "a <Files> section that closes names after one that opened names")
		case h.Kind == HostsNone && !closed:
			// Apache answers 403 before it asks for a password.
			deny = append(deny, f)
		case h.Kind == HostsNone:
		case v || len(u) > 0:
			return nil, refuse(f.line, "a password requirement inside a <Files> section")
		case h.Kind == HostsAll && closed:
			names, reason := filesNames(f.node)
			if reason != "" {
				return nil, refuse(f.line, reason)
			}
			rule.Allow = append(rule.Allow, names...)
		case h.Kind == HostsAll:
			return nil, refuse(f.line, "a <Files> section that opens files in a folder not closed to everyone")
		default:
			return nil, refuse(f.line, "a <Files> section that opens files to some clients only")
		}
	}
	rule.Allow = sortedUnique(rule.Allow)
	if len(rule.Allow) > MaxRuleNames {
		return nil, refuse(0, "the <Files> sections open more files than this server converts")
	}
	if len(deny) == 0 {
		return rule, nil
	}
	names := Names{}
	for _, f := range deny {
		n, reason := filesDenyNames(f.node)
		if reason != "" {
			return nil, refuse(f.line, reason)
		}
		names.Exact = append(names.Exact, n.Exact...)
		names.Endings = append(names.Endings, n.Endings...)
	}
	names.Exact, names.Endings = sortedUnique(names.Exact), sortedUnique(names.Endings)
	if len(names.Exact)+len(names.Endings) > MaxRuleNames {
		return nil, refuse(deny[0].line, "the <Files> sections close more names than this server converts")
	}
	rule.Deny = &names
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

// denyNamePattern is a name, or a name ending, a deny may close: letters,
// digits and . _ @ ~ -, so the renderer's regex quotes only '.'.
var denyNamePattern = regexp.MustCompile(`^[A-Za-z0-9._@~-]{1,127}$`)

// filesDenyNames lists the names a <Files> or <FilesMatch> section closes
// (the shapes are described at the top of this file), or why it cannot be
// converted. Names that include a folder's index file close the folder's
// own address too (Names.CoversIndex).
func filesDenyNames(n *Node) (Names, string) {
	var re string
	switch {
	case strings.EqualFold(n.Name, "Files") && len(n.Args) == 1:
		name := n.Args[0]
		end, star := strings.CutPrefix(name, "*")
		switch {
		case star && !strings.ContainsAny(end, "?*[\\") && denyName(end):
			return Names{Endings: []string{end}}, ""
		case strings.ContainsAny(name, "?*[\\"):
			return Names{}, "<Files> with a wildcard other than one leading *"
		case !denyName(name):
			return Names{}, "<Files> names " + quoteArg(name) + ", which has characters this server does not put in its rules"
		}
		return Names{Exact: []string{name}}, ""
	case strings.EqualFold(n.Name, "Files") && len(n.Args) == 2 && n.Args[0] == "~":
		re = n.Args[1]
	case strings.EqualFold(n.Name, "FilesMatch") && len(n.Args) == 1:
		re = n.Args[0]
	default:
		return Names{}, "<" + n.Name + "> must name one file or one pattern"
	}
	var out Names
	if names, ok := expandAnchored(re); ok {
		out.Exact = names
	} else if ends, ok := expandEnding(re); ok {
		out.Endings = ends
	} else {
		return Names{}, "<" + n.Name + "> pattern " + quoteArg(re) + " is not a list of whole names (^...$) or of name endings (...$)"
	}
	for _, name := range append(slices.Clone(out.Exact), out.Endings...) {
		if !denyName(name) {
			return Names{}, "<" + n.Name + "> pattern matches " + quoteArg(name) + ", which has characters this server does not put in its rules"
		}
	}
	if len(out.Exact)+len(out.Endings) > MaxRuleNames {
		return Names{}, "<" + n.Name + "> pattern matches more names than this server converts"
	}
	return out, ""
}

func denyName(name string) bool {
	return denyNamePattern.MatchString(name) && name != "." && name != ".."
}

// expandEnding expands ...$ without a leading ^ and with a finite
// language into the endings it matches: Apache searches the name for the
// expression, so a name matches when it ends with one of them. An empty
// ending would match every name and refuses.
func expandEnding(expr string) ([]string, bool) {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return nil, false
	}
	subs := []*syntax.Regexp{re}
	if re.Op == syntax.OpConcat {
		subs = re.Sub
	}
	if len(subs) < 2 || subs[len(subs)-1].Op != syntax.OpEndText {
		return nil, false
	}
	out := []string{""}
	for _, sub := range subs[:len(subs)-1] {
		part, ok := expand(sub)
		if !ok {
			return nil, false
		}
		if out, ok = product(out, part); !ok {
			return nil, false
		}
	}
	if slices.Contains(out, "") {
		return nil, false
	}
	return sortedUnique(out), true
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
// serves as Apache did: every file native or converted. Warnings are the
// lines a person checks before cutover, and PHP the lines that chose a PHP
// version on the old server, for the migration to compare with its plan.
type SiteConversion struct {
	Native   bool          `json:"native"`
	Rules    []FolderRule  `json:"rules"`
	Refused  []FileRefusal `json:"refused,omitempty"`
	Warnings []FileWarning `json:"warnings,omitempty"`
	PHP      []PHPHandler  `json:"php_handlers,omitempty"`
	// Redirects are the root .htaccess's converted redirect lines, in file
	// order (the first that matches answers), and ErrorPages its error
	// pages by status, the last line for a status winning, as in Apache.
	Redirects  []Redirect  `json:"redirects,omitempty"`
	ErrorPages []ErrorPage `json:"error_pages,omitempty"`
}

// MaxSiteRedirects bounds the redirects a site's root .htaccess converts;
// more refuse.
const MaxSiteRedirects = 100

// FileRefusal is why a site is not Native: a line of a file, a whole file
// (Line 0), or the site itself (File empty) for a cause such as a link the
// scan did not follow. Directive is the line's label (handling.go label).
// Cause is one of Causes or CauseNotConverted; it is CauseAccessControl
// when the refusal concerns an access rule, which OpenLiteSpeed would
// leave open.
type FileRefusal struct {
	File      string `json:"file,omitempty"`
	Line      int    `json:"line,omitempty"`
	Directive string `json:"directive,omitempty"`
	Cause     string `json:"cause,omitempty"`
	Reason    string `json:"reason"`
}

// ConvertSite decides whether a scanned site is Native with its converted
// rules. Beyond each file's own conversion it refuses what the rules cannot
// carry: a folder rule at the site root (its rule would cover every path,
// the certificate challenge among them), and any .htaccess below a
// converted folder, because the converted folder's rule turns rewriting
// off for everything below it and Apache would have applied that file. A
// rule that only closes file names is neither: it may be at the root, and
// the files below it keep working.
func ConvertSite(site SiteResult) SiteConversion {
	out := SiteConversion{Rules: []FolderRule{}}
	for _, cause := range site.Causes {
		switch cause {
		case CauseSymlinkNotFollowed, CauseScanTruncated, CauseUnreadableDir:
			out.Refused = append(out.Refused, FileRefusal{Cause: cause, Reason: causeReason[cause]})
		}
	}
	// A verdict no file accounts for is not one this function can judge.
	if site.Verdict != VerdictNative && !slices.ContainsFunc(site.Files, func(f FileResult) bool { return f.Verdict != VerdictNative }) && len(out.Refused) == 0 {
		out.Refused = append(out.Refused, FileRefusal{Reason: "the scan found rules no file holds"})
	}
	for _, f := range site.Files {
		switch {
		case f.Verdict == VerdictNative:
		case convertible(f) && f.Conversion != nil && f.Conversion.Rule != nil:
			if f.Conversion.Rule.Open() {
				continue
			}
			if f.Conversion.Rule.Path == "/" && f.Conversion.Rule.Folder() {
				line, directive := firstAccess(f)
				out.Refused = append(out.Refused, FileRefusal{File: f.Path, Line: line, Directive: directive, Cause: CauseAccessControl, Reason: "access rules for the whole site, which this server does not convert"})
				continue
			}
			rule := *f.Conversion.Rule
			rule.File = f.Path
			out.Rules = append(out.Rules, rule)
		case convertible(f) && f.Conversion != nil:
			// Whatever line the converter stopped at, the file's access rules
			// are not carried, so OpenLiteSpeed would open its folder: an
			// access refusal. A refusal of the whole file names its first
			// access rule.
			line, directive := f.Conversion.Line, labelAt(f, f.Conversion.Line)
			if line == 0 {
				line, directive = firstAccess(f)
			}
			out.Refused = append(out.Refused, FileRefusal{File: f.Path, Line: line, Directive: directive, Cause: CauseAccessControl, Reason: f.Conversion.Refused})
		default:
			out.Refused = append(out.Refused, fileRefusals(f)...)
		}
	}
	for _, rule := range out.Rules {
		// A rule that only closes file names takes those names' paths, not
		// the folder, so the .htaccess files below it keep working.
		if !rule.Folder() {
			continue
		}
		for _, f := range site.Files {
			if f.URLPath != rule.Path && strings.HasPrefix(f.URLPath, rule.Path) {
				out.Refused = append(out.Refused, FileRefusal{File: f.Path, Cause: CauseAccessControl, Reason: "an .htaccess below the converted folder " + rule.Path})
			}
		}
	}
	if len(out.Rules) > 0 {
		for _, f := range site.Files {
			if f.RewriteToPath > 0 {
				out.Refused = append(out.Refused, FileRefusal{File: f.Path, Line: f.RewriteToPath, Directive: labelAt(f, f.RewriteToPath), Cause: CauseAccessControl, Reason: "a rewrite rule whose result the request itself or a file path can choose, which OpenLiteSpeed could serve without the protected folders' checks"})
			}
		}
	}
	pages := map[int]ErrorPage{}
	for _, f := range site.Files {
		for _, g := range f.Findings {
			switch {
			case g.Handling == HandlingWarning:
				out.Warnings = append(out.Warnings, FileWarning{File: f.Path, Line: g.Line, Directive: g.Label, Reason: g.Reason})
			case g.Handling == HandlingSifruno && (strings.EqualFold(g.Directive, "AddHandler") || strings.EqualFold(g.Directive, "AddType")):
				out.PHP = append(out.PHP, PHPHandler{File: f.Path, Line: g.Line, Directive: g.Label, Path: f.URLPath, Package: g.PHP})
			}
			switch {
			case g.Redirect != nil:
				out.Redirects = append(out.Redirects, *g.Redirect)
				if len(out.Redirects) == MaxSiteRedirects+1 {
					out.Refused = append(out.Refused, FileRefusal{File: f.Path, Line: g.Line, Directive: g.Label, Cause: CauseNotConverted, Reason: "more redirects than this server converts for one site (" + strconv.Itoa(MaxSiteRedirects) + ")"})
				}
			case g.ErrorPage != nil:
				pages[g.ErrorPage.Status] = *g.ErrorPage
			}
		}
	}
	for _, p := range pages {
		// "default" and an error text leave OpenLiteSpeed's own page.
		if p.URL != "" {
			out.ErrorPages = append(out.ErrorPages, p)
		}
	}
	sort.Slice(out.ErrorPages, func(i, j int) bool { return out.ErrorPages[i].Status < out.ErrorPages[j].Status })
	sort.Slice(out.Rules, func(i, j int) bool { return out.Rules[i].Path < out.Rules[j].Path })
	out.Native = len(out.Refused) == 0
	if !out.Native {
		out.Rules, out.Redirects, out.ErrorPages = []FolderRule{}, nil, nil
	}
	return out
}

// A rewrite into a protected folder. Apache checks access again for the
// rewritten URL. OpenLiteSpeed 1.9.4 does too when the result is a URL
// path: HttpReq::postRewriteProcess (src/http/httpreq.cpp) answers 1 when
// the context changes, processContextRewrite then clears HSF_URI_PROCESSED,
// and after the access check of the old context the request goes back to
// HSPS_CONTEXT_MAP, where processContext tries the regex contexts first and
// a changed context is checked again (src/http/httpsession.cpp). But when the
// result names a file path, postRewriteProcess first looks it up by context
// location (m_pVHost->matchLocation, the comment "if is rewriten to file
// path, reverse lookup context from file path") and skips context
// processing; ContextTree::add (src/http/contexttree.cpp) indexes plain
// contexts by location from "/", and regex contexts not at all, so a result
// such as /home/<user>/public_html/private/x is served under the "/" context
// or a subfolder's, without the protected folder's regex context. In an
// .htaccess Apache treats that substitution as a URL path (mod_rewrite's
// per-directory rewriting), which finds nothing. Every location such a
// lookup can reach for a site's files is under /home (olsweb.HomeRoot).
//
// rewriteToPath therefore returns the line of the first RewriteRule whose
// substitution is an internal rewrite (not "-", not a URL with a scheme, no
// R or redirect flag) that either starts, after an optional '/', with a
// back-reference or a variable (the request could choose "home/..."), or
// whose first path part is "home", or of a RewriteBase that does either,
// and 0 when there is none. ConvertSite refuses a site with converted
// folders when any file has one.
func rewriteToPath(lines []Line) int {
	for _, l := range lines {
		if l.Kind != LineDirective {
			continue
		}
		args := l.Node.Args
		switch {
		case strings.EqualFold(l.Node.Name, "RewriteBase") && len(args) > 0:
			if pathLike(args[0]) {
				return l.Num
			}
		case strings.EqualFold(l.Node.Name, "RewriteRule"):
			if len(args) < 2 {
				continue
			}
			flags := ""
			if len(args) > 2 {
				flags = args[2]
			}
			if internalRewrite(args[1], flags) && pathLike(args[1]) {
				return l.Num
			}
		}
	}
	return 0
}

var schemeURL = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)

// internalRewrite reports a substitution that maps the request to another
// resource on this site rather than answering it with a redirect.
func internalRewrite(sub, flags string) bool {
	if sub == "-" || schemeURL.MatchString(sub) {
		return false
	}
	for _, flag := range strings.Split(strings.Trim(flags, "[]"), ",") {
		name, _, _ := strings.Cut(strings.TrimSpace(flag), "=")
		if strings.EqualFold(name, "R") || strings.EqualFold(name, "redirect") {
			return false
		}
	}
	return true
}

// pathLike reports a rewrite result that could start with /home/: one that
// starts with a back-reference or variable, or whose first part is "home".
func pathLike(sub string) bool {
	s := strings.TrimPrefix(sub, "/")
	first, _, _ := strings.Cut(s, "/")
	first, _, _ = strings.Cut(first, "?")
	return strings.HasPrefix(s, "$") || strings.HasPrefix(s, "%") || strings.ContainsAny(first, "$%") || strings.EqualFold(first, "home")
}

var causeReason = map[string]string{
	CauseSymlinkNotFollowed: "a folder reached through a link, which the check does not follow",
	CauseScanTruncated:      "more files or folders than the check reads",
	CauseUnreadableDir:      "a folder the check could not read",
}

// fileRefusals names each line that keeps a file the converter does not
// take off the Native tier: a file the scan could not read, lines Apache
// cannot read, unknown directives, and lines OpenLiteSpeed ignores that no
// handling class covers (handling.go). The file's access rules are named
// only when nothing else is wrong with it, so a refusal names an access
// rule only when that rule is the reason.
func fileRefusals(f FileResult) []FileRefusal {
	if f.Error != "" {
		cause := CauseUnreadableFile
		if len(f.Causes) > 0 {
			cause = f.Causes[0]
		}
		return []FileRefusal{{File: f.Path, Cause: cause, Reason: "the file " + f.Error}}
	}
	var out []FileRefusal
	for _, p := range f.Problems {
		out = append(out, FileRefusal{File: f.Path, Line: p.Line, Cause: CauseMalformed, Reason: "a line Apache cannot read: " + p.Reason})
	}
	for _, g := range f.Findings {
		switch {
		case g.Category == CategoryUnknown:
			out = append(out, FileRefusal{File: f.Path, Line: g.Line, Directive: g.Label, Cause: CauseUnknown, Reason: "a directive this panel does not know"})
		case g.Category != CategoryStructure && g.Category != CategoryAccessControl && !g.Honoured && g.Handling == "":
			out = append(out, FileRefusal{File: f.Path, Line: g.Line, Directive: g.Label, Cause: CauseNotConverted, Reason: g.Reason})
		}
	}
	if len(out) == 0 {
		for _, g := range f.Findings {
			if g.Category == CategoryAccessControl {
				out = append(out, FileRefusal{File: f.Path, Line: g.Line, Directive: g.Label, Cause: CauseAccessControl, Reason: g.Reason})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Line < out[j].Line })
	if len(out) == 0 {
		out = append(out, FileRefusal{File: f.Path, Reason: "rules OpenLiteSpeed does not act on"})
	}
	return out
}

// firstAccess is the line and label of a file's first access rule.
func firstAccess(f FileResult) (int, string) {
	for _, g := range f.Findings {
		if g.Category == CategoryAccessControl {
			return g.Line, g.Label
		}
	}
	return 0, ""
}

// labelAt is the label of the directive at a line of a file, if any.
func labelAt(f FileResult, line int) string {
	for _, g := range f.Findings {
		if line > 0 && g.Line == line {
			return g.Label
		}
	}
	return ""
}
