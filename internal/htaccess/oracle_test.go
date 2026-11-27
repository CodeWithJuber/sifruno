package htaccess

import (
	"net"
	"net/netip"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The oracle below is a second, independent model of Apache 2.4 with
// mod_access_compat, written from the module docs and its check_dir_access
// rather than from convert.go: it reads files of top-level Order, Allow,
// Deny, Require all and Require ip lines (and Options), and answers whether a
// client address may reach the folder. It declines (ok false) anything else.
func apacheAllows(f *File, ip netip.Addr) (allowed, ok bool) {
	compat, authz := false, false
	allowThenDeny := false
	var allows, denies []string
	var requires [][]string
	for _, n := range f.Nodes {
		switch n.Kind {
		case KindComment:
			continue
		case KindSection:
			return false, false
		}
		args := n.Args
		switch strings.ToLower(n.Name) {
		case "options":
		case "order":
			if len(args) != 1 {
				return false, false
			}
			compat = true
			switch strings.ToLower(args[0]) {
			case "allow,deny":
				allowThenDeny = true
			case "deny,allow":
				allowThenDeny = false
			default:
				return false, false
			}
		case "allow", "deny":
			if len(args) < 2 || !strings.EqualFold(args[0], "from") {
				return false, false
			}
			compat = true
			if strings.EqualFold(n.Name, "allow") {
				allows = append(allows, args[1:]...)
			} else {
				denies = append(denies, args[1:]...)
			}
		case "require":
			authz = true
			requires = append(requires, args)
		default:
			return false, false
		}
	}
	matches := func(list []string) (bool, bool) {
		hit := false
		for _, entry := range list {
			m, ok := oracleMatch(entry, ip)
			if !ok {
				return false, false
			}
			hit = hit || m
		}
		return hit, true
	}
	pass := true
	if compat {
		a, ok1 := matches(allows)
		d, ok2 := matches(denies)
		if !ok1 || !ok2 {
			return false, false
		}
		if allowThenDeny {
			pass = a && !d
		} else {
			pass = !d || a
		}
	}
	if authz {
		granted := false
		for _, r := range requires {
			switch {
			case len(r) == 2 && strings.EqualFold(r[0], "all") && strings.EqualFold(r[1], "granted"):
				granted = true
			case len(r) == 2 && strings.EqualFold(r[0], "all") && strings.EqualFold(r[1], "denied"):
			case len(r) >= 2 && strings.EqualFold(r[0], "ip"):
				m, ok := matches(r[1:])
				if !ok {
					return false, false
				}
				granted = granted || m
			default:
				return false, false
			}
		}
		pass = pass && granted
	}
	return pass, true
}

// oracleMatch reads one Allow/Deny/Require ip entry the way the module docs
// describe it: all, a full address, a CIDR network, or the first one to
// three bytes of an IPv4 address.
func oracleMatch(entry string, ip netip.Addr) (bool, bool) {
	if strings.EqualFold(entry, "all") {
		return true, true
	}
	if _, network, err := net.ParseCIDR(entry); err == nil {
		return network.Contains(net.IP(ip.AsSlice())), true
	}
	if a := net.ParseIP(entry); a != nil {
		return a.Equal(net.IP(ip.AsSlice())), true
	}
	parts := strings.Split(entry, ".")
	if len(parts) > 3 || !ip.Is4() {
		return false, len(parts) <= 3 && partialIPv4(parts)
	}
	if !partialIPv4(parts) {
		return false, false
	}
	b := ip.As4()
	for i, p := range parts {
		v, _ := strconv.Atoi(p)
		if int(b[i]) != v {
			return false, true
		}
	}
	return true, true
}

func partialIPv4(parts []string) bool {
	for _, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 || v > 255 || p == "" {
			return false
		}
	}
	return true
}

var oracleClients = []netip.Addr{
	netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.200"), netip.MustParseAddr("198.51.100.7"),
	netip.MustParseAddr("10.1.2.3"), netip.MustParseAddr("10.200.0.1"), netip.MustParseAddr("203.0.113.9"),
	netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db9::1"),
}

func ruleAllows(r FolderRule, ip netip.Addr) bool {
	in := false
	for _, n := range r.Hosts.Networks {
		if netip.MustParsePrefix(n).Contains(ip) {
			in = true
		}
	}
	switch r.Hosts.Kind {
	case HostsAll:
		return true
	case HostsOnly:
		return in
	case HostsExcept:
		return !in
	}
	return false
}

// bareDenyAll reports a file whose only directives are Deny from all,
// Order and Options, with no section: Apache closes such a folder to every
// client whatever the order.
func bareDenyAll(f *File) bool {
	deny := false
	for _, n := range f.Nodes {
		switch {
		case n.Kind == KindComment:
		case n.Kind == KindSection:
			return false
		case strings.EqualFold(n.Name, "deny") && len(n.Args) == 2 && strings.EqualFold(n.Args[0], "from") && strings.EqualFold(n.Args[1], "all"):
			deny = true
		case strings.EqualFold(n.Name, "order"), strings.EqualFold(n.Name, "options"):
		default:
			return false
		}
	}
	return deny
}

// checkOracle fails when the converter's rule for data is more open than
// Apache for any sample client, or when a bare deny-all is not closed.
func checkOracle(t *testing.T, data []byte, rule *FolderRule) {
	t.Helper()
	f, err := Parse(data)
	if err != nil || rule == nil {
		return
	}
	if bareDenyAll(f) && (rule.Hosts.Kind != HostsNone || rule.Open()) {
		t.Fatalf("a bare Deny from all came out as %+v: %q", rule, data)
	}
	for _, ip := range oracleClients {
		apache, ok := apacheAllows(f, ip)
		if ok && ruleAllows(*rule, ip) && !apache {
			t.Fatalf("the rule %+v lets %s in, Apache does not: %q", rule, ip, data)
		}
	}
}

func TestOracleAgreesOnPatterns(t *testing.T) {
	for _, text := range []string{
		"Deny from all\n", "Order Allow,Deny\n", "Order Deny,Allow\nDeny from all\nAllow from 192.0.2.0/24\n",
		"Order Allow,Deny\nAllow from all\nDeny from 203.0.113.0/24\n", "Require ip 10.1 2001:db8::/32\n",
		"Require all denied\n", "Deny from 203.0.113.9\n", "Order Allow,Deny\nAllow from 10\n",
	} {
		c := convertText(t, "/p/", text)
		if c.Rule == nil {
			t.Fatalf("%q refused: %s", text, c.Refused)
		}
		f, _ := Parse([]byte(text))
		for _, ip := range oracleClients {
			apache, ok := apacheAllows(f, ip)
			if !ok || apache != ruleAllows(*c.Rule, ip) {
				t.Errorf("%q for %s: rule %v, Apache %v (ok %v)", text, ip, ruleAllows(*c.Rule, ip), apache, ok)
			}
		}
	}
}

// apacheClosesName is a second, independent model of Apache 2.4's <Files>
// handling, written from server/core.c (filesection) and server/request.c
// (ap_file_walk) rather than from convert.go: <Files name> compares the
// file's name whole, a wildcard name with fnmatch, <FilesMatch re> and
// <Files ~ re> search the name for re; every section that matches applies
// in file order, and a later one's access lines replace an earlier one's.
// It reads files of top-level comments and such sections holding Require
// all, Order, Allow from all and Deny from all (inside <IfModule
// [!]mod_authz_core.c>, read as Apache 2.4), and declines (ok false)
// anything else.
func apacheClosesName(f *File, name string) (closed, ok bool) {
	for _, n := range f.Nodes {
		switch {
		case n.Kind == KindComment:
		case n.Kind == KindSection && (strings.EqualFold(n.Name, "Files") || strings.EqualFold(n.Name, "FilesMatch")):
			match, ok := oracleSectionMatches(n, name)
			if !ok {
				return false, false
			}
			if !match {
				continue
			}
			verdict, set, ok := oracleSectionCloses(n.Children)
			if !ok {
				return false, false
			}
			if set {
				closed = verdict
			}
		default:
			return false, false
		}
	}
	return closed, true
}

func oracleSectionMatches(n *Node, name string) (bool, bool) {
	expr := ""
	switch {
	case strings.EqualFold(n.Name, "Files") && len(n.Args) == 1:
		if strings.ContainsAny(n.Args[0], "*?[") {
			m, err := path.Match(n.Args[0], name)
			return m, err == nil
		}
		return n.Args[0] == name, true
	case strings.EqualFold(n.Name, "Files") && len(n.Args) == 2 && n.Args[0] == "~":
		expr = n.Args[1]
	case strings.EqualFold(n.Name, "FilesMatch") && len(n.Args) == 1:
		expr = n.Args[0]
	default:
		return false, false
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return false, false
	}
	return re.MatchString(name), true
}

// oracleSectionCloses reads one section's access lines as Apache 2.4 with
// the default Satisfy All: mod_access_compat (Order, Deny from all, Allow
// from all) and mod_authz_core (Require all) must both admit the client.
func oracleSectionCloses(nodes []*Node) (closed, set, ok bool) {
	compat, allowThenDeny, denyAll, allowAll := false, false, false, false
	authz, denied := false, false
	var walk func([]*Node) bool
	walk = func(nodes []*Node) bool {
		for _, n := range nodes {
			args := n.Args
			switch {
			case n.Kind == KindComment:
			case n.Kind == KindSection && strings.EqualFold(n.Name, "IfModule") && len(args) == 1 && authzCoreNames[args[0]]:
				if !walk(n.Children) {
					return false
				}
			case n.Kind == KindSection && strings.EqualFold(n.Name, "IfModule") && len(args) == 1 && authzCoreNames[strings.TrimPrefix(args[0], "!")]:
			case n.Kind == KindSection:
				return false
			case strings.EqualFold(n.Name, "Order") && len(args) == 1:
				compat, allowThenDeny = true, strings.EqualFold(args[0], "allow,deny")
			case strings.EqualFold(n.Name, "Deny") && len(args) == 2 && strings.EqualFold(args[1], "all"):
				compat, denyAll = true, true
			case strings.EqualFold(n.Name, "Allow") && len(args) == 2 && strings.EqualFold(args[1], "all"):
				compat, allowAll = true, true
			case strings.EqualFold(n.Name, "Require") && len(args) == 2 && strings.EqualFold(args[0], "all"):
				authz, denied = true, strings.EqualFold(args[1], "denied")
			default:
				return false
			}
		}
		return true
	}
	if !walk(nodes) {
		return false, false, false
	}
	compatCloses := compat && ((allowThenDeny && (denyAll || !allowAll)) || (!allowThenDeny && denyAll && !allowAll))
	return compatCloses || (authz && denied), compat || authz, true
}

// oracleNames are the file names the names check asks about, beside each
// name a rule lists and a name with each ending it lists.
var oracleNames = []string{
	"wp-config.php", "xmlrpc.php", ".user.ini", ".htaccess", "readme.html", "readme.txt", "index.php",
	"index.html", "style.css", "dump.sql", "a.bak", "index.php~", "error_log", "debug.log", "x.php.save",
	"wp-config.php.bak", "my-wp-config.php", "a.sql.gz", "secret.json",
}

// checkNamesOracle fails when the converter's names differ from Apache's
// for a sample name, in a file the model reads: the converter claims the
// exact set.
func checkNamesOracle(t *testing.T, data []byte, rule *FolderRule) {
	t.Helper()
	f, err := Parse(data)
	if err != nil || rule == nil {
		return
	}
	names := slices.Clone(oracleNames)
	if rule.Deny != nil {
		names = append(names, rule.Deny.Exact...)
		for _, e := range rule.Deny.Endings {
			names = append(names, "x"+e, e, e+"x")
		}
		for _, n := range rule.Deny.Exact {
			names = append(names, "x"+n, n+"x")
		}
	}
	for _, name := range names {
		apache, ok := apacheClosesName(f, name)
		if !ok {
			return
		}
		ours := rule.Deny != nil && rule.Deny.Match(name)
		if apache != ours {
			t.Fatalf("%q: rule closes it %v, Apache %v: %q", name, ours, apache, data)
		}
	}
}

func TestNamesOracleAgreesOnPatterns(t *testing.T) {
	for _, text := range []string{
		"<files wp-config.php>\norder allow,deny\ndeny from all\n</files>\n",
		"<Files xmlrpc.php>\nOrder Deny,Allow\nDeny from all\n</Files>\n",
		"<Files \".user.ini\">\n<IfModule mod_authz_core.c>\n\tRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n\tOrder deny,allow\n\tDeny from all\n</IfModule>\n</Files>\n",
		"<FilesMatch \"^(wp-config\\.php|readme\\.(html|txt))$\">\nRequire all denied\n</FilesMatch>\n",
		"<FilesMatch \"\\.(sql|bak|log)$\">\nRequire all denied\n</FilesMatch>\n",
		"<FilesMatch \"wp-config\\.php$\">\nRequire all denied\n</FilesMatch>\n",
		"<Files ~ \"(~|\\.save)$\">\nDeny from all\n</Files>\n",
		"<Files *.php>\ndeny from all\n</Files>\n",
		"<Files a.php>\nOrder Allow,Deny\n</Files>\n",
	} {
		r := ClassifyFile(".htaccess", "/", []byte(text))
		if r.Conversion == nil || r.Conversion.Rule == nil || r.Conversion.Rule.Deny == nil {
			t.Fatalf("%q: %+v", text, r.Conversion)
		}
		f, _ := Parse([]byte(text))
		if _, ok := apacheClosesName(f, "x"); !ok {
			t.Fatalf("the model declines %q", text)
		}
		checkNamesOracle(t, []byte(text), r.Conversion.Rule)
	}
}
