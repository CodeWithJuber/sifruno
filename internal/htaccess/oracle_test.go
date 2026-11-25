package htaccess

import (
	"net"
	"net/netip"
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
