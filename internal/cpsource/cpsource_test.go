package cpsource

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// The shapes below follow the example responses on cPanel's API pages
// cited in cpsource.go; values are made up.

const listaccts = `{"data":{"acct":[
 {"user":"shopone","domain":"shop.example.test","diskused":"14M","disklimit":"unlimited","suspended":0,"ip":"192.168.0.128","partition":"home","plan":"default"},
 {"user":"staff","domain":"staff.example.test","diskused":"3M","disklimit":"500M","suspended":0},
 {"user":"old1","domain":"old.example.test","diskused":"1M","disklimit":"unlimited","suspended":1},
 {"user":"Bad-Name","domain":"bad.example.test","diskused":"1M","disklimit":"unlimited","suspended":0}
]},"metadata":{"command":"listaccts","reason":"OK","result":1,"version":1}}`

func TestParseAccounts(t *testing.T) {
	items, err := ParseAccounts([]byte(listaccts))
	if err != nil || len(items) != 4 {
		t.Fatalf("parse: %v %v", items, err)
	}
	if items[0] != (Account{User: "shopone", Domain: "shop.example.test", DiskUsedMiB: 14}) {
		t.Errorf("first: %+v", items[0])
	}
	if items[1].DiskLimitMiB != 500 || items[1].Problem != "" {
		t.Errorf("limit: %+v", items[1])
	}
	if !items[2].Suspended || items[2].Problem == "" {
		t.Errorf("a suspended account must not be movable: %+v", items[2])
	}
	if items[3].Problem == "" {
		t.Errorf("a name the broker refuses must not be movable: %+v", items[3])
	}
	for _, bad := range []string{``, `{`, `{"data":{"acct":[{"user":"a","domain":"b","diskused":"lots"}]}}`} {
		if items, err := ParseAccounts([]byte(bad)); err == nil && (len(items) == 0 || items[0].Problem == "") {
			t.Errorf("%q: read as a movable account", bad)
		}
	}
}

func TestCommandsTakeOnlyPlainNames(t *testing.T) {
	for _, user := range []string{"", "a", "root;id", "a b", "UPPER", "a$(id)", "-l"} {
		if _, err := DatabasesCommand(user); err == nil {
			t.Errorf("%q accepted", user)
		}
		if _, err := CrontabCommand(user); err == nil {
			t.Errorf("%q accepted", user)
		}
	}
	for _, domain := range []string{"example", "a..b", "x.test;id", "-x.test", "X.test"} {
		if _, err := DomainUserDataCommand(domain); err == nil {
			t.Errorf("%q accepted", domain)
		}
	}
	for _, db := range []string{"", "a-b", "a b", "a`b", strings.Repeat("d", 65)} {
		if _, err := DumpCommand(db); err == nil {
			t.Errorf("%q accepted", db)
		}
	}
	if _, err := RemoveKeyCommand("../x"); err == nil {
		t.Error("a bad migration id accepted")
	}
	got, err := DatabasesCommand("shopone")
	if err != nil || got != "/usr/local/cpanel/bin/uapi --output=json --user=shopone Mysql list_databases" {
		t.Errorf("command: %q %v", got, err)
	}
	remove, _ := RemoveKeyCommand(strings.Repeat("a", 32))
	if remove != `/usr/bin/sed -i -e '/^restrict ssh-ed25519 [A-Za-z0-9+\/=]* sifruno-migration-`+strings.Repeat("a", 32)+`$/d' /root/.ssh/authorized_keys` {
		t.Errorf("remove: %q", remove)
	}
}

// TestParseClientAddress: the source's SSH_CONNECTION gives the address it
// sees this server come from, as one plain address, or nothing.
func TestParseClientAddress(t *testing.T) {
	if ClientAddressCommand() != `printf '%s\n' "$SSH_CONNECTION"` {
		t.Fatalf("command %q", ClientAddressCommand())
	}
	for out, want := range map[string]string{
		"203.0.113.5 51234 198.51.100.7 22\n":    "203.0.113.5",
		"2001:db8::5 51234 2001:db8::7 22\n":     "2001:db8::5",
		"2001:0db8::0005 51234 2001:db8::7 22\n": "2001:db8::5",
	} {
		if got, err := ParseClientAddress([]byte(out)); err != nil || got != want {
			t.Errorf("%q: %q %v", out, got, err)
		}
	}
	for _, bad := range []string{
		"", "\n", "203.0.113.5 51234 198.51.100.7 22", "203.0.113.5 51234 198.51.100.7 22\n\n",
		"203.0.113.5 51234 198.51.100.7\n", "203.0.113.5 51234 198.51.100.7 22 x\n", "203.0.113.5  51234 198.51.100.7 22\n",
		"203.0.113.0/24 51234 198.51.100.7 22\n", "source 51234 198.51.100.7 22\n", "::ffff:203.0.113.5 51234 198.51.100.7 22\n",
		"fe80::5%eth0 51234 fe80::7%eth0 22\n", "203.0.113.5 0 198.51.100.7 22\n", "203.0.113.5 051234 198.51.100.7 22\n",
		"203.0.113.5 51234 198.51.100.7 65536\n", "203.0.113.5\t51234 198.51.100.7 22\n",
	} {
		if got, err := ParseClientAddress([]byte(bad)); err == nil {
			t.Errorf("%q read as %q", bad, got)
		}
	}
}

func TestParseSite(t *testing.T) {
	out := `{"data":{"userdata":{"documentroot":"/home/shopone/public_html","servername":"shop.example.test","serveralias":"www.shop.example.test parked.example.test","user":"shopone","homedir":"/home/shopone","ip":"10.0.0.1","port":80}},"metadata":{"command":"domainuserdata","result":1}}`
	site, err := ParseSite([]byte(out), "shopone", "shop.example.test")
	if err != nil || site.HomeDir != "/home/shopone" || !site.WWW || !reflect.DeepEqual(site.Aliases, []string{"parked.example.test"}) {
		t.Fatalf("site: %+v %v", site, err)
	}
	other := strings.Replace(out, `"documentroot":"/home/shopone/public_html"`, `"documentroot":"/home/shopone/sub"`, 1)
	if _, err := ParseSite([]byte(other), "shopone", "shop.example.test"); !errors.Is(err, ErrNotPublicHTML) {
		t.Errorf("a site outside public_html: %v", err)
	}
	for _, bad := range []string{
		strings.Replace(out, `"user":"shopone"`, `"user":"staff"`, 1),
		strings.Replace(out, `"homedir":"/home/shopone"`, `"homedir":"/home/../shopone"`, 1),
	} {
		if _, err := ParseSite([]byte(bad), "shopone", "shop.example.test"); err == nil {
			t.Errorf("accepted: %s", bad)
		}
	}
}

func TestParseVhostPHPAndMap(t *testing.T) {
	out := `{"data":{"versions":[{"account":"shopone","documentroot":"/home/shopone/public_html","homedir":"/home/shopone","main_domain":1,"php_fpm":0,"version":"ea-php81","vhost":"shop.example.test"}]},"metadata":{"command":"php_get_vhost_versions","result":1}}`
	v, err := ParseVhostPHP([]byte(out), "shopone", "shop.example.test")
	if err != nil || v != "ea-php81" {
		t.Fatalf("version: %q %v", v, err)
	}
	if _, err := ParseVhostPHP([]byte(out), "staff", "shop.example.test"); err == nil {
		t.Error("another account's vhost read as this site's")
	}
	for source, want := range map[string]struct {
		v     string
		exact bool
	}{"ea-php81": {"8.1", true}, "ea-php84": {"8.4", true}, "alt-php82": {"8.2", true}, "ea-php74": {"8.1", false}, "ea-php56": {"8.1", false}, "ea-php85": {"8.4", false}, "inherit": {"8.3", false}, "": {"8.3", false}} {
		if v, exact := PHPVersion(source); v != want.v || exact != want.exact {
			t.Errorf("%q: %s %v", source, v, exact)
		}
	}
}

func TestParseDatabasesAndUsers(t *testing.T) {
	dbs := `{"apiversion":3,"func":"list_databases","module":"Mysql","result":{"data":[{"database":"shopone_wp","disk_usage":673,"users":["shopone_wpuser"]}],"errors":null,"messages":null,"metadata":{"transformed":1},"status":1,"warnings":null}}`
	items, err := ParseDatabases([]byte(dbs), "shopone")
	if err != nil || !reflect.DeepEqual(items, []Database{{Name: "shopone_wp", Users: []string{"shopone_wpuser"}}}) {
		t.Fatalf("databases: %+v %v", items, err)
	}
	if _, err := ParseDatabases([]byte(strings.Replace(dbs, `"shopone_wp"`, `"wordpress"`, 1)), "shopone"); !errors.Is(err, ErrUnprefixed) {
		t.Errorf("an unprefixed database: %v", err)
	}
	if _, err := ParseDatabases([]byte(strings.Replace(dbs, `"status":1`, `"status":0`, 1)), "shopone"); err == nil {
		t.Error("a failed call read as an answer")
	}
	users := `{"apiversion":3,"func":"list_users","module":"Mysql","result":{"data":[{"databases":["shopone_wp"],"shortuser":"wpuser","user":"shopone_wpuser"}],"errors":null,"status":1}}`
	names, err := ParseDatabaseUsers([]byte(users), "shopone")
	if err != nil || !reflect.DeepEqual(names, []string{"shopone_wpuser"}) {
		t.Fatalf("users: %v %v", names, err)
	}
}

func TestParseUsers(t *testing.T) {
	hash := "*" + strings.Repeat("A1", 20)
	sql, err := UsersSQL([]string{"shopone_wpuser", "shopone_ro"})
	if err != nil || !strings.Contains(sql, "SHOW CREATE USER 'shopone_wpuser'@'localhost'") || !strings.Contains(sql, "FROM mysql.db WHERE Host='localhost'") {
		t.Fatalf("sql: %s %v", sql, err)
	}
	if _, err := UsersSQL([]string{"x'; DROP"}); err == nil {
		t.Error("a name with a quote accepted")
	}
	all := strings.TrimSuffix(strings.Repeat("Y\t", 18), "\t")
	some := "Y\tN\tN\tN\tN\tN\tN\tN\tN\tN\tN\tN\tN\tN\tN\tN\tN\tN"
	out := "sifruno-user\tshopone_wpuser\n" +
		"CREATE USER `shopone_wpuser`@`localhost` IDENTIFIED BY PASSWORD '" + hash + "'\n" +
		"sifruno-user\tshopone_ro\n" +
		"CREATE USER `shopone_ro`@`localhost` IDENTIFIED VIA ed25519 USING 'xyz'\n" +
		"sifruno-grant\tshopone_wpuser\tshopone\\_wp\t" + all + "\n" +
		"sifruno-grant\tshopone_ro\tshopone\\_wp\t" + some + "\n" +
		"sifruno-grant\tshopone_ro\tshopone\\_%\t" + some + "\n"
	items, skipped, err := ParseUsers([]byte(out), []string{"shopone_wpuser", "shopone_ro"}, []string{"shopone_wp"})
	if err != nil {
		t.Fatal(err)
	}
	if items[0].Hash != hash || items[0].Problem != "" || !reflect.DeepEqual(items[0].Grants, []Grant{{Database: "shopone_wp", Privileges: []string{"ALL PRIVILEGES"}}}) {
		t.Errorf("wpuser: %+v", items[0])
	}
	if items[1].Hash != "" || items[1].Problem == "" || !reflect.DeepEqual(items[1].Grants, []Grant{{Database: "shopone_wp", Privileges: []string{"SELECT"}}}) {
		t.Errorf("ro: %+v", items[1])
	}
	if len(skipped) != 1 {
		t.Errorf("the pattern grant must be left out and listed: %v", skipped)
	}
	mysql := "sifruno-user\tshopone_wpuser\nCREATE USER `shopone_wpuser`@`localhost` IDENTIFIED WITH 'mysql_native_password' AS '" + hash + "' REQUIRE NONE\n"
	if items, _, err := ParseUsers([]byte(mysql), []string{"shopone_wpuser"}, nil); err != nil || items[0].Hash != hash {
		t.Errorf("MySQL's form: %+v %v", items, err)
	}
	if _, _, err := ParseUsers([]byte("sifruno-user\tsomeone_else\n"), []string{"shopone_wpuser"}, nil); err == nil {
		t.Error("an answer about another user was read")
	}
}

func TestCounts(t *testing.T) {
	tables, err := ParseTables([]byte("wp_options\nwp_posts\n"))
	if err != nil || len(tables) != 2 {
		t.Fatal(tables, err)
	}
	for _, bad := range []string{"bad\x01name\n", "it's\n", "back\\slash\n"} {
		if _, err := ParseTables([]byte(bad)); err == nil {
			t.Errorf("%q was read as a table name", bad)
		}
	}
	sql, err := CountsSQL("shopone_wp", []string{"wp_options", "we`ird"})
	if err != nil || !strings.Contains(sql, "FROM `shopone_wp`.`we``ird`") {
		t.Errorf("sql: %s %v", sql, err)
	}
	counts, err := ParseCounts([]byte("wp_options\t120\nwp_posts\t3\n"), tables)
	if err != nil || counts["wp_options"] != 120 || counts["wp_posts"] != 3 {
		t.Errorf("counts: %v %v", counts, err)
	}
	if _, err := ParseCounts([]byte("wp_options\t120\n"), tables); err == nil {
		t.Error("a missing table was read as counted")
	}
}

func TestParseCrontab(t *testing.T) {
	out := "# comment\nMAILTO=\"me@example.test\"\n*/15  *  * * *   /usr/local/bin/php /home/shopone/public_html/wp-cron.php >/dev/null 2>&1\n@daily /home/shopone/bin/report\n@reboot /home/shopone/bin/start\n0 3 * * *\n"
	jobs, skipped, err := ParseCrontab([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	want := []CronLine{
		{Schedule: "*/15 * * * *", Command: "/usr/local/bin/php /home/shopone/public_html/wp-cron.php >/dev/null 2>&1"},
		{Schedule: "0 0 * * *", Command: "/home/shopone/bin/report"},
	}
	if !reflect.DeepEqual(jobs, want) || len(skipped) != 3 {
		t.Errorf("jobs %+v skipped %v", jobs, skipped)
	}
	for _, s := range skipped {
		if strings.Contains(s, "/home/shopone") || strings.Contains(s, "me@example") {
			t.Errorf("a skipped line quotes what the crontab held: %q", s)
		}
	}
	// A no-break space or a Unicode space would split differently from
	// cron: the line is refused, not realigned.
	for _, odd := range []string{"*/5\u00a0* * * * php job.php\n", "0 3 * * *\u2003/bin/true\n", "0 3 * * * echo\u00a0x\n"} {
		jobs, skipped, err := ParseCrontab([]byte(odd))
		if err != nil || len(jobs) != 0 || len(skipped) != 1 {
			t.Errorf("%q: jobs %+v skipped %v %v", odd, jobs, skipped, err)
		}
	}
}

func TestInstallKeyCommand(t *testing.T) {
	id := strings.Repeat("b", 32)
	got := InstallKeyCommand("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample", id)
	// printf starts the line on a new line of its own, so a file whose
	// last line has no new line keeps that line whole.
	want := `mkdir -p /root/.ssh && chmod 700 /root/.ssh && printf '\n%s\n' 'restrict ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample sifruno-migration-` + id + `' >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys`
	if got != want {
		t.Errorf("got %q", got)
	}
}
