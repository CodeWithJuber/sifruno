package hostaccounts

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"sifruno/internal/cpsource"
	"sifruno/internal/sitesource"
)

// serverDump is nginx -T on a plain nginx server: a WordPress site behind
// an http-to-https block, and an application nginx proxies to.
const serverDump = `# configuration file /etc/nginx/nginx.conf:
http { include /etc/nginx/conf.d/*.conf; }
# configuration file /etc/nginx/conf.d/blog.conf:
server {
    listen 80;
    server_name blog.example.test www.blog.example.test;
    root /var/www/blog;
    location / { try_files $uri $uri/ /index.php?$args; }
    location ~ \.php$ { fastcgi_pass unix:/run/php-fpm/www.sock; include fastcgi_params; }
    location /private/ { deny all; }
    location = /old-page { return 301 https://blog.example.test/new-page; }
}
# configuration file /etc/nginx/conf.d/app.conf:
server {
    listen 80;
    server_name app.example.test;
    location / { proxy_pass http://127.0.0.1:3000; }
}
`

const serverWPConfig = "<?php\ndefine('DB_NAME', 'wordpress');\ndefine('DB_USER', 'wpuser');\ndefine('DB_PASSWORD', 'fixture-db-secret');\ndefine('DB_HOST', 'localhost');\n$table_prefix = 'wp_';\n"

// serverStat is stat over the folders on the way to /var/www/blog.
const serverStat = "/var|directory|root|0|755\n/var/www|directory|root|0|755\n/var/www/blog|directory|nginx|995|755\n"

// serverUser is the old server's database answer for wpuser: its password
// hash and a grant on db.
func serverUser(hash, db string) string {
	return "sifruno-user\twpuser\nCREATE USER `wpuser`@`localhost` IDENTIFIED BY PASSWORD '" + hash + "'\nsifruno-grant\twpuser\t" + db + "\t" + strings.TrimSuffix(strings.Repeat("Y\t", 18), "\t") + "\n"
}

// serverHash is the mysql_native_password hash of the password config
// gives, as the broker makes it.
func serverHash(t *testing.T, config string) string {
	t.Helper()
	c, err := sitesource.ParseWPConfig([]byte(config))
	if err != nil {
		t.Fatal(err)
	}
	return c.NativeHash()
}

// serverMigrate answers the fixed commands of another Linux server.
func serverMigrate(t *testing.T) (*store, *fakeMigrate, Migration) {
	t.Helper()
	s, f, _ := migrateStore(t)
	owner := sitesource.Owner{Name: "nginx", UID: 995}
	stat, _ := sitesource.StatCommand("/var/www/blog")
	wp, _ := sitesource.WPConfigCommand("/var/www/blog", owner)
	du, _ := sitesource.DiskCommand("/var/www/blog")
	cron, _ := sitesource.CrontabCommand(owner)
	for command, answer := range map[string]string{
		sitesource.NginxDumpCommand:    serverDump,
		sitesource.ApacheVhostsCommand: "",
		sitesource.FPMPoolsCommand:     "== /etc/php-fpm.d/www.conf\nlisten = /run/php-fpm/www.sock\n",
		sitesource.FPMVersionsCommand:  "== /usr/sbin/php-fpm PHP 8.2.13 (fpm-fcgi) (built: Nov 21 2023)\n",
		stat:                           serverStat,
		cpsource.SQLCommand():          serverUser(serverHash(t, serverWPConfig), "wordpress"),
		wp:                             serverWPConfig,
		du:                             "12\t/var/www/blog\n",
		cron:                           "*/10 * * * * php /var/www/blog/wp-cron.php\n",
	} {
		f.answers[command] = answer
	}
	m, err := s.openMigration(context.Background(), MigrationOpenInput{Host: "source.example.test", Port: 22, Via: ViaServer, Reason: "Move a website here"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	if m.Via != ViaServer || !strings.Contains(m.InstallCommand, ">> /root/.ssh/authorized_keys") {
		t.Fatalf("opened: %+v", m)
	}
	if m, err = s.pinMigrationHostKey(context.Background(), m.ID, MigrationPinInput{Fingerprint: m.HostKeys[0].Fingerprint, Reason: "Fingerprint checked"}, "test operator"); err != nil {
		t.Fatal(err)
	}
	return s, f, m
}

func TestServerSitesListWhatMovesBeforeAnythingIsMade(t *testing.T) {
	s, f, m := serverMigrate(t)
	ctx := context.Background()
	sites, err := s.migrationSites(ctx, m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 2 || sites[0].Domain != "app.example.test" || sites[1].Domain != "blog.example.test" {
		t.Fatalf("sites = %+v", sites)
	}
	blog := sites[1]
	if !blog.Movable || blog.Account != "blog" || blog.Owner != "nginx" || !blog.WordPress || blog.Database != "wordpress" || blog.PHP != "8.2" || blog.PHPSource != "php8.2-fpm" || blog.DocRoot != "/var/www/blog" || !blog.WWW {
		t.Fatalf("blog = %+v", blog)
	}
	app := sites[0]
	if app.Movable || len(app.Refused) == 0 || !strings.Contains(app.Refused[0].Text, "proxy_pass") || app.Refused[0].Where != "/etc/nginx/conf.d/app.conf line 4" {
		t.Fatalf("app = %+v", app)
	}
	raw, _ := json.Marshal(sites)
	if strings.Contains(string(raw), "fixture-db-secret") || strings.Contains(string(raw), "*") && strings.Contains(string(raw), (sitesource.WPConfig{Password: "fixture-db-secret"}).NativeHash()) {
		t.Fatal("the listing holds the database password or its hash")
	}
	if slices.Contains(f.commands, cpsource.ListAccountsCommand()) {
		t.Fatal("a cPanel tool ran on another Linux server")
	}
	if _, err := s.migrationAccounts(ctx, m.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("accounts of another Linux server: %v", err)
	}
}

func TestServerPlanCarriesTheDatabaseUnderTheAccountsPrefix(t *testing.T) {
	s, f, m := serverMigrate(t)
	ctx := context.Background()
	plan, err := s.planMigration(ctx, m.ID, MigrationPlanInput{Username: "blog", Site: "blog.example.test", Reason: "Move a website here"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Domain != "blog.example.test" || plan.Username != "blog" || plan.Tier != "native" || plan.DiskUsedMiB != 12 || plan.PHPSource != "php8.2-fpm" || plan.ClientAddress != "203.0.113.5" {
		t.Fatalf("plan = %+v", plan)
	}
	hash := (sitesource.WPConfig{Password: "fixture-db-secret"}).NativeHash()
	if len(plan.Databases) != 1 || plan.Databases[0].Name != "blog_wordpress" || len(plan.Users) != 1 || plan.Users[0].Name != "blog_wpuser" || plan.Users[0].Hash != hash ||
		plan.Users[0].Grants[0].Database != "blog_wordpress" || !slices.Equal(plan.Users[0].Grants[0].Privileges, []string{"ALL PRIVILEGES"}) {
		t.Fatalf("database = %+v %+v", plan.Databases, plan.Users)
	}
	if len(plan.Cron) != 1 || plan.Cron[0].Command != "php /var/www/blog/wp-cron.php" {
		t.Fatalf("cron = %+v", plan.Cron)
	}
	if plan.Site == nil || plan.Site.DocRoot != "/var/www/blog" || plan.Site.Owner != "nginx" || plan.Site.Database != "wordpress" || !plan.Site.WordPress {
		t.Fatalf("site = %+v", plan.Site)
	}
	notes := ""
	for _, item := range plan.NotCarried {
		notes += item.Text + "\n"
	}
	for _, want := range []string{"becomes blog_wordpress", "left out, as nginx never read them: old/.htaccess", "Email, DNS and FTP accounts stay"} {
		if !strings.Contains(notes, want) {
			t.Errorf("not carried lacks %q:\n%s", want, notes)
		}
	}
	if raw, _ := json.Marshal(plan); strings.Contains(string(raw), "fixture-db-secret") {
		t.Fatal("the plan holds the database password")
	}
	if !slices.Contains(f.files, "preflight /var/www/blog as nginx") {
		t.Fatalf("preflight = %v", f.files)
	}
	// A site whose rules are refused answers a plan that is not Native,
	// line by line, and nothing is copied.
	plan, err = s.planMigration(ctx, m.ID, MigrationPlanInput{Username: "app", Site: "app.example.test", Reason: "Move a website here"}, "test operator")
	if err != nil || plan.Tier == "native" || len(plan.TierRefusals) == 0 || !strings.Contains(plan.TierRefusals[0], "app.conf line 4: proxy_pass") || len(plan.TierFix) == 0 {
		t.Fatalf("refused plan = %+v %v", plan, err)
	}
	var failed *MigrationError
	if _, err = s.planMigration(ctx, m.ID, MigrationPlanInput{Username: "gone", Site: "gone.example.test", Reason: "x"}, "test operator"); !errors.As(err, &failed) || failed.Step != "account_missing" {
		t.Fatalf("a domain the server does not name: %v", err)
	}
	if _, err = s.planMigration(ctx, m.ID, MigrationPlanInput{Username: "blog", Reason: "x"}, "test operator"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no site named: %v", err)
	}
}

func TestServerCopyUsesTheAccountsDomainAndTheDatabaseItNames(t *testing.T) {
	s, f, m := serverMigrate(t)
	ctx := context.Background()
	a := createFixtureNamed(t, s, "blog", "blog.example.test")
	if _, err := s.migrateFiles(ctx, a.ID, MigrateFilesInput{Migration: m.ID, ExpectedRevision: a.Revision, Reason: "Move a website here"}, "test operator"); err != nil {
		t.Fatal(err)
	}
	want := `/var/www/blog as nginx -> blog (12 MiB, rules ["" "private"], wp-config blog_wordpress blog_wpuser, home /nonexistent/sifruno-no-home)`
	if !slices.Contains(f.files, want) {
		t.Fatalf("files = %v", f.files)
	}
	if _, err := s.migrateDatabase(ctx, a.ID, MigrateDatabaseInput{Migration: m.ID, Database: "blog_wordpress", ExpectedRevision: a.Revision, Reason: "Move a website here"}, "test operator"); err != nil || len(f.databases) != 1 || !strings.HasPrefix(f.databases[0], "wordpress into blog_wordpress as ") {
		t.Fatalf("database: %v %v", err, f.databases)
	}
	var failed *MigrationError
	if _, err := s.migrateDatabase(ctx, a.ID, MigrateDatabaseInput{Migration: m.ID, Database: "blog_other", ExpectedRevision: a.Revision, Reason: "x"}, "test operator"); !errors.As(err, &failed) || failed.Step != "database" {
		t.Fatalf("a database wp-config.php does not name: %v", err)
	}
	// An account whose domain the old server does not serve gets nothing.
	other := createFixtureNamed(t, s, "otheracct", "other.example.test")
	if _, err := s.migrateFiles(ctx, other.ID, MigrateFilesInput{Migration: m.ID, ExpectedRevision: other.Revision, Reason: "x"}, "test operator"); !errors.As(err, &failed) || failed.Step != "account_missing" {
		t.Fatalf("another domain: %v", err)
	}
	// Nor does one whose site is refused.
	app := createFixtureNamed(t, s, "appacct", "app.example.test")
	if _, err := s.migrateFiles(ctx, app.ID, MigrateFilesInput{Migration: m.ID, ExpectedRevision: app.Revision, Reason: "x"}, "test operator"); !errors.As(err, &failed) || failed.Step != "tier" {
		t.Fatalf("a refused site: %v", err)
	}
}

func TestServerWithoutAWebServerSaysSo(t *testing.T) {
	s, f, m := serverMigrate(t)
	f.answers[sitesource.NginxDumpCommand] = ""
	_, err := s.migrationSites(context.Background(), m.ID)
	var failed *MigrationError
	if !errors.As(err, &failed) || failed.Step != "source" || !strings.Contains(failed.Detail, "neither nginx") {
		t.Fatalf("no web server: %v", err)
	}
	f.answers[sitesource.NginxDumpCommand] = serverDump
	f.fails = map[string]fakeFailure{sitesource.NginxDumpCommand: {out: "nginx: [emerg] unknown directive \"bogus\" in /etc/nginx/conf.d/x.conf:3", code: 1}}
	if _, err = s.migrationSites(context.Background(), m.ID); !errors.As(err, &failed) || failed.Step != "source" || !strings.Contains(failed.Output, "unknown directive") {
		t.Fatalf("a broken nginx: %v", err)
	}
}

// A database moves only when the site proves it is its own: wp-config.php
// names a website's database, and the old server's user it names has the
// password it gives and a grant on it. Otherwise the site moves without it.
func TestServerDatabaseMovesOnlyWhenTheSiteOwnsIt(t *testing.T) {
	hash := serverHash(t, serverWPConfig)
	other := serverHash(t, strings.Replace(serverWPConfig, "fixture-db-secret", "fixture-db-other", 1))
	wp, _ := sitesource.WPConfigCommand("/var/www/blog", sitesource.Owner{Name: "nginx", UID: 995})
	for _, c := range []struct {
		name, config, users, want string
		fails                     bool
	}{
		{"the server's own database", strings.Replace(serverWPConfig, "'wordpress'", "'MySQL'", 1), serverUser(hash, "wordpress"), "the database server's own database", false},
		{"another password", serverWPConfig, serverUser(other, "wordpress"), "is not the old server's password", false},
		{"a grant on another database", serverWPConfig, serverUser(hash, "bob_shop"), "has no grant on the database wordpress", false},
		{"no such user", serverWPConfig, "", "did not answer for the user wpuser", true},
		{"another sign-in method", serverWPConfig, "sifruno-user\twpuser\nCREATE USER `wpuser`@`localhost` IDENTIFIED VIA unix_socket\n", "signs in another way", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, f, m := serverMigrate(t)
			ctx := context.Background()
			f.answers[wp] = c.config
			f.answers[cpsource.SQLCommand()] = c.users
			if c.fails {
				f.fails = map[string]fakeFailure{cpsource.SQLCommand(): {out: "ERROR 1141 (42000) at line 2: There is no such grant defined for user 'wpuser' on host 'localhost'", code: 1}}
			}
			plan, err := s.planMigration(ctx, m.ID, MigrationPlanInput{Username: "blog", Site: "blog.example.test", Reason: "Move a website here"}, "test operator")
			if err != nil {
				t.Fatal(err)
			}
			notes := ""
			for _, item := range plan.NotCarried {
				if item.Part == "database" {
					notes += item.Text + "\n"
				}
			}
			if len(plan.Databases) != 0 || len(plan.Users) != 0 || !strings.Contains(notes, c.want) {
				t.Fatalf("databases %+v users %+v, notes:\n%s", plan.Databases, plan.Users, notes)
			}
			a := createFixtureNamed(t, s, "blog", "blog.example.test")
			var failed *MigrationError
			if _, err := s.migrateDatabase(ctx, a.ID, MigrateDatabaseInput{Migration: m.ID, Database: "blog_wordpress", ExpectedRevision: a.Revision, Reason: "x"}, "test operator"); !errors.As(err, &failed) || failed.Step != "database" || len(f.databases) != 0 {
				t.Fatalf("copied a database the site does not own: %v %v", err, f.databases)
			}
		})
	}
}

// A document root reached through a folder another user could swap for a
// link, or a root-owned one holding what another user can change, is
// refused before anything is read from it as root.
func TestServerRefusesAPathAnotherUserCouldRedirect(t *testing.T) {
	stat, _ := sitesource.StatCommand("/var/www/blog")
	tree, _ := sitesource.RootTreeCommand("/var/www/blog")
	const rootOwned = "/var|directory|root|0|755\n/var/www|directory|root|0|755\n/var/www/blog|directory|root|0|755\n"
	for _, c := range []struct {
		name, stat, tree, want string
	}{
		{"a link on the way", "/var|directory|root|0|755\n/var/www|symbolic link|root|0|777\n/var/www/blog|directory|nginx|995|755\n", "", "is a link or not a folder"},
		{"a folder others may write", "/var|directory|root|0|755\n/var/www|directory|root|0|777\n/var/www/blog|directory|nginx|995|755\n", "", "The folder /var/www on the way"},
		{"a root-owned root another user can change", rootOwned, "/var/www/blog/uploads\n", "but /var/www/blog/uploads in it can be changed by another user"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, f, m := serverMigrate(t)
			f.answers[stat] = c.stat
			f.answers[tree] = c.tree
			sites, err := s.migrationSites(context.Background(), m.ID)
			if err != nil {
				t.Fatal(err)
			}
			blog := sites[1]
			if blog.Movable || len(blog.Refused) == 0 || !strings.Contains(blog.Refused[len(blog.Refused)-1].Text, c.want) {
				t.Fatalf("blog = %+v", blog)
			}
			for _, command := range f.commands {
				if strings.Contains(command, "wp-config.php") || strings.Contains(command, "/usr/bin/du ") {
					t.Fatalf("%q ran on a refused path", command)
				}
			}
		})
	}
	// A root-owned root nobody else can change is read as root.
	s, f, m := serverMigrate(t)
	f.answers[stat] = rootOwned
	f.answers[tree] = ""
	wp, _ := sitesource.WPConfigCommand("/var/www/blog", sitesource.Owner{Name: "root", UID: 0})
	f.answers[wp] = serverWPConfig
	sites, err := s.migrationSites(context.Background(), m.ID)
	if err != nil || !sites[1].Movable || sites[1].Owner != "root" || sites[1].Database != "wordpress" {
		t.Fatalf("a root-owned root: %+v %v", sites, err)
	}
}
