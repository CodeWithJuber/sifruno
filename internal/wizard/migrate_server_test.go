package wizard

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"sifruno/internal/cpsource"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/sitemodel"
)

// serverPlan is what the broker plans for a WordPress site on a plain
// nginx server, moved into the account "blog".
func serverPlan() hostaccounts.MigrationPlan {
	return hostaccounts.MigrationPlan{
		Username: "blog", Domain: "blog.example.test", WWW: true, PHPSource: "php8.2-fpm", DiskUsedMiB: 12, Tier: "native",
		Databases: []cpsource.Database{{Name: "blog_wordpress", Users: []string{"blog_wpuser"}}},
		Users:     []cpsource.DatabaseUser{{Name: "blog_wpuser", Hash: testHash, Grants: []cpsource.Grant{{Database: "blog_wordpress", Privileges: []string{"ALL PRIVILEGES"}}}}},
		Cron:      []cpsource.CronLine{{Schedule: "*/10 * * * *", Command: "php /var/www/blog/wp-cron.php > /var/www/blog2/log"}},
		NotCarried: []sitemodel.Item{
			{Part: "mail", Text: "Email, DNS and FTP accounts stay on the old server; this moves the website's files, its database and its jobs."},
			{Part: "info", Text: "The database wordpress becomes blog_wordpress and its user wpuser becomes blog_wpuser with the same password."},
			{Part: "rule", Text: "add_header: Extra response headers (add_header) are not carried.", Where: "/etc/nginx/conf.d/blog.conf line 9"},
		},
		Site: &hostaccounts.MigrationSite{Domain: "blog.example.test", Server: "nginx", Where: "/etc/nginx/conf.d/blog.conf line 1", DocRoot: "/var/www/blog", Owner: "nginx",
			Account: "blog", PHPSource: "php8.2-fpm", PHP: "8.2", WordPress: true, Database: "wordpress", Movable: true},
	}
}

func (f *migrationFixture) migrateServer(t *testing.T, site string) (Job, error) {
	t.Helper()
	f.broker.via, f.broker.plan = hostaccounts.ViaServer, serverPlan()
	job, err := f.runner.StartMigration(context.Background(), MigrationInput{Source: sourceID, Username: "blog", Site: site}, "test operator")
	if err != nil {
		return Job{}, err
	}
	f.runner.Wait()
	done, _ := f.runner.Get(job.ID)
	return done, nil
}

func TestServerMoveCopiesUnderTheNewNames(t *testing.T) {
	f := newMigrationFixture(t)
	job, err := f.migrateServer(t, "blog.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if job.State != StateSucceeded || job.Domain != "blog.example.test" || job.Username != "blog" {
		t.Fatalf("job: %+v %+v", job, job.Error)
	}
	m := job.Migration
	if m.SourceSite != "blog.example.test" || m.SourceUser != "nginx" || !slices.Equal(m.Databases, []string{"blog_wordpress"}) || !slices.Equal(m.DatabaseUsers, []string{"blog_wpuser"}) {
		t.Fatalf("migration: %+v", m)
	}
	// Only what a person must check is a note: not the mail, not the new
	// names, which the steps say.
	if len(m.Notes) != 1 || !strings.Contains(m.Notes[0], "add_header") || !strings.Contains(m.Notes[0], "blog.conf line 9") {
		t.Fatalf("notes: %q", m.Notes)
	}
	messages := map[string]string{}
	for _, s := range job.Steps {
		messages[s.Name] = s.Message
	}
	for step, want := range map[string]string{
		StepSource:   "Found blog.example.test on nginx (/etc/nginx/conf.d/blog.conf line 1): files in /var/www/blog owned by nginx, its database wordpress, 1 scheduled job(s), PHP 8.2",
		StepAccount:  "Created the hosting account blog for blog.example.test.",
		StepFiles:    "Copied /var/www/blog (owned by nginx there) into public_html, read as nginx. nginx's rules became the .htaccess files",
		StepDatabase: "Copied the database wordpress as blog_wordpress, with its user as blog_wpuser and the same password: 1 tables, 3 rows, every table's rows match.",
		StepCron:     "where they named /var/www/blog they now name /home/blog/public_html",
	} {
		if !strings.Contains(messages[step], want) {
			t.Errorf("%s: %q lacks %q", step, messages[step], want)
		}
	}
	// The job's folder only, not a longer one that starts with its name.
	if len(f.broker.cron) != 1 || f.broker.cron[0].Command != "php /home/blog/public_html/wp-cron.php > /var/www/blog2/log" {
		t.Fatalf("cron: %+v", f.broker.cron)
	}
	if !slices.Contains(f.order.all, "copy-db blog_wordpress") {
		t.Fatalf("order: %q", f.order.all)
	}
	raw, _ := os.ReadFile(filepath.Join(f.dir, "jobs.json"))
	if strings.Contains(string(raw), testHash) {
		t.Fatal("the job record holds the hash")
	}
}

func TestServerMoveWithRefusedRulesMakesNothing(t *testing.T) {
	f := newMigrationFixture(t)
	f.broker.via = hostaccounts.ViaServer
	plan := serverPlan()
	plan.Domain, plan.Username = "app.example.test", "app"
	plan.Site = &hostaccounts.MigrationSite{Domain: "app.example.test", Server: "nginx", Where: "/etc/nginx/conf.d/app.conf line 1", Owner: "", Movable: false}
	plan.Tier, plan.TierRefusals, plan.TierFix = "compat", []string{"/etc/nginx/conf.d/app.conf line 4: proxy_pass: Sifruno does not convert this directive"}, []string{"/etc/nginx/conf.d/app.conf line 4"}
	f.broker.plan = plan
	job, err := f.runner.StartMigration(context.Background(), MigrationInput{Source: sourceID, Username: "app", Site: "app.example.test"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	f.runner.Wait()
	job, _ = f.runner.Get(job.ID)
	if job.State != StateFailed || job.Error == nil || !strings.Contains(job.Error.Why, "app.conf line 4") || !strings.Contains(job.Error.Why, "Nothing was created here") || !strings.Contains(job.Error.Technical, "proxy_pass") {
		t.Fatalf("job: %+v %+v", job.State, job.Error)
	}
	if slices.ContainsFunc(f.order.all, func(s string) bool { return strings.HasPrefix(s, "create ") || strings.HasPrefix(s, "files ") }) {
		t.Fatalf("something was made: %q", f.order.all)
	}
}

func TestServerMoveNeedsTheSiteAndOnlyThere(t *testing.T) {
	f := newMigrationFixture(t)
	if _, err := f.migrateServer(t, ""); err == nil {
		t.Fatal("a move from another Linux server without a site started")
	}
	f.broker.via = ""
	if _, err := f.runner.StartMigration(context.Background(), MigrationInput{Source: sourceID, Username: "shopone", Site: "shop.example.test"}, "test operator"); err == nil {
		t.Fatal("a cPanel move took a site")
	}
	// The broker answering for another site than asked is refused.
	f2 := newMigrationFixture(t)
	f2.broker.via = hostaccounts.ViaServer
	f2.broker.plan = serverPlan()
	f2.broker.plan.Domain = "other.example.test"
	job, err := f2.runner.StartMigration(context.Background(), MigrationInput{Source: sourceID, Username: "blog", Site: "blog.example.test"}, "test operator")
	if err != nil {
		t.Fatal(err)
	}
	f2.runner.Wait()
	if job, _ = f2.runner.Get(job.ID); job.State != StateFailed {
		t.Fatalf("job: %+v", job.State)
	}
}

func TestMovedCommandNamesTheNewFolder(t *testing.T) {
	for in, want := range map[string]string{
		"php /var/www/blog/wp-cron.php":    "php /home/blog/public_html/wp-cron.php",
		"cd /var/www/blog && php cron.php": "cd /home/blog/public_html && php cron.php",
		"ls /var/www/blog":                 "ls /home/blog/public_html",
		"ls /var/www/blogs/x":              "ls /var/www/blogs/x",
		"php '/var/www/blog/x.php'":        "php '/home/blog/public_html/x.php'",
	} {
		if got := movedCommand(in, "/var/www/blog", "/home/blog/public_html"); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
