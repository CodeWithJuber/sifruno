package wizard

import (
	"slices"
	"strings"
	"testing"

	"sifruno/internal/cpsource"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/sitemodel"
)

func TestCPanelPlanIsAWebsiteModel(t *testing.T) {
	plan := hostaccounts.MigrationPlan{Username: "shop", Domain: "example.com", Aliases: []string{"example.net"}, WWW: true, PHPSource: "ea-php82", Tier: "native", Htaccess: 2,
		Databases:     []cpsource.Database{{Name: "shop_wp", Users: []string{"shop_wp"}}},
		Users:         []cpsource.DatabaseUser{{Name: "shop_wp", Hash: "*0123456789ABCDEF0123456789ABCDEF01234567", Grants: []cpsource.Grant{{Database: "shop_wp", Privileges: []string{"ALL PRIVILEGES"}}}}},
		Cron:          []cpsource.CronLine{{Schedule: "0 * * * *", Command: "php -q ~/public_html/cron.php"}},
		GrantsSkipped: []string{"a grant of shop_wp on a database name pattern or another database"}, CronSkipped: []string{"a variable line (such as MAILTO or PATH): jobs here run with the server's defaults"}}
	site := cpanelSite(plan, sitemodel.SourceCPanel, "8.2", true)
	if err := site.Check(); err != nil {
		t.Fatal(err)
	}
	if !site.Users[0].HasHash || site.Databases[0].Dump != "ssh" || !site.Rules.Native || site.Rules.Htaccess != 2 || len(site.Cron) != 1 {
		t.Fatalf("site = %+v", site)
	}
	var texts []string
	for _, item := range site.NotCarried {
		texts = append(texts, item.Part+": "+item.Text)
	}
	want := []string{
		"domain: The site's other domains (example.net) were not added; this version moves the main domain. Add them on the website's Domains tab.",
		"database: A database grant was not copied: a grant of shop_wp on a database name pattern or another database.",
		"cron: A scheduled-job line was not copied: a variable line (such as MAILTO or PATH): jobs here run with the server's defaults.",
	}
	if strings.Join(texts, "\n") != strings.Join(want, "\n") {
		t.Fatalf("not carried:\n%s", strings.Join(texts, "\n"))
	}
	// The model never holds the hash.
	if strings.Contains(strings.Join(texts, ""), testHash) {
		t.Fatal("the model holds a password hash")
	}
	if raw := strings.Join(texts, ""); strings.Contains(raw, "0123456789ABCDEF") {
		t.Fatal("the model holds a password hash")
	}
}

// A move from a cPanel backup file is the same job: no fingerprint to
// confirm, the file named as the source, its own step titles, what the
// file holds that does not move as notes, and the file deleted last.
func TestBackupFileMoveIsTheSameJob(t *testing.T) {
	f := newMigrationFixture(t)
	f.broker.via, f.broker.pinned = hostaccounts.ViaArchive, false
	f.broker.plan.NotCarried = []sitemodel.Item{{Part: "mail", Text: "Email accounts and their mail stay with the old host."}}
	job := f.migrate(t)
	if job.State != StateSucceeded || job.Migration.SourceHost != "a cPanel backup file" || !job.Migration.KeyRemoved {
		t.Fatalf("job: %+v %+v", job, job.Error)
	}
	titles := map[string]string{}
	for _, s := range job.Steps {
		titles[s.Name] = s.Title + ": " + s.Message
	}
	for name, want := range map[string]string{
		StepSource:   "Read the website from the backup file",
		StepKey:      "Delete the uploaded backup file: Deleted the uploaded backup file from this server.",
		StepDatabase: "Loaded 1 database(s) from the backup file",
	} {
		if !strings.Contains(titles[name], want) {
			t.Errorf("step %s = %q, want %q", name, titles[name], want)
		}
	}
	if !slices.Contains(job.Migration.Notes, "Email accounts and their mail stay with the old host.") {
		t.Fatalf("notes: %v", job.Migration.Notes)
	}
}
