package wizard

import (
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
	if raw := strings.Join(texts, ""); strings.Contains(raw, "0123456789ABCDEF") {
		t.Fatal("the model holds a password hash")
	}
}
