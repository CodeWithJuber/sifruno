package wizard

import (
	"strings"

	"sifruno/internal/cpsource"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/sitemodel"
)

// cpanelSite is the cPanel adapter onto the website model
// (docs/migration-design.md): the broker's plan of a cPanel account, read
// over SSH, through WHM or from a backup file, as a sitemodel.Site. What
// this version does not carry (the site's other domains, grants on other
// databases, cron lines this server's jobs cannot hold) is the model's
// NotCarried, which the job shows as notes.
func cpanelSite(plan hostaccounts.MigrationPlan, source, php string, exact bool) sitemodel.Site {
	s := sitemodel.Site{Source: source, Account: plan.Username, Domain: plan.Domain, WWW: plan.WWW,
		DiskUsedMiB: plan.DiskUsedMiB, DiskLimitMiB: plan.DiskLimitMiB, DocRoot: "public_html",
		Databases: []sitemodel.Database{}, Users: []sitemodel.User{}, Cron: append([]cpsource.CronLine{}, plan.Cron...),
		PHP:     sitemodel.PHP{Source: plan.PHPSource, Version: php, Exact: exact, Settings: []sitemodel.Setting{}},
		Rules:   sitemodel.Rules{Native: plan.Tier == "native", Htaccess: plan.Htaccess, Redirects: []sitemodel.Redirect{}, Folders: []string{}, Rewrites: []string{}},
		Aliases: []string{}, NotCarried: []sitemodel.Item{}}
	dump := "ssh"
	if source == sitemodel.SourceArchive {
		dump = "archive"
	}
	for _, d := range plan.Databases {
		s.Databases = append(s.Databases, sitemodel.Database{Name: d.Name, Dump: dump})
	}
	for _, u := range plan.Users {
		s.Users = append(s.Users, sitemodel.User{Name: u.Name, HasHash: u.Hash != "", Grants: u.Grants})
	}
	if len(plan.Aliases) > 0 {
		s.Skip("domain", "The site's other domains ("+strings.Join(plan.Aliases, ", ")+") were not added; this version moves the main domain. Add them on the website's Domains tab.", "")
	}
	for _, g := range plan.GrantsSkipped {
		s.Skip("database", "A database grant was not copied: "+g+".", "")
	}
	for _, c := range plan.CronSkipped {
		s.Skip("cron", "A scheduled-job line was not copied: "+c+".", "")
	}
	for _, r := range plan.TierRefusals {
		s.Skip("rule", r, "")
	}
	// A backup file's adapter says itself what does not move.
	for _, item := range plan.NotCarried {
		s.Skip(item.Part, item.Text, item.Where)
	}
	return s
}

// siteSource is the model's name for where a migration reads from.
func siteSource(via string) string {
	if via == hostaccounts.ViaArchive {
		return sitemodel.SourceArchive
	}
	return sitemodel.SourceCPanel
}

// sourceName names the old server, or the backup file, in the job's words.
func sourceName(m hostaccounts.Migration) string {
	if m.Via == hostaccounts.ViaArchive {
		return "a cPanel backup file"
	}
	return m.Host
}

// archiveStepTitles are the steps whose words differ for a move from a
// backup file: the source is the file, and the last step deletes it.
var archiveStepTitles = map[string]string{
	StepSource: "Read the website from the backup file",
	StepKey:    "Delete the uploaded backup file",
}

// retitle gives a backup file's move its own step titles.
func retitle(job *Job) {
	for i, s := range job.Steps {
		if title, ok := archiveStepTitles[s.Name]; ok {
			job.Steps[i].Title = title
		}
	}
}
