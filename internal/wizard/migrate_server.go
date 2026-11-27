package wizard

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"sifruno/internal/cpsource"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/sitemodel"
	"sifruno/internal/sitesource"
)

// A website moved from another Linux server (hostaccounts README, "From
// another Linux server"): the broker read it from the web server's own
// configuration, by its domain, and the job moves it into an account with
// the name the admin chose. Its steps are the cPanel move's; what differs
// is said here: where the files came from, the database's new names, and
// the scheduled jobs' folder.

// serverSource is the source step for a website on another Linux server.
func (j *run) serverSource(ctx context.Context, plan hostaccounts.MigrationPlan) (string, *stepError) {
	m, mr := j.job.Migration, j.migration
	mr.plan = plan
	for _, u := range plan.Users {
		if u.Hash != "" {
			j.secrets = append(j.secrets, u.Hash)
		}
	}
	j.job.Domain, j.in.Domain = plan.Domain, plan.Domain
	m.PHPSource, m.WWW, m.Tier = plan.PHPSource, plan.WWW && !strings.HasPrefix(plan.Domain, "www."), plan.Tier
	j.touch()
	if !validDomain(plan.Domain) || plan.Domain != m.SourceSite || plan.Username != j.job.Username || plan.Site == nil {
		return "", &stepError{why: "The old server answered for another website or account than the one asked for.", next: "Start the move again from Move a website here.", technical: "domain " + clip(plan.Domain)}
	}
	m.SourceUser = plan.Site.Owner
	if owner, taken := j.domainOwner(ctx); taken {
		return "", &stepError{why: plan.Domain + " already belongs to the hosting account " + owner + " on this server.", next: "Remove that website first, or move another one."}
	}
	if !plan.Site.Movable {
		return "", serverRefusal(plan)
	}
	if plan.Tier != "native" {
		return "", tierRefusal(plan)
	}
	for _, w := range plan.TierWarnings {
		j.note("A .htaccess line is not carried over: " + w)
	}
	php, exact := sitesource.PHPVersion(plan.PHPSource)
	mr.php = php
	if !exact {
		source := plan.PHPSource
		if source == "" {
			source = "a version it does not name"
		}
		j.note(fmt.Sprintf("The old server runs PHP as %s; this server offers 8.1 to 8.4, so the copy runs PHP %s. Check the preview for errors.", clip(source), php))
	}
	site := serverModel(plan, php, exact)
	for _, item := range site.NotCarried {
		j.note(item.Text)
	}
	for _, line := range plan.Cron {
		job := hostaccounts.CronJob{Schedule: line.Schedule, Command: line.Command}
		if hostaccounts.CronJobProblem(job) != "" {
			j.note("A scheduled job was not copied because this server's job rules refuse it (for example a % in the command). Add it again on the website's Jobs tab.")
			continue
		}
		mr.cronJobs = append(mr.cronJobs, job)
	}
	m.Probes = probesOf(plan.Probes)
	m.ClientAddress = plan.ClientAddress
	m.Converted = slices.Clone(plan.Converted)
	database := "no database"
	if len(plan.Databases) == 1 {
		database = "its database " + plan.Site.Database
	}
	converted := ""
	if len(plan.Converted) > 0 {
		converted = fmt.Sprintf(" %d rule(s) become the web server's config: %s.", len(plan.Converted), folderPaths(plan.Converted))
	}
	return clip(fmt.Sprintf("Found %s on %s (%s): files in %s owned by %s, %s, %d scheduled job(s), PHP %s (%s), rules OpenLiteSpeed acts on.%s",
		plan.Domain, plan.Site.Server, plan.Site.Where, plan.Site.DocRoot, plan.Site.Owner, database, len(plan.Cron), php, plan.PHPSource, converted)), nil
}

// serverRefusal explains a website whose web server block has lines this
// server does not convert: nothing was made, and the lines are named.
func serverRefusal(plan hostaccounts.MigrationPlan) *stepError {
	technical := clip("refused: " + strings.Join(plan.TierRefusals, " | "))
	lines := strings.Join(plan.TierFix[:min(len(plan.TierFix), tierLinesShown)], ", ")
	if more := len(plan.TierFix) - tierLinesShown; more > 0 {
		lines += fmt.Sprintf(" and %d more", more)
	}
	why := "The old server's configuration for " + plan.Domain + " has lines this server does not convert"
	if lines != "" {
		why += " (" + lines + ")"
	}
	return &stepError{
		why:       why + ", so moving it as it is would change what it does. Nothing was created here.",
		next:      "Leave this website on the old server for now, or change those lines there (Technical details says why for each), then move it again.",
		technical: technical}
}

// serverModel is the website model of a plan from another Linux server.
// What the summary page showed as information only (mail stays, nginx's
// .htaccess files stay, the database's new names) is not a note: the job
// says it in its steps. Everything else that does not move is.
func serverModel(plan hostaccounts.MigrationPlan, php string, exact bool) sitemodel.Site {
	s := sitemodel.Site{Source: sitemodel.SourceSSH, Account: plan.Username, Domain: plan.Domain, WWW: plan.WWW, DiskUsedMiB: plan.DiskUsedMiB,
		Home: plan.Site.DocRoot, Databases: []sitemodel.Database{}, Users: []sitemodel.User{}, Cron: append([]cpsource.CronLine{}, plan.Cron...),
		PHP:   sitemodel.PHP{Source: plan.PHPSource, Version: php, Exact: exact, Settings: []sitemodel.Setting{}},
		Rules: sitemodel.Rules{Native: plan.Tier == "native", Htaccess: plan.Htaccess, Redirects: []sitemodel.Redirect{}, Folders: []string{}, Rewrites: []string{}}, Aliases: []string{}, NotCarried: []sitemodel.Item{}}
	for _, d := range plan.Databases {
		s.Databases = append(s.Databases, sitemodel.Database{Name: d.Name, SourceName: plan.Site.Database, Dump: "ssh"})
	}
	for _, u := range plan.Users {
		s.Users = append(s.Users, sitemodel.User{Name: u.Name, HasHash: u.Hash != "", Grants: u.Grants})
	}
	for _, c := range plan.CronSkipped {
		s.Skip("cron", "A scheduled-job line was not copied: "+c+".", "")
	}
	for _, item := range plan.NotCarried {
		if item.Part == "mail" || item.Part == "info" {
			continue
		}
		text := item.Text
		if item.Where != "" {
			text += " (" + item.Where + ")"
		}
		s.Skip(item.Part, text, item.Where)
	}
	return s
}

// movedCommand puts the site's new folder in a scheduled job's command
// where it names the old one: the old document root as a whole path, not
// a longer folder that starts with its name.
func movedCommand(command, oldRoot, newRoot string) string {
	if oldRoot == "" || newRoot == "" {
		return command
	}
	return regexp.MustCompile(regexp.QuoteMeta(oldRoot)+`(/|$|[\s;'"&|<>)])`).ReplaceAllString(command, newRoot+"$1")
}

// serverCron gives the scheduled jobs the site's new folder.
func (j *run) serverCron() (moved bool) {
	mr := j.migration
	if mr.plan.Site == nil || mr.home == "" {
		return false
	}
	for i, job := range mr.cronJobs {
		command := movedCommand(job.Command, mr.plan.Site.DocRoot, mr.home+"/public_html")
		if command != job.Command && hostaccounts.CronJobProblem(hostaccounts.CronJob{Schedule: job.Schedule, Command: command}) == "" {
			mr.cronJobs[i].Command, moved = command, true
		}
	}
	return moved
}

// serverFilesMessage is the files step's words for a site from another
// Linux server.
func serverFilesMessage(plan hostaccounts.MigrationPlan, res hostaccounts.MigrateFilesResult, protected string) string {
	site := plan.Site
	text := "Copied " + site.DocRoot + " (owned by " + site.Owner + " there) into public_html, read as " + site.Owner + "."
	if site.Server == "nginx" {
		text += " nginx's rules became the .htaccess files OpenLiteSpeed reads; the folder's own .htaccess files stayed there, as nginx never read them."
	}
	if res.WordPress && len(plan.Databases) == 1 {
		text += " It is a WordPress site; its wp-config.php now names the database " + plan.Databases[0].Name + " and the user " + plan.Users[0].Name + "."
	} else if res.WordPress {
		text += " It is a WordPress site."
	}
	return clip(text + protected)
}

// serverDatabasesMessage is the database step's words for a site from
// another Linux server, whose database took the account's prefix here.
func (j *run) serverDatabasesMessage() string {
	plan, mr := j.migration.plan, j.migration
	if len(plan.Databases) != 1 || len(plan.Users) != 1 || plan.Site == nil {
		return ""
	}
	text := fmt.Sprintf("Copied the database %s as %s, with its user as %s and the same password: %d tables, %d rows", plan.Site.Database, plan.Databases[0].Name, plan.Users[0].Name, mr.dbTables, mr.dbRows)
	if mr.dbDiffers > 0 {
		return clip(fmt.Sprintf("%s; %d table(s) differ in rows.", text, mr.dbDiffers))
	}
	return clip(text + ", every table's rows match.")
}
