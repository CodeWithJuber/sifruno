package hostaccounts

import (
	"bytes"
	"context"
	"errors"
	"path"
	"slices"
	"strconv"
	"strings"

	"sifruno/internal/cpsource"
	"sifruno/internal/htaccess"
	"sifruno/internal/sitemodel"
	"sifruno/internal/sitesource"
)

// A migration from another Linux server (docs/migration-design.md, adapter
// 3): Plesk, DirectAdmin, HestiaCP or a plain server with Apache or nginx
// and PHP-FPM. The broker signs in with the migration's key exactly as for
// cPanel (the same key, host key pin, expiry and removal), but asks the web
// server itself what it serves: nginx -T and httpd -S name the virtual
// hosts, and internal/sitesource reads them. Every command is one of
// sitesource's fixed ones. Each step reads the site again by the account's
// domain, so the panel names only the migration, the domain and the
// account name here. The copy is the cPanel copy's from the staged files
// on: the document root lands as the account's public_html, nginx's rules
// arrive as the .htaccess files the scan converts, and a WordPress
// database keeps its password under the account's own prefix, with
// wp-config.php pointed at the new names on the root-only staged copy.

// ViaServer is a migration from another Linux server.
const ViaServer = "server"

// MigrationSite is one website another Linux server's web server serves,
// as the broker read it. Account is the name it gets here unless the admin
// picks another; Database the one its wp-config.php names. It never holds
// a password, a hash or a key.
type MigrationSite struct {
	Domain      string           `json:"domain"`
	Aliases     []string         `json:"aliases"`
	WWW         bool             `json:"www"`
	Server      string           `json:"server"`
	Where       string           `json:"where"`
	DocRoot     string           `json:"doc_root"`
	Owner       string           `json:"owner"`
	Account     string           `json:"account"`
	PHPSource   string           `json:"php_source"`
	PHP         string           `json:"php"`
	WordPress   bool             `json:"wordpress"`
	Database    string           `json:"database"`
	Certificate bool             `json:"certificate"`
	Movable     bool             `json:"movable"`
	Refused     []sitemodel.Item `json:"refused"`
	NotCarried  []sitemodel.Item `json:"not_carried"`
}

// maxWordPressReads bounds the wp-config.php files a listing reads; past
// it a site's database is read when its move starts.
const maxWordPressReads = 32

// serverSite is one site as a step reads it: the web server's block, its
// owner, and the database its wp-config.php names.
type serverSite struct {
	site  sitesource.ServerSite
	owner sitesource.Owner
	// wp is set when the document root holds a wp-config.php.
	wp *serverDatabase
}

// serverDatabase is a WordPress site's database: its names on the old
// server and here, and the mysql_native_password hash of the password
// wp-config.php gives, so the user here has the same password without
// the broker keeping it. Problem says why it does not move.
type serverDatabase struct {
	source, sourceUser string
	name, user         string
	hash               string
	problem            string
}

func (d *serverDatabase) moves() bool { return d != nil && d.problem == "" && d.name != "" }

// serverFailure is a source command that failed: ssh's own failure, or the
// command's exit with what it printed on its error output.
func (s *store) serverCommand(ctx context.Context, m migrationRecord, command string, max int) ([]byte, int, []byte, error) {
	stdout := &limitBuffer{max: max}
	out, code, err := s.migrate.Remote(ctx, m, command, nil, stdout, migrateRemoteTimeout)
	if err != nil {
		return nil, 0, nil, err
	}
	if code == 255 {
		return nil, 0, nil, sshFailure("connect", out)
	}
	return stdout.b, code, out, nil
}

// serverSites reads the old server's websites from its web servers' own
// view of their configuration, then the PHP-FPM pools for their versions.
// A server with neither nginx nor Apache, or with no website either names,
// is a source error that says so.
func (s *store) serverSites(ctx context.Context, m migrationRecord) ([]sitesource.ServerSite, error) {
	out, code, errOut, err := s.serverCommand(ctx, m, sitesource.NginxDumpCommand, cpsource.MaxOutput)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, &MigrationError{Step: "source", Detail: "nginx on the old server says its own configuration has an error (nginx -T failed), so Sifruno cannot tell which websites it serves. Fix it there (nginx -t names the line).", Output: installDetail(errOut)}
	}
	nginx, err := sitesource.ParseNginxDump(out)
	if err != nil {
		return nil, &MigrationError{Step: "source", Detail: installDetail([]byte("nginx's configuration could not be read: "+err.Error())) + "."}
	}
	hasNginx := len(nginx) > 0
	out, code, errOut, err = s.serverCommand(ctx, m, sitesource.ApacheVhostsCommand, 1<<20)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, &MigrationError{Step: "source", Detail: "Apache on the old server says its own configuration has an error (httpd -S failed), so Sifruno cannot tell which websites it serves. Fix it there (apachectl configtest names the line).", Output: installDetail(append(out, errOut...))}
	}
	files, err := sitesource.ApacheFiles(out)
	if err != nil {
		return nil, &MigrationError{Step: "source", Detail: "Apache on the old server names its virtual hosts in more than 64 files, more than this version reads."}
	}
	hasApache := len(bytes.TrimSpace(out)) > 0
	var apache []sitesource.ApacheSite
	for _, file := range files {
		command, err := sitesource.ConfigFileCommand(file)
		if err != nil {
			return nil, &MigrationError{Step: "source", Detail: installDetail([]byte("Apache reads virtual hosts from " + file + ", outside the folders this version reads (/etc/httpd, /etc/apache2, DirectAdmin's users' folders)."))}
		}
		data, code, errOut, err := s.serverCommand(ctx, m, command, sitesource.MaxConfigBytes+1)
		if errors.Is(err, ErrUnavailable) {
			return nil, &MigrationError{Step: "source", Detail: installDetail([]byte(file + " is larger than 1 MiB, more than this version reads."))}
		}
		if err != nil {
			return nil, err
		}
		if code != 0 {
			return nil, &MigrationError{Step: "source", Detail: installDetail([]byte(file + " could not be read on the old server.")), Output: installDetail(errOut)}
		}
		sites, err := sitesource.ParseApache(file, data)
		if err != nil {
			return nil, &MigrationError{Step: "source", Detail: installDetail([]byte("Apache's configuration could not be read: "+err.Error())) + "."}
		}
		apache = append(apache, sites...)
	}
	if !hasNginx && !hasApache {
		return nil, &MigrationError{Step: "source", Detail: "The old server runs neither nginx (/usr/sbin/nginx) nor Apache (/usr/sbin/httpd or apache2ctl), so this way of moving does not apply to it. A cPanel server moves with the cPanel answer; a CyberPanel server runs OpenLiteSpeed, which this version does not read yet."}
	}
	sites := sitesource.ServerSites(nginx, apache)
	if len(sites) == 0 {
		return nil, &MigrationError{Step: "source", Detail: "The old server's web server names no website by its domain: no server_name or ServerName that is a plain domain."}
	}
	pools, versions := s.serverPHP(ctx, m)
	for i := range sites {
		sites[i].ResolvePHP(pools, versions)
	}
	return sites, nil
}

// serverPHP reads the PHP-FPM pools and versions; a server whose answer
// cannot be read leaves the sites' versions unknown, which the plan notes.
func (s *store) serverPHP(ctx context.Context, m migrationRecord) ([]sitesource.FPMPool, map[string]string) {
	var pools []sitesource.FPMPool
	versions := map[string]string{}
	if out, code, _, err := s.serverCommand(ctx, m, sitesource.FPMPoolsCommand, 1<<20); err == nil && code == 0 {
		pools = sitesource.ParseFPMPools(out)
	}
	if out, code, _, err := s.serverCommand(ctx, m, sitesource.FPMVersionsCommand, 64<<10); err == nil && code == 0 {
		versions = sitesource.ParseFPMVersions(out)
	}
	return pools, versions
}

// serverOwner reads who owns the site's document root, which must be a
// folder.
func (s *store) serverOwner(ctx context.Context, m migrationRecord, root string) (sitesource.Owner, error) {
	command, err := sitesource.StatCommand(root)
	if err != nil {
		return sitesource.Owner{}, &MigrationError{Step: "source", Detail: installDetail([]byte("The website's folder " + root + " is not one this version copies."))}
	}
	out, code, errOut, err := s.serverCommand(ctx, m, command, 4096)
	if err != nil {
		return sitesource.Owner{}, err
	}
	if code != 0 {
		return sitesource.Owner{}, &MigrationError{Step: "source", Detail: installDetail([]byte("The website's folder " + root + " is not on the old server.")), Output: installDetail(errOut)}
	}
	owner, err := sitesource.ParseStat(out)
	switch {
	case errors.Is(err, sitesource.ErrNotFolder):
		return sitesource.Owner{}, &MigrationError{Step: "source", Detail: installDetail([]byte("The website's folder " + root + " is a link or not a folder. Point the web server at the real folder, or move the files there."))}
	case err != nil:
		return sitesource.Owner{}, &MigrationError{Step: "source", Detail: installDetail([]byte("The owner of " + root + " could not be read: a user without a name, or a name this version does not take."))}
	}
	return owner, nil
}

// serverDatabaseOf reads the site's wp-config.php as the folder's owner.
// No wp-config.php is no WordPress (nil). One whose database is not named
// plainly, or is on another server, or whose names do not fit here, has a
// problem: the site moves without its database, and the plan says why.
func (s *store) serverDatabaseOf(ctx context.Context, m migrationRecord, root string, owner sitesource.Owner, account string) (*serverDatabase, error) {
	command, err := sitesource.WPConfigCommand(root, owner)
	if err != nil {
		return nil, ErrInvalid
	}
	out, code, errOut, err := s.serverCommand(ctx, m, command, 256<<10+1)
	if errors.Is(err, ErrUnavailable) {
		return &serverDatabase{problem: "Its wp-config.php is larger than 256 KiB, more than Sifruno reads, so its database is not copied."}, nil
	}
	if err != nil {
		return nil, err
	}
	if code != 0 {
		if bytes.Contains(errOut, []byte("No such file")) {
			return nil, nil
		}
		return &serverDatabase{problem: "Its wp-config.php could not be read as the folder's owner (" + owner.Name + "), so its database is not copied."}, nil
	}
	defer clear(out)
	c, err := sitesource.ParseWPConfig(out)
	if err != nil {
		return &serverDatabase{problem: "Its wp-config.php does not name the database with plain text (a value built from code or the environment), so its database is not copied. Copy it by hand, or write the names plainly there first."}, nil
	}
	d := &serverDatabase{source: c.Name, sourceUser: c.User, hash: c.NativeHash()}
	if !c.LocalDatabase() {
		d.problem = "Its database is on another server (DB_HOST " + clipText(c.Host, 80) + "), so it is not copied; wp-config.php keeps pointing there."
		return d, nil
	}
	if !cpsource.DatabasePattern.MatchString(c.Name) {
		d.problem = "Its database name " + clipText(c.Name, 64) + " has characters this version does not copy."
		return d, nil
	}
	var ok bool
	if d.name, ok = sitesource.HereName(account, c.Name, 64); !ok {
		d.problem = "Its database name " + c.Name + " is too long to take the account's prefix here."
		return d, nil
	}
	if d.user, ok = sitesource.HereName(account, c.User, 47); !ok {
		d.problem = "Its database user " + clipText(c.User, 64) + " is too long to take the account's prefix here, or has characters this version does not take."
	}
	return d, nil
}

func clipText(s string, n int) string {
	s = installDetail([]byte(s))
	if len(s) > n {
		s = s[:n]
	}
	return s
}

// serverSiteFor reads one site again, by its domain, with its owner and,
// for WordPress, its database under the account name here.
func (s *store) serverSiteFor(ctx context.Context, m migrationRecord, domain, account string) (serverSite, error) {
	sites, err := s.serverSites(ctx, m)
	if err != nil {
		return serverSite{}, err
	}
	i := slices.IndexFunc(sites, func(x sitesource.ServerSite) bool { return x.Domain == domain })
	if i < 0 {
		return serverSite{}, &MigrationError{Step: "account_missing", Detail: "The old server's web server no longer names " + domain + "."}
	}
	out := serverSite{site: sites[i]}
	if !out.site.Movable() {
		return out, nil
	}
	if out.owner, err = s.serverOwner(ctx, m, out.site.DocRoot); err != nil {
		return serverSite{}, err
	}
	if out.wp, err = s.serverDatabaseOf(ctx, m, out.site.DocRoot, out.owner, account); err != nil {
		return serverSite{}, err
	}
	return out, nil
}

// serverItems are a site's refusals and notes as the plan lists them.
func serverItems(list []sitemodel.Item) []string {
	out := []string{}
	for _, item := range list {
		if len(out) == maxTierLines {
			break
		}
		where := "the site"
		if item.Where != "" {
			where = item.Where
		}
		out = append(out, installDetail([]byte(where+": "+item.Text)))
	}
	return out
}

// migrationSites lists the old server's websites for the admin to pick
// one: each with what moves and what does not, before anything is made.
func (s *store) migrationSites(ctx context.Context, id string) ([]MigrationSite, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	m, err := s.lockedMigration(id)
	if err != nil {
		return nil, err
	}
	if m.Via != ViaServer {
		return nil, ErrInvalid
	}
	work, cancel := backupContext(ctx, 2*migrateRemoteTimeout)
	defer cancel()
	sites, err := s.serverSites(work, m)
	if err != nil {
		return nil, err
	}
	out := make([]MigrationSite, 0, len(sites))
	reads := 0
	for _, x := range sites {
		v := MigrationSite{Domain: x.Domain, Aliases: slices.Clone(x.Aliases), WWW: x.WWW, Server: x.Server, Where: x.Where, DocRoot: x.DocRoot, PHPSource: x.PHPSource,
			Certificate: x.TLS != nil, Refused: slices.Clone(x.Refused), NotCarried: slices.Clone(x.Notes)}
		v.PHP, _ = sitesource.PHPVersion(x.PHPSource)
		if v.Refused == nil {
			v.Refused = []sitemodel.Item{}
		}
		if v.NotCarried == nil {
			v.NotCarried = []sitemodel.Item{}
		}
		if x.Movable() {
			owner, err := s.serverOwner(work, m, x.DocRoot)
			var failed *MigrationError
			switch {
			case errors.As(err, &failed) && failed.Step == "source":
				v.Refused = append(v.Refused, sitemodel.Item{Part: "file", Text: failed.Detail, Where: x.Where})
			case err != nil:
				return nil, err
			default:
				v.Owner, v.Account = owner.Name, sitesource.AccountName(owner, x.Domain)
				if reads < maxWordPressReads {
					reads++
					wp, err := s.serverDatabaseOf(work, m, x.DocRoot, owner, v.Account)
					if err != nil {
						return nil, err
					}
					v.WordPress = wp != nil
					if wp.moves() {
						v.Database = wp.source
					} else if wp != nil {
						v.NotCarried = append(v.NotCarried, sitemodel.Item{Part: "database", Text: wp.problem, Where: x.DocRoot + "/wp-config.php"})
					}
				}
			}
		}
		v.Movable = x.Movable() && len(v.Refused) == len(x.Refused) && v.Account != ""
		v.NotCarried = append(v.NotCarried, serverNotCarried(x)...)
		out = append(out, v)
	}
	return out, nil
}

// serverNotCarried is what never moves from another server in this
// version, for every site.
func serverNotCarried(x sitesource.ServerSite) []sitemodel.Item {
	items := []sitemodel.Item{{Part: "mail", Text: "Email, DNS and FTP accounts stay on the old server; this moves the website's files, its database and its jobs."}}
	if len(x.Aliases) > 0 {
		items = append(items, sitemodel.Item{Part: "domain", Text: "The site's other domains (" + strings.Join(x.Aliases, ", ") + ") are not added; this version moves the main domain. Add them on the website's Domains tab.", Where: x.Where})
	}
	if x.Server == "nginx" {
		items = append(items, sitemodel.Item{Part: "info", Text: ".htaccess files in the website's folder are left out: nginx does not read them, so they were not in force there. Its own rules come over instead."})
	}
	return items
}

// validMigrationSite is a plan's site: a domain, and the account name it
// gets here.
func validServerPlan(in MigrationPlanInput) bool {
	return cpsource.ValidDomain(in.Site) && in.CPanel == nil
}

// planServer reads one site for the move: everything the copy needs, the
// tier its rules get, and what does not move. A site whose rules are
// refused answers a plan that is not Native, with each line, as an Apache
// site whose .htaccess is refused does: nothing is made.
func (s *store) planServer(ctx context.Context, m migrationRecord, in MigrationPlanInput) (MigrationPlan, error) {
	if !validServerPlan(in) {
		return MigrationPlan{}, ErrInvalid
	}
	x, err := s.serverSiteFor(ctx, m, in.Site, in.Username)
	if err != nil {
		return MigrationPlan{}, err
	}
	site := x.site
	plan := MigrationPlan{Username: in.Username, Domain: site.Domain, Aliases: slices.Clone(site.Aliases), WWW: site.WWW, PHPSource: site.PHPSource,
		Databases: []cpsource.Database{}, Users: []cpsource.DatabaseUser{}, GrantsSkipped: []string{}, Cron: []cpsource.CronLine{}, CronSkipped: []string{}, Probes: []MigrationProbe{}, TierCauses: []string{},
		Converted: []MigrationFolder{}, TierRefusals: []string{}, TierFix: []string{}, TierWarnings: []string{}, NotCarried: slices.Clone(site.Notes),
		Site: &MigrationSite{Domain: site.Domain, Aliases: slices.Clone(site.Aliases), WWW: site.WWW, Server: site.Server, Where: site.Where, DocRoot: site.DocRoot, Owner: x.owner.Name, Account: in.Username,
			PHPSource: site.PHPSource, Certificate: site.TLS != nil, Movable: site.Movable(), Refused: slices.Clone(site.Refused), NotCarried: []sitemodel.Item{}}}
	plan.Site.PHP, _ = sitesource.PHPVersion(site.PHPSource)
	if plan.Aliases == nil {
		plan.Aliases = []string{}
	}
	if plan.NotCarried == nil {
		plan.NotCarried = []sitemodel.Item{}
	}
	plan.NotCarried = append(plan.NotCarried, serverNotCarried(site)...)
	if !site.Movable() {
		plan.Tier, plan.TierCauses = string(htaccess.VerdictCompat), []string{"not_converted"}
		plan.TierRefusals = serverItems(site.Refused)
		for _, item := range site.Refused {
			if item.Where != "" && len(plan.TierFix) < maxTierLines {
				plan.TierFix = append(plan.TierFix, installDetail([]byte(item.Where)))
			}
		}
		return plan, nil
	}
	if command, err := sitesource.DiskCommand(site.DocRoot); err == nil {
		if out, code, _, err := s.serverCommand(ctx, m, command, 4096); err == nil && code == 0 {
			plan.DiskUsedMiB, _ = sitesource.ParseDiskMiB(out)
		}
	}
	if d := x.wp; d != nil {
		plan.Site.WordPress = true
		if d.moves() {
			plan.Site.Database = d.source
			plan.Databases = append(plan.Databases, cpsource.Database{Name: d.name, Users: []string{d.user}})
			plan.Users = append(plan.Users, cpsource.DatabaseUser{Name: d.user, Hash: d.hash,
				Grants: []cpsource.Grant{{Database: d.name, Privileges: []string{"ALL PRIVILEGES"}}}})
			plan.NotCarried = append(plan.NotCarried, sitemodel.Item{Part: "info", Text: "The database " + d.source + " becomes " + d.name + " and its user " + d.sourceUser + " becomes " + d.user + " with the same password: names here start with the account's name. wp-config.php is changed to the new names."})
		} else {
			plan.NotCarried = append(plan.NotCarried, sitemodel.Item{Part: "database", Text: d.problem, Where: site.DocRoot + "/wp-config.php"})
		}
	} else {
		plan.NotCarried = append(plan.NotCarried, sitemodel.Item{Part: "database", Text: "The site has no wp-config.php, so Sifruno cannot tell which database it uses, and none is copied. Copy it by hand if it has one (the Databases tab makes one here)."})
	}
	if x.owner.UID > 0 {
		if err := s.serverCron(ctx, m, x.owner, &plan); err != nil {
			return MigrationPlan{}, err
		}
	}
	plan.ClientAddress = s.sourceClient(ctx, m)
	src := serverSource{site: x.site, owner: x.owner}
	if err := s.planTier(ctx, m, "", &src, &plan); err != nil {
		return MigrationPlan{}, err
	}
	return plan, nil
}

// serverCron reads the folder owner's crontab: the jobs a site on a plain
// server runs. Root's is the server's own and is never read for a site.
func (s *store) serverCron(ctx context.Context, m migrationRecord, owner sitesource.Owner, plan *MigrationPlan) error {
	command, err := sitesource.CrontabCommand(owner)
	if err != nil {
		return nil
	}
	out, code, errOut, err := s.serverCommand(ctx, m, command, 256<<10)
	switch {
	case err != nil:
		return err
	case code == 1 && bytes.Contains(errOut, []byte("no crontab for")):
		return nil
	case code != 0:
		return migrationFailed("source", errOut)
	}
	jobs, skipped, err := cpsource.ParseCrontab(out)
	if err != nil {
		return &MigrationError{Step: "source", Detail: "The scheduled jobs of " + owner.Name + " on the old server could not be read."}
	}
	plan.Cron, plan.CronSkipped = jobs, skipped
	return nil
}

// serverSource is what the engine's copy of a site from another server
// needs: the folder, who owns it, how its rules arrive, and the names
// wp-config.php gets here.
type serverSource struct {
	site  sitesource.ServerSite
	owner sitesource.Owner
	// dbName and dbUser are set when wp-config.php is to name them.
	dbName, dbUser string
}

// stagedHome is the source home placeFiles reads password files under:
// the document root's parent when it is a public_html folder, as the copy
// stages it there. Any other document root has no home in the copy, so
// a password folder there is refused rather than read from the wrong file.
func (src serverSource) stagedHome() string {
	if path.Base(src.site.DocRoot) == "public_html" {
		return path.Dir(src.site.DocRoot)
	}
	return "/nonexistent/sifruno-no-home"
}

// serverCopySite reads the account's site from the old server for a copy
// step: it must be there under the account's domain, movable.
func (s *store) serverCopySite(ctx context.Context, m migrationRecord, r record) (serverSite, error) {
	x, err := s.serverSiteFor(ctx, m, r.Account.Domain, r.Account.Username)
	if err != nil {
		return serverSite{}, err
	}
	if !x.site.Movable() {
		return serverSite{}, &MigrationError{Step: "tier", Detail: "The old server's configuration for " + r.Account.Domain + " now has lines this server does not convert."}
	}
	return x, nil
}

// serverFiles copies a site from another server into the account.
func (s *store) serverFiles(ctx context.Context, m migrationRecord, r record) (serverSource, int64, error) {
	x, err := s.serverCopySite(ctx, m, r)
	if err != nil {
		return serverSource{}, 0, err
	}
	src := serverSource{site: x.site, owner: x.owner}
	if x.wp.moves() {
		src.dbName, src.dbUser = x.wp.name, x.wp.user
	}
	var need int64
	if command, err := sitesource.DiskCommand(x.site.DocRoot); err == nil {
		if out, code, _, err := s.serverCommand(ctx, m, command, 4096); err == nil && code == 0 {
			need, _ = sitesource.ParseDiskMiB(out)
		}
	}
	return src, need, nil
}

// serverSourceDatabase names the old server's database the account's
// database is copied from: the one the site's wp-config.php names, whose
// name here is the one asked for.
func (s *store) serverSourceDatabase(ctx context.Context, m migrationRecord, r record, db string) (string, error) {
	x, err := s.serverCopySite(ctx, m, r)
	if err != nil {
		return "", err
	}
	if !x.wp.moves() || x.wp.name != db {
		return "", &MigrationError{Step: "database", Detail: "The old server's website " + r.Account.Domain + " names no database that becomes " + db + " here."}
	}
	return x.wp.source, nil
}

// serverCertificate reads the certificate and key files the site's block
// names, as root (keys are root's alone), from the certificate folders.
func (s *store) serverCertificate(ctx context.Context, m migrationRecord, r record) (cpsource.VhostSSL, error) {
	x, err := s.serverCopySite(ctx, m, r)
	if err != nil {
		return cpsource.VhostSSL{}, err
	}
	tls := x.site.TLS
	if tls == nil || tls.Certificate == "" || tls.Key == "" {
		return cpsource.VhostSSL{}, cpsource.ErrNoCertificate
	}
	read := func(file string) ([]byte, error) {
		command, err := sitesource.TLSFileCommand(file)
		if err != nil {
			return nil, &MigrationError{Step: "source", Detail: installDetail([]byte("The certificate file " + file + " is outside the folders Sifruno reads certificates from (/etc/letsencrypt, /etc/pki, /etc/ssl, the web server's own)."))}
		}
		out, code, errOut, err := s.serverCommand(ctx, m, command, sitesource.MaxTLSFile+1)
		if errors.Is(err, ErrUnavailable) {
			return nil, &MigrationError{Step: "source", Detail: installDetail([]byte(file + " is larger than a certificate file is."))}
		}
		if err != nil {
			return nil, err
		}
		if code != 0 {
			return nil, &MigrationError{Step: "source", Detail: installDetail([]byte(file + " could not be read on the old server.")), Output: installDetail(errOut)}
		}
		return out, nil
	}
	cert, err := read(tls.Certificate)
	if err != nil {
		return cpsource.VhostSSL{}, err
	}
	key, err := read(tls.Key)
	if err != nil {
		return cpsource.VhostSSL{}, err
	}
	defer clear(key)
	return cpsource.VhostSSL{Certificate: string(cert), Key: string(key)}, nil
}

// leftOutItems names the .htaccess files an nginx site holds, which the
// copy leaves out, five at most and then how many more.
func leftOutItems(files []string) []sitemodel.Item {
	if len(files) == 0 {
		return nil
	}
	shown := files[:min(len(files), 5)]
	text := "These .htaccess files are left out, as nginx never read them: " + strings.Join(shown, ", ")
	if more := len(files) - len(shown); more > 0 {
		text += " and " + strconv.Itoa(more) + " more"
	}
	return []sitemodel.Item{{Part: "info", Text: installDetail([]byte(text)) + "."}}
}
