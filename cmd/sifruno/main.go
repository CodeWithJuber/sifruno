package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"sifruno/config"
	"sifruno/internal/acme"
	"sifruno/internal/api"
	"sifruno/internal/backuphost"
	"sifruno/internal/budget"
	"sifruno/internal/compat"
	"sifruno/internal/dbhost"
	"sifruno/internal/dnshost"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/hostpkgs"
	"sifruno/internal/mailhost"
	"sifruno/internal/operator"
	"sifruno/internal/panelcert"
	"sifruno/internal/securestate"
	"sifruno/internal/serverinfo"
	"sifruno/internal/sitebackups"
	"sifruno/internal/sites"
	"sifruno/internal/tlshost"
	"sifruno/internal/trail"
	"sifruno/internal/whmapi"
	"sifruno/internal/wizard"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	listen := flag.String("listen", "127.0.0.1:8080", "Loopback HTTP address")
	sitesListen := flag.String("sites-listen", "127.0.0.1:8082", "Loopback static website address; empty disables serving")
	state := flag.String("state", ".state/sifruno", "Private application-owned state directory")
	ui := flag.String("ui", "web/dist", "Built panel directory")
	accountsSocket := flag.String("accounts-socket", "", "Absolute Unix socket of the separately installed Linux account broker; empty disables accounts")
	backupScheduler := flag.Bool("backup-scheduler", false, "Opt in to app-owned static-site ZIP schedules; no archive rotation")
	whmBaseURL := flag.String("whm-base-url", "https://127.0.0.1", "External HTTPS base URL used in WHM create_user_session login links (per-service port appended)")
	whmListen := flag.String("whm-listen", "", "Optional TLS WHM API ingress address, e.g. 0.0.0.0:2087; requires --whm-tls-cert/--whm-tls-key and --accounts-socket")
	whmTLSCert := flag.String("whm-tls-cert", "", "Operator-provided TLS certificate chain for the WHM ingress")
	whmTLSKey := flag.String("whm-tls-key", "", "Operator-provided TLS private key for the WHM ingress")
	dbDefaults := flag.String("db-defaults-file", "", "Option file with the panel database admin credentials (0600); empty uses socket auth as the invoking user")
	mailHomesFlag := flag.String("mail-homes", "/srv/sfn-mail", "Mailbox root for the mail surface (cPanel mail/ + etc/ layout; controller-writable)")
	dnsRoot := flag.String("dns-root", "/srv/sfn-dns", "DNS zone store root (BIND master files; maps to the reference's /var/named)")
	dnsReload := flag.String("dns-reload-cmd", "", "Program and plain arguments run after zone changes, executed without a shell (e.g. /usr/sbin/rndc reload)")
	dnsNS1 := flag.String("dns-ns1", "ns1.hostlelo.com", "Default first nameserver for account zones")
	dnsNS2 := flag.String("dns-ns2", "ns2.hostlelo.com", "Default second nameserver for account zones")
	dnsIP := flag.String("dns-ip", "127.0.0.1", "Default A-record address for account zones (set to the public web IP in production)")
	tlsRoot := flag.String("tls-root", "", "TLS certificate store root (installssl/listcrts); empty disables the TLS surface")
	acmeDirectory := flag.String("acme-directory", acme.LetsEncrypt, "ACME v2 directory URL for website certificates; the WHM AutoSSL surface uses it only when this flag is given")
	acmeEmail := flag.String("acme-email", "", "Contact email for the ACME account; with --accounts-socket it turns on website certificates (HTTP-01) and accepts the certificate authority's terms of service")
	acmeCAFile := flag.String("acme-ca-file", "", "Optional PEM bundle trusted for the ACME server only, instead of the system roots (a test CA such as Pebble)")
	acmeTestProbeLoopback := flag.Bool("acme-test-probe-loopback", false, "Test only: let the website aliases' reachability probe connect to loopback addresses, for a test CA such as Pebble whose DNS answers 127.0.0.1; refused unless --acme-directory names a loopback address. Never set in production")
	acmeInsecure := flag.Bool("acme-insecure-skip-verify", false, "Skip ACME directory TLS verification (test rigs with a private CA only; never in production)")
	acmeResolver := flag.String("acme-dns-resolver", "127.0.0.1:53", "Resolver used to confirm _acme-challenge TXT propagation before ACME validation")
	backupRoot := flag.String("backup-root", "", "Backup archive root; empty disables the backup surface")
	httpsListen := flag.String("https-listen", "", "Optional HTTPS address for the panel beyond loopback, e.g. 0.0.0.0:2083; only admin sign-in (password and code) works there")
	panelHosts := flag.String("panel-host", "", "Comma-separated host names or IPs the HTTPS listener answers for; required with --https-listen")
	tlsCert := flag.String("tls-cert", "", "Certificate chain for --https-listen; without it a self-signed certificate is kept in the state directory")
	tlsKey := flag.String("tls-key", "", "Private key for --tls-cert")
	dbSocket := flag.String("db-socket", "/var/lib/mysql/mysql.sock", "Local MariaDB unix socket; when reachable the database surface is enabled (fail-closed offline otherwise)")
	flag.Parse()
	given := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { given[f.Name] = true })
	host, port, err := net.SplitHostPort(*listen)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("this development workbench must bind an explicit loopback IP")
	}
	if *sitesListen != "" {
		websiteHost, _, e := net.SplitHostPort(*sitesListen)
		websiteIP := net.ParseIP(websiteHost)
		if e != nil || websiteIP == nil || !websiteIP.IsLoopback() {
			return errors.New("static website serving must bind an explicit loopback IP")
		}
	}
	dir, err := securestate.Dir(*state)
	if err != nil {
		return err
	}
	b, obligations, err := config.Load()
	if err != nil {
		return err
	}
	t, err := trail.Open(filepath.Join(dir, "trail"))
	if err != nil {
		return err
	}
	costs, err := budget.Open(filepath.Join(dir, "budget"), b.AIMonthlyCap)
	if err != nil {
		return err
	}
	access, err := operator.Open(filepath.Join(dir, "operator"))
	if err != nil {
		return err
	}
	websiteStore, err := sites.Open(filepath.Join(dir, "sites"), t)
	if err != nil {
		return err
	}
	defer websiteStore.Close()
	var uiFS fs.FS
	root, err := os.OpenRoot(*ui)
	if err == nil {
		defer root.Close()
		uiFS = root.FS()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	monitor := serverinfo.NewCollector()
	defer monitor.Close()
	server := &http.Server{Addr: *listen, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	servers := []*http.Server{server}
	listeners := []net.Listener{listener}
	previewPort := uint16(0)
	if *sitesListen != "" {
		websiteListener, e := net.Listen("tcp", *sitesListen)
		if e != nil {
			return e
		}
		defer websiteListener.Close()
		previewPort = uint16(websiteListener.Addr().(*net.TCPAddr).Port)
		servers = append(servers, &http.Server{Addr: *sitesListen, Handler: websiteStore.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10})
		listeners = append(listeners, websiteListener)
	}
	var whmHandler http.Handler
	var whmServer *whmapi.Server
	// The database service is built with the WHM transport and shared with
	// the website wizard, so both write the same registry.
	var dbSvc *dbhost.LocalService
	if *accountsSocket != "" {
		// WHM API 1 compatibility transport over the real account broker.
		// Tokens live in a root-only JSON file; an absent store denies all
		// credentials (fail closed) until token issuance lands with pr-access.
		tokens, terr := whmapi.OpenTokenStore(filepath.Join(dir, "whmapi-tokens.json"))
		if terr != nil {
			return terr
		}
		pkgs, perr := hostpkgs.Open(filepath.Join(dir, "packages.json"))
		if perr != nil {
			return perr
		}
		sessions, serr := whmapi.OpenSessionStore(filepath.Join(dir, "whmapi-sessions.json"))
		if serr != nil {
			return serr
		}
		whmBackend := whmapi.HostAccounts{
			Svc:    hostaccounts.NewClient(*accountsSocket),
			Build:  "11.138.0.11",
			Actor:  "whm-api",
			Server: "127.0.0.1",
		}
		whmServer = whmapi.New(whmBackend, tokens).WithPackageStore(pkgs).WithSessionStore(sessions, *whmBaseURL)
		mailHomes := *mailHomesFlag
		if err := os.MkdirAll(mailHomes, 0o755); err == nil {
			whmServer.SetMailService(&mailhost.LocalService{
				Homes: mailHomes,
				State: dir,
			})
		}
		reloadArgv, rerr := dnshost.ParseReloadCommand(*dnsReload)
		if rerr != nil {
			return rerr
		}
		dnsStore := &dnshost.Store{Root: *dnsRoot, Reload: dnshost.ExecReloader{Argv: reloadArgv}}
		whmServer.SetDNSStore(dnsStore)
		whmServer.SetDNSDefaults(*dnsNS1, *dnsNS2, *dnsIP)
		if *tlsRoot != "" {
			tlsStore := &tlshost.Store{Root: *tlsRoot}
			whmServer.SetTLSStore(tlsStore)
			// Before --acme-directory had a default, AutoSSL ran only when
			// it was given; that stays so.
			if *acmeDirectory != "" && given["acme-directory"] {
				acme := tlshost.NewACMEClient(*acmeDirectory, *acmeEmail, filepath.Join(*tlsRoot, "_acme"))
				if *acmeInsecure {
					acme.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // test rigs only
				}
				whmServer.SetAutoSSL(&tlshost.Runner{
					Store:     tlsStore,
					ACME:      acme,
					Publisher: whmapi.DNSChallengePublisher{DNS: dnsStore, ResolverAddr: *acmeResolver},
				})
			}
		}
		whmHandler = whmServer
		dbReg, dberr := dbhost.OpenRegistry(filepath.Join(dir, "dbmap.json"))
		if dberr != nil {
			return dberr
		}
		dbSvc = &dbhost.LocalService{
			Run:      dbhost.CLIRunner{Socket: *dbSocket, DefaultsFile: *dbDefaults},
			Registry: dbReg,
		}
		whmServer.SetDBService(dbSvc)
		if *backupRoot != "" {
			dumpOpts := []string{"--protocol=socket", "--socket=" + *dbSocket}
			if *dbDefaults != "" {
				dumpOpts = append([]string{"--defaults-extra-file=" + *dbDefaults}, dumpOpts...)
			}
			bs := &backuphost.Store{
				Root:         *backupRoot,
				MailHomes:    *mailHomesFlag,
				DNSRoot:      *dnsRoot,
				DumpOpts:     dumpOpts,
				PanelVersion: whmBackend.Build,
			}
			bs.Databases = func(ctx context.Context, account string) ([]string, error) {
				dbs, err := dbSvc.ListDatabases(ctx, account)
				if err != nil {
					return nil, err
				}
				names := make([]string, 0, len(dbs))
				for _, d := range dbs {
					names = append(names, d.Name)
				}
				return names, nil
			}
			bs.AccountDomains = func(account string) []string {
				for _, a := range whmBackend.ListAccounts() {
					if a.User == account && a.Domain != "" {
						return []string{a.Domain}
					}
				}
				return nil
			}
			whmServer.SetBackupStore(bs)
		}
	}
	var websiteJobs *wizard.Runner
	var siteBackups *sitebackups.Manager
	var certificates *acme.Manager
	if *accountsSocket != "" && dbSvc != nil {
		broker := hostaccounts.NewClient(*accountsSocket)
		web, okWeb := broker.(hostaccounts.WebService)
		wordpress, okWordPress := broker.(hostaccounts.WordPressService)
		placeholder, okPlaceholder := broker.(hostaccounts.PlaceholderService)
		if !okWeb || !okWordPress || !okPlaceholder {
			return errors.New("the account broker client lacks the web, WordPress or placeholder operation")
		}
		jobs, jerr := wizard.OpenStore(filepath.Join(dir, "wizard"))
		if jerr != nil {
			return jerr
		}
		// A nil interface, not a nil *acme.Manager: the wizard reads nil as
		// "certificates are not set up".
		var certs wizard.Certificates
		if *acmeEmail != "" {
			if installer := certificateInstaller(broker); installer == nil {
				fmt.Fprintln(os.Stderr, "Website certificates are off: the account broker client has no certificate operation, so new websites use http")
			} else {
				m, aerr := acme.New(acme.Config{Email: *acmeEmail, Directory: *acmeDirectory, CAFile: *acmeCAFile, StateDir: filepath.Join(dir, "acme"), TestProbeLoopback: *acmeTestProbeLoopback}, installer, brokerSites{broker})
				if aerr != nil {
					return aerr
				}
				certificates, certs = m, m
			}
		}
		websiteJobs = wizard.New(wizard.Broker{Service: broker, WebService: web, WordPressService: wordpress, PlaceholderService: placeholder}, dbSvc, jobs, certs)
		// Website backups: the broker runs restic; the panel schedules the
		// nightly backups, the weekly prune and drill, and the jobs a person
		// starts. Nothing runs until backup storage is set up.
		backupBroker, okBackups := broker.(sitebackups.Broker)
		if !okBackups {
			return errors.New("the account broker client lacks the backup operations")
		}
		if siteBackups, err = sitebackups.Open(sitebackups.StatePath(dir), backupBroker, dbSvc); err != nil {
			return err
		}
	}
	var remoteServer *http.Server
	var remoteListener net.Listener
	var remoteHosts []string
	var httpsNote string
	if *httpsListen != "" {
		hosts := splitHosts(*panelHosts)
		if len(hosts) == 0 {
			return errors.New("--https-listen needs --panel-host with the names people type to reach the panel")
		}
		cert, cerr := panelcert.Load(dir, *tlsCert, *tlsKey, hosts, time.Now())
		if cerr != nil {
			return cerr
		}
		listener, lerr := tls.Listen("tcp", *httpsListen, &tls.Config{Certificates: []tls.Certificate{cert.Certificate}, MinVersion: tls.VersionTLS12})
		if lerr != nil {
			return lerr
		}
		defer listener.Close()
		remote := &http.Server{Addr: *httpsListen, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
		remoteServer, remoteListener, remoteHosts = remote, listener, hosts
		kind := "operator-provided"
		if cert.SelfSigned {
			kind = "self-signed; browsers warn until you add --tls-cert"
		}
		httpsNote = fmt.Sprintf("Panel over HTTPS on %s for %s — admin sign-in only\nTLS certificate (%s), valid until %s, SHA-256 %s\n",
			*httpsListen, strings.Join(hosts, ", "), kind, cert.NotAfter.UTC().Format("2006-01-02"), cert.Fingerprint)
	}
	if *whmListen != "" {
		ingressListener, ingressServer, ierr := listenWHMIngress(*whmListen, *whmTLSCert, *whmTLSKey, whmHandler)
		if ierr != nil {
			return ierr
		}
		defer ingressListener.Close()
		servers = append(servers, ingressServer)
		listeners = append(listeners, ingressListener)
	}
	// A nil interface, not a nil *dbhost.LocalService: the API reads nil as
	// "databases are not set up".
	var siteDatabases api.Databases
	if dbSvc != nil {
		siteDatabases = dbSvc
	}
	// A nil interface, not a nil *acme.Manager, when certificates are off.
	var siteCertificates api.SiteCertificates
	if certificates != nil {
		siteCertificates = certificates
	}
	server.Handler = api.New(api.Options{Certificates: siteCertificates, PanelHosts: splitHosts(*panelHosts), Report: compat.Evaluate(b, obligations), Trail: t, Budget: costs, UI: uiFS, Server: monitor, Sites: websiteStore, Operator: access, Accounts: hostaccounts.NewClient(*accountsSocket), WebPreview: hostaccounts.NewWebPreviewClient(*accountsSocket), SitePreviewPort: &previewPort, BackupSchedulerEnabled: *backupScheduler, WHM: whmHandler, Wizard: websiteJobs, Databases: siteDatabases, Backups: siteBackups, AllowedOrigins: []string{"http://127.0.0.1:" + port, "http://localhost:" + port, "http://[::1]:" + port, "http://127.0.0.1:5173", "http://localhost:5173"}})
	if remoteServer != nil {
		// The same API, behind operator.Remote: only the panel's host names,
		// only TLS, and only admin sessions.
		remoteServer.Handler = operator.Remote(server.Handler, remoteHosts)
		servers = append(servers, remoteServer)
		listeners = append(listeners, remoteListener)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	if *backupScheduler {
		workerDone := make(chan struct{})
		go func() { defer close(workerDone); websiteStore.RunBackupScheduler(ctx) }()
		// Runs before the earlier Store.Close defer, including Serve failures.
		defer func() { stop(); <-workerDone }()
	} else {
		defer stop()
	}
	if certificates != nil {
		renewDone := make(chan struct{})
		go func() { defer close(renewDone); certificates.Run(ctx) }()
		defer func() { stop(); <-renewDone }()
	}
	if siteBackups != nil {
		backupsDone := make(chan struct{})
		go func() { defer close(backupsDone); siteBackups.Run(ctx) }()
		defer func() { stop(); <-backupsDone }()
	}
	done := make(chan error, len(servers))
	for i, running := range servers {
		go func(s *http.Server, l net.Listener) { done <- s.Serve(l) }(running, listeners[i])
	}
	fmt.Printf("Sifruno local workbench http://%s — compatibility unverified\n", *listen)
	if *sitesListen != "" {
		fmt.Printf("Local static website listener http://%s\n", *sitesListen)
	}
	fmt.Print(httpsNote)
	select {
	case err = <-done:
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, running := range servers {
		if e := running.Shutdown(shutdown); e != nil {
			err = errors.Join(err, e)
			_ = running.Close()
		}
	}
	return err
}

// certificateInstaller joins the account broker's certificate operation to
// the panel's acme.Installer; nil (certificates off) when the client has no
// such operation.
func certificateInstaller(service hostaccounts.Service) acme.Installer {
	certs, ok := service.(hostaccounts.CertificateService)
	if !ok {
		return nil
	}
	return brokerInstaller{certs}
}

// brokerInstaller installs an issued certificate through the broker's typed
// SetCertificate operation, which validates it again before it goes live.
type brokerInstaller struct {
	hostaccounts.CertificateService
}

func (b brokerInstaller) Install(ctx context.Context, accountID string, revision uint64, certPEM, keyPEM []byte) (uint64, time.Time, error) {
	res, err := b.SetCertificate(ctx, accountID, hostaccounts.CertificateInput{
		ExpectedRevision: revision,
		CertPEM:          string(certPEM),
		KeyPEM:           string(keyPEM),
		Reason:           "Let's Encrypt certificate",
	}, "panel certificates")
	if err != nil {
		return 0, time.Time{}, err
	}
	return res.Account.Revision, time.Unix(res.Certificate.NotAfter, 0), nil
}

// brokerSites lists the broker's accounts for the certificate renewal loop.
type brokerSites struct{ hostaccounts.Service }

func (b brokerSites) Sites(ctx context.Context) ([]acme.Site, error) {
	accounts, err := b.List(ctx)
	if err != nil {
		return nil, err
	}
	sites := make([]acme.Site, 0, len(accounts))
	for _, a := range accounts {
		sites = append(sites, certificateSite(a))
	}
	return sites, nil
}

// certificateSite is a broker account as the certificate manager sees it:
// its domain, its aliases, and the domains its certificate names.
func certificateSite(a hostaccounts.Account) acme.Site {
	site := acme.Site{AccountID: a.ID, Domain: a.Domain, Revision: a.Revision, Active: a.State == "active"}
	if a.SiteDomains != nil {
		site.Aliases = slices.Clone(a.SiteDomains.Aliases)
	}
	if a.Certificate.NotAfter > 0 {
		site.NotAfter = time.Unix(a.Certificate.NotAfter, 0)
	}
	if a.Certificate.Names != "" {
		site.Covered = strings.Split(a.Certificate.Names, ",")
	}
	return site
}

// splitHosts reads --panel-host: comma-separated, lower-cased, de-duplicated.
func splitHosts(value string) []string {
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(value, ",") {
		h := strings.ToLower(strings.TrimSpace(part))
		if h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}
