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
	"syscall"
	"time"

	"sifruno/config"
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
	"sifruno/internal/securestate"
	"sifruno/internal/serverinfo"
	"sifruno/internal/sites"
	"sifruno/internal/tlshost"
	"sifruno/internal/trail"
	"sifruno/internal/whmapi"
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
	dnsReload := flag.String("dns-reload-cmd", "", "Command run after zone changes to notify the authoritative server (e.g. named reload)")
	dnsNS1 := flag.String("dns-ns1", "ns1.hostlelo.com", "Default first nameserver for account zones")
	dnsNS2 := flag.String("dns-ns2", "ns2.hostlelo.com", "Default second nameserver for account zones")
	dnsIP := flag.String("dns-ip", "127.0.0.1", "Default A-record address for account zones (set to the public web IP in production)")
	tlsRoot := flag.String("tls-root", "", "TLS certificate store root (installssl/listcrts); empty disables the TLS surface")
	acmeDirectory := flag.String("acme-directory", "", "ACME v2 directory URL for AutoSSL issuance (e.g. Let's Encrypt staging/production); empty disables AutoSSL")
	acmeEmail := flag.String("acme-email", "", "Contact email for the ACME account")
	acmeInsecure := flag.Bool("acme-insecure-skip-verify", false, "Skip ACME directory TLS verification (test rigs with a private CA only; never in production)")
	acmeResolver := flag.String("acme-dns-resolver", "127.0.0.1:53", "Resolver used to confirm _acme-challenge TXT propagation before ACME validation")
	backupRoot := flag.String("backup-root", "", "Backup archive root; empty disables the backup surface")
	dbSocket := flag.String("db-socket", "/var/lib/mysql/mysql.sock", "Local MariaDB unix socket; when reachable the database surface is enabled (fail-closed offline otherwise)")
	flag.Parse()
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
		dnsStore := &dnshost.Store{Root: *dnsRoot, Reload: dnshost.ExecReloader{Command: *dnsReload}}
		whmServer.SetDNSStore(dnsStore)
		whmServer.SetDNSDefaults(*dnsNS1, *dnsNS2, *dnsIP)
		if *tlsRoot != "" {
			tlsStore := &tlshost.Store{Root: *tlsRoot}
			whmServer.SetTLSStore(tlsStore)
			if *acmeDirectory != "" {
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
		dbSvc := &dbhost.LocalService{
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
	if *whmListen != "" {
		ingressListener, ingressServer, ierr := listenWHMIngress(*whmListen, *whmTLSCert, *whmTLSKey, whmHandler)
		if ierr != nil {
			return ierr
		}
		defer ingressListener.Close()
		servers = append(servers, ingressServer)
		listeners = append(listeners, ingressListener)
	}
	server.Handler = api.New(api.Options{Report: compat.Evaluate(b, obligations), Trail: t, Budget: costs, UI: uiFS, Server: monitor, Sites: websiteStore, Operator: access, Accounts: hostaccounts.NewClient(*accountsSocket), WebPreview: hostaccounts.NewWebPreviewClient(*accountsSocket), SitePreviewPort: &previewPort, BackupSchedulerEnabled: *backupScheduler, WHM: whmHandler, AllowedOrigins: []string{"http://127.0.0.1:" + port, "http://localhost:" + port, "http://[::1]:" + port, "http://127.0.0.1:5173", "http://localhost:5173"}})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	if *backupScheduler {
		workerDone := make(chan struct{})
		go func() { defer close(workerDone); websiteStore.RunBackupScheduler(ctx) }()
		// Runs before the earlier Store.Close defer, including Serve failures.
		defer func() { stop(); <-workerDone }()
	} else {
		defer stop()
	}
	done := make(chan error, len(servers))
	for i, running := range servers {
		go func(s *http.Server, l net.Listener) { done <- s.Serve(l) }(running, listeners[i])
	}
	fmt.Printf("Sifruno local workbench http://%s — compatibility unverified\n", *listen)
	if *sitesListen != "" {
		fmt.Printf("Local static website listener http://%s\n", *sitesListen)
	}
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
