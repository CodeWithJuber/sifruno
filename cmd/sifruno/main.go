package main

import (
	"context"
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
	"sifruno/internal/budget"
	"sifruno/internal/compat"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/hostpkgs"
	"sifruno/internal/operator"
	"sifruno/internal/securestate"
	"sifruno/internal/serverinfo"
	"sifruno/internal/sites"
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
		whmHandler = whmapi.New(whmapi.HostAccounts{
			Svc:    hostaccounts.NewClient(*accountsSocket),
			Build:  "11.138.0.11",
			Actor:  "whm-api",
			Server: "127.0.0.1",
		}, tokens).WithPackageStore(pkgs)
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
