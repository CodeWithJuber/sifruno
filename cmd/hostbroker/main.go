package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sifruno/internal/hostaccounts"
	"strings"
	"syscall"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWithServices(args, stdout, stderr, hostaccounts.CheckHostPolicy, hostaccounts.RunBroker)
}

func runWithServices(args []string, stdout, stderr io.Writer, probe func(context.Context) hostaccounts.HostPolicyReport, serve func(context.Context, hostaccounts.BrokerOptions) error) int {
	// This diagnostic is standalone. Reject diagnostic tokens before flag.Parse
	// can consume one as the value of a serving option.
	if len(args) == 1 && args[0] == "--check-host" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		report := probe(ctx)
		if json.NewEncoder(stdout).Encode(report) != nil {
			fmt.Fprintln(stderr, "Unable to write native host policy report")
			return 1
		}
		if !report.Supported {
			return 1
		}
		return 0
	}
	for _, arg := range args {
		key, _, _ := strings.Cut(arg, "=")
		if key == "--check-host" || key == "-check-host" {
			fmt.Fprintln(stderr, "Invalid native broker configuration")
			return 2
		}
	}
	f := flag.NewFlagSet("hostbroker", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	opts := hostaccounts.BrokerOptions{}
	f.StringVar(&opts.StateDir, "state", "", "New dedicated root-only broker state")
	f.StringVar(&opts.SocketPath, "socket", "", "Exclusive absolute Unix socket")
	f.StringVar(&opts.HomesDir, "homes", "", "Dedicated managed home parent")
	uid := f.Uint("controller-uid", 0, "Existing non-root controller UID")
	if f.Parse(args) != nil || f.NArg() != 0 || *uid == 0 || uint64(*uid) > uint64(^uint32(0)) {
		fmt.Fprintln(stderr, "Invalid native broker configuration")
		return 2
	}
	opts.ControllerUID = uint32(*uid)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if serve(ctx, opts) != nil {
		fmt.Fprintln(stderr, "Native broker unavailable or recovery required")
		return 1
	}
	return 0
}
