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
	"strconv"
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
	return runWithAllServices(args, stdout, stderr, probe, hostaccounts.CheckBrokerAdmission, serve)
}

func runWithAllServices(args []string, stdout, stderr io.Writer, probe func(context.Context) hostaccounts.HostPolicyReport, admission func(context.Context, hostaccounts.BrokerOptions) hostaccounts.BrokerAdmissionReport, serve func(context.Context, hostaccounts.BrokerOptions) error) int {
	if len(args) > 0 && args[0] == "--check-startup" {
		opts, ok := startupOptions(args[1:])
		if !ok {
			fmt.Fprintln(stderr, "Invalid native broker configuration")
			return 2
		}
		// The deadline is cooperative: synchronous metadata probes are not
		// preempted. Cancellation causes the report to discard partial checks.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		report := admission(ctx, opts)
		if json.NewEncoder(stdout).Encode(report) != nil {
			fmt.Fprintln(stderr, "Unable to write native broker startup admission report")
			return 1
		}
		if !report.Supported {
			return 1
		}
		return 0
	}
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
		if key == "--check-host" || key == "-check-host" || key == "--check-startup" || key == "-check-startup" {
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

func startupOptions(args []string) (hostaccounts.BrokerOptions, bool) {
	opts := hostaccounts.BrokerOptions{}
	if len(args) != 8 {
		return opts, false
	}
	seen := map[string]bool{}
	for i := 0; i < len(args); i += 2 {
		key, value := args[i], args[i+1]
		if seen[key] || value == "" || strings.HasPrefix(value, "-") {
			return opts, false
		}
		seen[key] = true
		switch key {
		case "--state":
			opts.StateDir = value
		case "--socket":
			opts.SocketPath = value
		case "--homes":
			opts.HomesDir = value
		case "--controller-uid":
			for _, c := range value {
				if c < '0' || c > '9' {
					return opts, false
				}
			}
			uid, e := strconv.ParseUint(value, 10, 32)
			if e != nil || uid == 0 {
				return opts, false
			}
			opts.ControllerUID = uint32(uid)
		default:
			return opts, false
		}
	}
	return opts, true
}
