package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"sifruno/internal/hostaccounts"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(runWithServices(ctx, os.Args[1:], os.Stdout, os.Stderr,
		hostaccounts.CheckControllerLayout, hostaccounts.PrepareControllerLayout))
}

type layoutService func(context.Context, hostaccounts.LayoutOptions) hostaccounts.LayoutReport

func runWithServices(parent context.Context, args []string, stdout, stderr io.Writer, plan, apply layoutService) int {
	mode, opts, ok := layoutOptions(args)
	if !ok {
		fmt.Fprintln(stderr, "Invalid controller layout configuration")
		return 2
	}
	// This deadline is cooperative: synchronous filesystem operations cannot be
	// preempted. The layout service must check cancellation between operations.
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	service := plan
	if mode == "--apply" {
		service = apply
	}
	report := service(ctx, opts)
	if json.NewEncoder(stdout).Encode(report) != nil {
		fmt.Fprintln(stderr, "Unable to write controller layout report")
		return 1
	}
	if !report.Ready {
		return 1
	}
	return 0
}

func layoutOptions(args []string) (string, hostaccounts.LayoutOptions, bool) {
	opts := hostaccounts.LayoutOptions{}
	if len(args) != 11 || (args[0] != "--plan" && args[0] != "--apply") {
		return "", opts, false
	}
	seen := make(map[string]bool, 5)
	for i := 1; i < len(args); i += 2 {
		key, value := args[i], args[i+1]
		if seen[key] || value == "" || strings.HasPrefix(value, "-") {
			return "", hostaccounts.LayoutOptions{}, false
		}
		seen[key] = true
		switch key {
		case "--state":
			opts.BrokerOptions.StateDir = value
		case "--socket":
			opts.BrokerOptions.SocketPath = value
		case "--homes":
			opts.BrokerOptions.HomesDir = value
		case "--controller-state":
			opts.ControllerStateDir = value
		case "--controller-uid":
			uid, err := strconv.ParseUint(value, 10, 32)
			if err != nil || uid == 0 || strconv.FormatUint(uid, 10) != value {
				return "", hostaccounts.LayoutOptions{}, false
			}
			opts.BrokerOptions.ControllerUID = uint32(uid)
		default:
			return "", hostaccounts.LayoutOptions{}, false
		}
	}
	return args[0], opts, true
}
