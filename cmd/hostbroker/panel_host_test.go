package main

import (
	"bytes"
	"context"
	"slices"
	"testing"

	"sifruno/internal/hostaccounts"
)

func brokerWithPanelHost(t *testing.T, value string, web bool) (int, *hostaccounts.WebOptions, string) {
	t.Helper()
	args := []string{"--state", "/private/state", "--socket", "/private/socket", "--homes", "/srv/managed", "--controller-uid", "2000", "--panel-host", value}
	if web {
		args = append(args, "--web-user", "nobody")
	}
	var out, errs bytes.Buffer
	var got *hostaccounts.WebOptions
	code := runWithPreviewServices(args, &out, &errs, func(context.Context) hostaccounts.HostPolicyReport {
		return hostaccounts.HostPolicyReport{}
	}, func(context.Context, hostaccounts.BrokerOptions) hostaccounts.BrokerAdmissionReport {
		return hostaccounts.BrokerAdmissionReport{}
	}, func(_ context.Context, _ hostaccounts.BrokerOptions, on features) error {
		got = on.web
		return nil
	})
	return code, got, errs.String()
}

// The panel's --panel-host value, as the installer writes it into both
// units: its DNS names reach the web operation, lower-cased and once each
// counting the www. form; an IP address has no vhost name and is left out.
func TestPanelHostReachesTheWebOperation(t *testing.T) {
	code, web, errs := brokerWithPanelHost(t, "Panel.Example.org, 203.0.113.9,www.panel.example.org,2001:db8::1,admin.example.org", true)
	if code != 0 || web == nil || !slices.Equal(web.PanelHosts, []string{"panel.example.org", "admin.example.org"}) || errs != "" {
		t.Fatalf("code %d, %+v, %q", code, web, errs)
	}
	code, web, _ = brokerWithPanelHost(t, "203.0.113.9", true)
	if code != 0 || web == nil || len(web.PanelHosts) != 0 {
		t.Fatalf("an IP alone: code %d, %+v", code, web)
	}
}

func TestPanelHostRefused(t *testing.T) {
	for name, value := range map[string]string{
		"one label":  "localhost",
		"a space":    "panel.example.org other",
		"a brace":    "panel.example.org{",
		"a newline":  "panel.example.org\nlistener x {",
		"a wildcard": "*.example.org",
	} {
		if code, web, errs := brokerWithPanelHost(t, value, true); code != 2 || web != nil || errs != "Invalid native broker configuration\n" {
			t.Errorf("%s: code %d, %+v, %q", name, code, web, errs)
		}
	}
	// The names are served by the web operation only.
	if code, _, _ := brokerWithPanelHost(t, "panel.example.org", false); code != 2 {
		t.Errorf("--panel-host without --web-user: code %d", code)
	}
}
