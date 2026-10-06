package hostaccounts_test

import (
	"context"
	"testing"

	"sifruno/internal/hostaccounts"
	"sifruno/internal/hostweb"
	"sifruno/internal/hostwebpreview"
)

func TestActualCompilerStoreBrokerClientPreview(t *testing.T) {
	profile := hostwebpreview.BrokerProfile(hostaccounts.BrokerOptions{HomesDir: "/srv/fixture-managed", ControllerUID: 2000})
	client, drift := hostaccounts.WebPreviewFixtureForTest(t, func(provider hostaccounts.SnapshotProvider) hostaccounts.WebPreviewService {
		return hostwebpreview.New(profile, provider)
	})
	expected, err := hostweb.Compile(profile, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.Preview(context.Background())
	if err != nil || got.Accounts != 0 || len(got.Files) != 1 || got.BundleSHA256 != expected.SHA256 || got.Files[0].SHA256 != expected.Files[0].SHA256 {
		t.Fatal("real composition did not return compiler result", err)
	}
	drift()
	got, err = client.Preview(context.Background())
	if err == nil || got.Files != nil || got.BundleSHA256 != "" {
		t.Fatal("drift leaked a preview")
	}
}
