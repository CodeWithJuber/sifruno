package olsweb

import (
	"errors"
	"strings"
	"testing"
)

func phpSite(memoryMiB int, settings ...PHPSetting) Server {
	s := folderSite()
	s.Sites[0].Limits.MemoryMiB = memoryMiB
	s.Sites[0].PHPSettings = settings
	return s
}

func TestPHPSettingsValidation(t *testing.T) {
	ok := []PHPSetting{
		{Name: "date.timezone", Value: "America/Argentina/Buenos_Aires"},
		{Name: "display_errors", Value: "on", Flag: true},
		{Name: "error_reporting", Value: "-1"},
		{Name: "memory_limit", Value: "1G"},
		{Name: "output_buffering", Value: "4096"},
		{Name: "upload_max_filesize", Value: "134217728"},
	}
	if err := Validate(phpSite(1024, ok...)); err != nil {
		t.Fatal(err)
	}
	if err := CheckPHPSettings(ok, 1024); err != nil {
		t.Fatal(err)
	}
	bad := map[string]Server{
		"unknown name":         phpSite(0, PHPSetting{Name: "session.name", Value: "x"}),
		"file name":            phpSite(0, PHPSetting{Name: "auto_prepend_file", Value: "x.php"}),
		"engine":               phpSite(0, PHPSetting{Name: "engine", Value: "0"}),
		"upper name":           phpSite(0, PHPSetting{Name: "Memory_Limit", Value: "256M"}),
		"unsorted":             phpSite(0, PHPSetting{Name: "memory_limit", Value: "256M"}, PHPSetting{Name: "display_errors", Value: "on", Flag: true}),
		"twice":                phpSite(0, PHPSetting{Name: "memory_limit", Value: "256M"}, PHPSetting{Name: "memory_limit", Value: "128M"}),
		"flag value":           phpSite(0, PHPSetting{Name: "display_errors", Value: "On", Flag: true}),
		"flag word":            phpSite(0, PHPSetting{Name: "display_errors", Value: "yes", Flag: true}),
		"slash":                phpSite(0, PHPSetting{Name: "max_input_vars", Value: "/etc/passwd"}),
		"space":                phpSite(0, PHPSetting{Name: "max_input_vars", Value: "1 2"}),
		"newline":              phpSite(0, PHPSetting{Name: "max_input_vars", Value: "1\nphp_value auto_prepend_file x"}),
		"brace":                phpSite(0, PHPSetting{Name: "max_input_vars", Value: "1}"}),
		"quote":                phpSite(0, PHPSetting{Name: "max_input_vars", Value: `"1"`}),
		"empty":                phpSite(0, PHPSetting{Name: "max_input_vars", Value: ""}),
		"time zone dots":       phpSite(0, PHPSetting{Name: "date.timezone", Value: "Europe/../etc"}),
		"time zone path":       phpSite(0, PHPSetting{Name: "date.timezone", Value: "/etc/localtime"}),
		"memory above limit":   phpSite(512, PHPSetting{Name: "memory_limit", Value: "513M"}),
		"memory no limit":      phpSite(512, PHPSetting{Name: "memory_limit", Value: "-1"}),
		"memory above default": phpSite(0, PHPSetting{Name: "memory_limit", Value: "2G"}),
		"memory not a size":    phpSite(0, PHPSetting{Name: "memory_limit", Value: "lots"}),
	}
	for name, s := range bad {
		t.Run(name, func(t *testing.T) {
			var fe *FieldError
			if err := Validate(s); !errors.As(err, &fe) || !strings.HasPrefix(fe.Field, "sites[0].php_settings") {
				t.Fatalf("got %v", err)
			}
		})
	}
	many := make([]PHPSetting, MaxPHPSettings+1)
	for i := range many {
		many[i] = PHPSetting{Name: "memory_limit", Value: "1M"}
	}
	if err := Validate(phpSite(0, many...)); err == nil {
		t.Fatal("accepted more settings than the bound")
	}
}

func TestPHPSizeMiB(t *testing.T) {
	for v, want := range map[string]int{"256M": 256, "256m": 256, "1G": 1024, "1024K": 1, "1025K": 2, "134217728": 128, "0": 0} {
		if got, ok := PHPSizeMiB(v); !ok || got != want {
			t.Errorf("%s: %d %t, want %d", v, got, ok, want)
		}
	}
	for _, v := range []string{"-1", "", "1T", "1 M", "M", "9999999999999"} {
		if _, ok := PHPSizeMiB(v); ok {
			t.Errorf("%q read as a size", v)
		}
	}
}

func TestPHPSettingsRendered(t *testing.T) {
	s := phpSite(1024, PHPSetting{Name: "display_errors", Value: "off", Flag: true}, PHPSetting{Name: "memory_limit", Value: "256M"})
	files, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	vh := string(files[VhostConfigPath("blog")])
	block := "\nphpIniOverride  {\nphp_flag display_errors off\nphp_value memory_limit 256M\n}\n"
	if !strings.Contains(vh, block) {
		t.Fatalf("no phpIniOverride block:\n%s", vh)
	}
	if strings.Index(vh, block) < strings.Index(vh, "scripthandler") {
		t.Errorf("the block comes before the site's PHP:\n%s", vh)
	}
	if _, err := confShape(files[VhostConfigPath("blog")]); err != nil {
		t.Fatal(err)
	}
	// A suspended site runs no PHP and writes no settings.
	s.Sites[0].Suspended = true
	if files, err = Render(s); err != nil || strings.Contains(string(files[VhostConfigPath("blog")]), "phpIniOverride") {
		t.Fatalf("suspended site: %v\n%s", err, files[VhostConfigPath("blog")])
	}
	// No settings, no block.
	if files, err = Render(phpSite(0)); err != nil || strings.Contains(string(files[VhostConfigPath("blog")]), "phpIniOverride") {
		t.Fatalf("no settings: %v", err)
	}
}
