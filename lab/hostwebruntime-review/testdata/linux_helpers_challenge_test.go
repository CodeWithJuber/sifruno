//go:build linux

package hostwebruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// These are real cancellation/filesystem helpers, not an Apache/PHP-FPM runtime fixture.
func TestReviewCanceledAcquireCannotPoisonReservation(t *testing.T) {
	r := &Runtime{gate: make(chan struct{}, 1)}
	for i := 0; i < 256; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := r.acquire(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled acquire returned %v", err)
		}
		if len(r.gate) != 0 {
			t.Fatal("canceled acquire retained the gate token")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := r.acquire(ctx); err != nil {
		t.Fatal(err)
	}
	r.release()
}
func TestReviewCanceledWaiterCannotReleaseAnotherReservation(t *testing.T) {
	r := &Runtime{gate: make(chan struct{}, 1)}
	if err := r.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.acquire(ctx); !errors.Is(err, context.Canceled) || len(r.gate) != 1 {
		t.Fatal("canceled waiter changed the owner's token")
	}
	r.release()
}

func TestReviewArgvRequiresExactConfigAndRole(t *testing.T) {
	r := &Runtime{opts: Options{Profile: reviewProfile()}}
	config := filepath.Join(r.opts.Profile.ManagedRoot, "generations", strings.Repeat("1", 32), "apache/front.conf")
	pin := processPin{Role: "front", Executable: r.opts.Profile.ApacheBinary, Config: config}
	good := strings.Join([]string{pin.Executable, "-DFOREGROUND", "-f", config, "-d", r.opts.Profile.FrontChroot}, "\x00") + "\x00"
	if !commandMatches(r, pin, []byte(good)) {
		t.Fatal("exact front argv rejected")
	}
	for _, value := range []string{good + "extra\x00", strings.Replace(good, config, config+".other", 1), strings.Replace(good, "-DFOREGROUND", "-k", 1), strings.TrimSuffix(good, "\x00")} {
		if commandMatches(r, pin, []byte(value)) {
			t.Fatal("prefix/foreign config/extra argv admitted")
		}
	}
	pin.Role = "fpm"
	pin.Executable = r.opts.Profile.FPMBinary
	title := "php-fpm: master process (" + config + ")"
	if !commandMatches(r, pin, []byte(title+"\x00\x00")) {
		t.Fatal("exact documented FPM title rejected")
	}
	for _, value := range []string{title + " extra\x00", strings.Replace(title, config, config+".other", 1), "php-fpm: pool arbitrary\x00"} {
		if commandMatches(r, pin, []byte(value)) {
			t.Fatal("foreign FPM title/config admitted")
		}
	}
}

func TestReviewForeignControllerProcessCannotBeStopped(t *testing.T) {
	// The current test process is not a namespace-init owned daemon. No syscall signaling is authorized.
	r := &Runtime{opts: Options{Profile: reviewProfile()}, children: map[int]*os.Process{}}
	start, err := startIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	boot, err := bootID()
	if err != nil {
		t.Fatal(err)
	}
	namespace, err := namespaceID(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	current, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	pin := processPin{Role: "front", PID: os.Getpid(), Start: start, Boot: boot, Namespace: namespace, Executable: current, ExecutableSHA256: strings.Repeat("0", 64), Config: "/foreign.conf"}
	if err := r.verifyPin(pin); err == nil {
		t.Fatal("test controller was admitted as an owned namespace-init daemon")
	}
	if err := r.stop(&record{Processes: []processPin{pin}}); err == nil {
		t.Fatal("foreign process stop was admitted")
	}
}
func reviewDirectory(t *testing.T) (string, int) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root-owned Linux helper fixture required; skipped is unqualified")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	fd, err := checkedDir(root, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return root, fd
}
func TestReviewOpenBelowRefusesTraversalSymlinkHardlinkAndModes(t *testing.T) {
	root, fd := reviewDirectory(t)
	outside := t.TempDir()
	sentinel := filepath.Join(outside, "sentinel")
	if err := os.WriteFile(sentinel, []byte("outside must remain unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../sentinel", sentinel, "escape/sentinel"} {
		child, err := openBelow(fd, name, unix.O_WRONLY|unix.O_TRUNC, 0)
		if err == nil {
			unix.Close(child)
			t.Fatalf("admitted escaping write path %q", name)
		}
	}
	if err := os.Link(sentinel, filepath.Join(root, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if _, err := readBelow(fd, "hardlink", 0600, 128); err == nil {
		t.Fatal("admitted hardlinked managed input")
	}
	if err := os.WriteFile(filepath.Join(root, "wrong-mode"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readBelow(fd, "wrong-mode", 0600, 128); err == nil {
		t.Fatal("admitted public managed input mode")
	}
	if err := writeExclusive(fd, "hardlink", []byte("replacement")); err == nil {
		t.Fatal("exclusive write overwrote an existing link")
	}
	if bytes, err := os.ReadFile(sentinel); err != nil || string(bytes) != "outside must remain unchanged" {
		t.Fatal("escape challenge mutated outside sentinel")
	}
}
func TestReviewStagedBundleRejectsCorruptionExtraInventoryAndDirectoryMode(t *testing.T) {
	for _, mutation := range []string{"bytes", "extra", "directory-mode", "hardlink"} {
		t.Run(mutation, func(t *testing.T) {
			root, fd := reviewDirectory(t)
			p := reviewProfile()
			r := &Runtime{fd: fd, opts: Options{Root: "/srv/sifruno-review", Profile: p}}
			if err := mkdirBelow(fd, "generations"); err != nil {
				t.Fatal(err)
			}
			g := reviewGeneration(t, p, false, false)
			if err := r.stage(g); err != nil {
				t.Fatal(err)
			}
			if err := r.disk(g); err != nil {
				t.Fatal(err)
			}
			config := filepath.Join(root, generationPath(g), "apache/front.conf")
			switch mutation {
			case "bytes":
				if err := os.WriteFile(config, []byte("corrupted actual bytes"), 0600); err != nil {
					t.Fatal(err)
				}
			case "extra":
				if err := os.WriteFile(filepath.Join(root, generationPath(g), "apache/unexpected.conf"), []byte("unexpected"), 0600); err != nil {
					t.Fatal(err)
				}
			case "directory-mode":
				if err := os.Chmod(filepath.Dir(config), 0777); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(config, filepath.Join(t.TempDir(), "alias")); err != nil {
					t.Fatal(err)
				}
			}
			if err := r.disk(g); err == nil {
				t.Fatal("corrupted/substituted bundle remained admitted")
			}
			if err := r.stage(g); err == nil {
				t.Fatal("existing corrupted generation was silently reused")
			}
		})
	}
}

func TestReviewActualMetadataReadRejectsCorruptionAndTrailingJSON(t *testing.T) {
	for _, mutation := range []string{"unknown-field", "trailing-json", "profile-hash", "input-hash", "hardlink"} {
		t.Run(mutation, func(t *testing.T) {
			root, fd := reviewDirectory(t)
			p := reviewProfile()
			r := &Runtime{fd: fd, opts: Options{Root: "/srv/sifruno-review", Profile: p}, inputsSHA: strings.Repeat("0", 64)}
			if err := mkdirBelow(fd, "generations"); err != nil {
				t.Fatal(err)
			}
			g := reviewGeneration(t, p, true, true)
			if err := r.stage(g); err != nil {
				t.Fatal(err)
			}
			v := record{Version: 1, Current: g, InputsSHA256: r.inputsSHA}
			if err := r.persist(v); err != nil {
				t.Fatal(err)
			}
			if _, err := r.load(); err != nil {
				t.Fatal(err)
			}
			statePath := filepath.Join(root, "state.json")
			bytes, err := os.ReadFile(statePath)
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "unknown-field":
				var fields map[string]any
				if err := json.Unmarshal(bytes, &fields); err != nil {
					t.Fatal(err)
				}
				fields["invented_field"] = true
				bytes, err = json.Marshal(fields)
			case "trailing-json":
				bytes = append(bytes, []byte("\n{}\n")...)
			case "profile-hash":
				v.Current.ProfileSHA256 = strings.Repeat("f", 64)
				bytes, err = json.Marshal(metadataCopy(v))
			case "input-hash":
				v.InputsSHA256 = strings.Repeat("f", 64)
				bytes, err = json.Marshal(metadataCopy(v))
			case "hardlink":
				err = os.Link(statePath, filepath.Join(t.TempDir(), "state-alias"))
			}
			if err != nil {
				t.Fatal(err)
			}
			if mutation != "hardlink" {
				if err := os.WriteFile(statePath, bytes, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := r.load(); err == nil {
				t.Fatal("corrupted actual metadata read remained admitted")
			}
			reopened := &Runtime{fd: fd, opts: r.opts, inputsSHA: r.inputsSHA}
			if _, err := reopened.load(); err == nil {
				t.Fatal("corrupt metadata admitted on fresh helper reopen without prior hash memory")
			}
			if after, err := os.ReadFile(statePath); err != nil || string(after) != string(bytes) {
				t.Fatal("metadata refusal rewrote corrupt evidence")
			}
		})
	}
}

func TestReviewActualStorageReservesDeniedRecoverySlots(t *testing.T) {
	_, fd := reviewDirectory(t)
	p := reviewProfile()
	r := &Runtime{fd: fd, opts: Options{Root: "/srv/sifruno-review", Profile: p}}
	if MaxGenerations < 3 {
		t.Fatal("generation bound cannot reserve recovery")
	}
	if err := mkdirBelow(fd, "generations"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxGenerations-2; i++ {
		g := reviewGeneration(t, p, false, false)
		g.ID = fmt.Sprintf("%032x", i+1)
		if err := r.stage(g); err != nil {
			t.Fatalf("supported active generation %d rejected: %v", i+1, err)
		}
	}
	blocked := reviewGeneration(t, p, false, false)
	blocked.ID = fmt.Sprintf("%032x", MaxGenerations-1)
	if err := r.stage(blocked); !errors.Is(err, ErrLimit) {
		t.Fatal("new active config consumed reserved denied recovery capacity")
	}
	for _, id := range []int{MaxGenerations - 1, MaxGenerations} {
		denied := reviewGeneration(t, p, true, false)
		denied.ID = fmt.Sprintf("%032x", id)
		if err := r.stage(denied); err != nil {
			t.Fatal("reserved actual denied generation could not be staged")
		}
	}
	denied := reviewGeneration(t, p, true, false)
	denied.ID = fmt.Sprintf("%032x", MaxGenerations+1)
	if err := r.stage(denied); !errors.Is(err, ErrLimit) {
		t.Fatal("absolute generation bound exceeded")
	}
	existing := reviewGeneration(t, p, false, false)
	existing.ID = fmt.Sprintf("%032x", 1)
	if err := r.stage(existing); err != nil {
		t.Fatal("immutable existing config cannot be reused at the cap")
	}
}
