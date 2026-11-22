package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sifruno/config"
	"sifruno/internal/budget"
	"sifruno/internal/compat"
	"sifruno/internal/evidence"
	"sifruno/internal/platform"
	"sifruno/internal/securestate"
	"sifruno/internal/trail"
)

const usage = `panelctl [--state .state/sifruno] [--panel-url http://127.0.0.1:8080] COMMAND
 status [--require-ready]                 compatibility evidence gate
 platform                                 current/legacy target profiles
 evidence compare REFERENCE CANDIDATE      sealed bundle comparison
 trail list | verify
 trail checkpoint --root DIR --paths a,b --reason TEXT --actor NAME
 trail seal ID | rollback ID              scoped files only; quiesce writers
 budget status
 budget approve --operation SHA256 --revision REV --actor NAME --max-micros N [--ttl 10m]
 budget reserve --id ID --approval ID --operation SHA256 --revision REV --micros N
 budget settle --id ID --actual-micros N   requires reconciled actual usage
 sites list | create --name NAME --domain DOMAIN
 sites show | files | read | backups --id ID [--path PATH]
 sites write --id ID --path PATH --from FILE --revision N [--sha256 SHA]
 sites state --id ID --state active|suspended --revision N
 sites backup --id ID --revision N
 sites backup-schedule --id ID
 sites backup-schedule-set --id ID --revision N --schedule-revision N --interval hourly|daily|weekly --enabled true|false
 sites restore --id ID --backup ID --revision N
 sites restore-preview --id ID --backup ID --revision N
 sites export --id ID --backup ID --out NEW.zip
 sites import --name NAME --domain DOMAIN --from NATIVE.zip
 backup inspect --from FILE --out NEW.jsonl
 htaccess scan --root DIR [--layout cpanel|dir|single] [--json] [--details]
 accounts capability | list | web-preview
 whm-token create --user USER --name NAME | list | revoke --name NAME
 accounts create --username USER --domain DOMAIN --reason TEXT
 accounts state --id ID --state active|suspended --revision N --reason TEXT
 migrate verify --old URL --new URL [--new-connect HOST:PORT] [--pages N] [--path P]...
   [--probe auth:P|deny:P]... [--probes-file FILE] [--insecure-new-tls] [--accept-warnings]
   [--json] [--out NEW.json]              compare old and new site; exit 3 = cutover locked
Local operator commands; sites require the running panel and its private access.key.
Accounts require the local panel, its access.key and a separately installed Linux broker.
Account suspension restricts new PAM-aware access; existing processes and mail are unaffected.
Sites manage app-owned static files only. Original WHM/cPanel compatibility is unverified.
ZIP transfer supports native Sifruno v1 static-site archives only, not cPanel host backups.
Backup inspect catalogs an original TAR/TAR.GZ without extracting files or contacting a panel.
Migrate verify sends credential-free GETs only; it compares pages and closed URLs, not
screenshots, databases, mail, DNS or SSL.
Htaccess scan only reads files; it prints counts, and paths or account names only with --details.
`

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string, out, errs io.Writer) error {
	global := flag.NewFlagSet("panelctl", flag.ContinueOnError)
	global.SetOutput(errs)
	state := global.String("state", ".state/sifruno", "Private application-owned state")
	panelURL := global.String("panel-url", "http://127.0.0.1:8080", "Explicit loopback panel URL for authenticated site commands")
	if err := global.Parse(args); err != nil {
		return err
	}
	args = global.Args()
	if len(args) == 0 || args[0] == "help" {
		fmt.Fprint(out, usage)
		return nil
	}
	if args[0] == "backup" {
		return runBackup(args[1:], out)
	}
	emit := func(v any) error { e := json.NewEncoder(out); e.SetIndent("", "  "); return e.Encode(v) }
	baseline, obligations, err := config.Load()
	if err != nil {
		return err
	}
	switch args[0] {
	case "sites":
		return runSites(args[1:], *state, *panelURL, out, errs)
	case "accounts":
		return runAccounts(args[1:], *state, *panelURL, out, errs)
	case "whm-token":
		return runWHMToken(args[1:], *state, out, errs)
	case "migrate":
		return runMigrate(args[1:], out, errs)
	case "htaccess":
		return runHtaccess(args[1:], out)
	case "status":
		f := flag.NewFlagSet("status", flag.ContinueOnError)
		f.SetOutput(errs)
		required := f.Bool("require-ready", false, "Exit nonzero unless compatible")
		if err = f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return errors.New("unexpected status arguments")
		}
		report := compat.Evaluate(baseline, obligations)
		if err = emit(report); err != nil {
			return err
		}
		if *required && !report.Ready {
			return errors.New("compatibility is unverified; readiness gate failed")
		}
		return nil
	case "platform":
		if len(args) != 1 {
			return errors.New("platform takes no arguments")
		}
		return emit(platform.Current())
	case "evidence":
		if len(args) != 4 || args[1] != "compare" {
			return errors.New("usage: evidence compare REFERENCE CANDIDATE")
		}
		read := func(path string) (evidence.Bundle, error) {
			f, e := os.Open(path)
			if e != nil {
				return evidence.Bundle{}, e
			}
			defer f.Close()
			return evidence.Load(f)
		}
		a, e := read(args[2])
		if e != nil {
			return e
		}
		b, e := read(args[3])
		if e != nil {
			return e
		}
		comparison, e := evidence.Compare(a, b)
		if e != nil {
			return e
		}
		return emit(comparison)
	case "trail", "budget": // Local stateful commands below.
	default:
		return fmt.Errorf("unknown command %q; run panelctl help", args[0])
	}
	if len(args) < 2 {
		return errors.New("subcommand required")
	}
	dir, err := securestate.Dir(*state)
	if err != nil {
		return err
	}
	if args[0] == "trail" {
		store, e := trail.Open(filepath.Join(dir, "trail"))
		if e != nil {
			return e
		}
		switch args[1] {
		case "list":
			if len(args) != 2 {
				return errors.New("trail list takes no arguments")
			}
			items, e := store.List()
			if e != nil {
				return e
			}
			return emit(map[string]any{"items": items})
		case "verify":
			if len(args) != 2 {
				return errors.New("trail verify takes no arguments")
			}
			if e = store.Verify(); e != nil {
				return e
			}
			return emit(map[string]bool{"journal_integrity_verified": true, "certifies_host_backup": false})
		case "checkpoint":
			f := flag.NewFlagSet("checkpoint", flag.ContinueOnError)
			f.SetOutput(errs)
			root := f.String("root", "", "Root directory")
			paths := f.String("paths", "", "Comma-separated relative files")
			reason := f.String("reason", "", "Reason")
			actor := f.String("actor", "", "Operator")
			if e = f.Parse(args[2:]); e != nil {
				return e
			}
			if f.NArg() != 0 || *root == "" || *paths == "" || *reason == "" || *actor == "" {
				return errors.New("checkpoint requires root, paths, reason and actor")
			}
			s, e := store.Checkpoint(*root, strings.Split(*paths, ","), *reason, *actor)
			if e != nil {
				return e
			}
			return emit(s)
		case "seal", "rollback":
			if len(args) != 3 {
				return errors.New("seal/rollback requires exactly one checkpoint id")
			}
			var s trail.Summary
			if args[1] == "seal" {
				s, e = store.Seal(args[2])
			} else {
				s, e = store.Rollback(args[2])
			}
			if e != nil {
				return e
			}
			return emit(s)
		default:
			return errors.New("unknown trail subcommand")
		}
	}
	store, err := budget.Open(filepath.Join(dir, "budget"), baseline.AIMonthlyCap)
	if err != nil {
		return err
	}
	if args[1] == "status" {
		if len(args) != 2 {
			return errors.New("budget status takes no arguments")
		}
		st, e := store.Status()
		if e != nil {
			return e
		}
		return emit(st)
	}
	f := flag.NewFlagSet(args[1], flag.ContinueOnError)
	f.SetOutput(errs)
	switch args[1] {
	case "approve":
		operation := f.String("operation", "", "Operation SHA256")
		revision := f.String("revision", "", "Relevant state revision")
		actor := f.String("actor", "", "Approving operator")
		max := f.Int64("max-micros", 0, "Worst-case USD micros")
		ttl := f.Duration("ttl", 10*time.Minute, "Expiry, max 20m")
		if err = f.Parse(args[2:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return errors.New("unexpected approval arguments")
		}
		a, e := store.Approve(*operation, *revision, *actor, *max, *ttl)
		if e != nil {
			return e
		}
		return emit(a)
	case "reserve":
		id := f.String("id", "", "Call id")
		approval := f.String("approval", "", "Local approval id")
		operation := f.String("operation", "", "Operation SHA256")
		revision := f.String("revision", "", "Current relevant revision")
		amount := f.Int64("micros", 0, "Worst-case USD micros")
		if err = f.Parse(args[2:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return errors.New("unexpected reservation arguments")
		}
		r, e := store.Reserve(*id, *approval, *operation, *revision, *amount)
		if e != nil {
			return e
		}
		return emit(r)
	case "settle":
		id := f.String("id", "", "Call id")
		actual := f.Int64("actual-micros", -1, "Reconciled USD micros")
		if err = f.Parse(args[2:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return errors.New("unexpected settlement arguments")
		}
		r, e := store.Settle(*id, *actual)
		if e != nil {
			return e
		}
		return emit(r)
	default:
		return errors.New("unknown budget subcommand")
	}
}
