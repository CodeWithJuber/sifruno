package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"sifruno/internal/htaccess"
)

var errHtaccessUsage = errors.New("usage: panelctl htaccess scan --root DIR [--layout cpanel|dir|single] [--json] [--details]")

// runHtaccess only reads the tree below --root. It does not initialize panel
// state, authentication or network clients. The scan runs on servers holding
// customer data and its aggregate is what gets shared, so account names,
// domains and paths appear only with --details.
func runHtaccess(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "scan" {
		return errHtaccessUsage
	}
	f := flag.NewFlagSet("htaccess scan", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	root := f.String("root", "", "Directory to scan")
	layoutName := f.String("layout", string(htaccess.LayoutSingle), "cpanel, dir or single")
	asJSON := f.Bool("json", false, "Print the report as JSON")
	details := f.Bool("details", false, "Include per-site paths and findings")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 || *root == "" {
		return errHtaccessUsage
	}
	layout, err := htaccess.ParseLayout(*layoutName)
	if err != nil {
		return errHtaccessUsage
	}
	report, err := htaccess.Scan(*root, layout, htaccess.DefaultLimits())
	if err != nil {
		return errors.New("htaccess scan: the root cannot be opened as a directory")
	}
	if !*details {
		report.Sites = nil
	}
	if *asJSON {
		e := json.NewEncoder(out)
		e.SetIndent("", "  ")
		return e.Encode(report)
	}
	_, err = io.WriteString(out, htaccessSummary(report, *details))
	return err
}

func htaccessSummary(r htaccess.Report, details bool) string {
	t := r.Totals
	var b strings.Builder
	fmt.Fprintf(&b, ".htaccess scan, layout %s (read-only)\n", r.Layout)
	fmt.Fprintf(&b, "sites: %d (native %d, convertible %d, compat %d)\n", t.Sites,
		t.SitesByVerdict[htaccess.VerdictNative], t.SitesByVerdict[htaccess.VerdictConvertible], t.SitesByVerdict[htaccess.VerdictCompat])
	fmt.Fprintf(&b, "sites without .htaccess: %d\n", t.SitesWithoutHtaccess)
	fmt.Fprintf(&b, ".htaccess files: %d (native %d, convertible %d, compat %d, not readable %d)\n", t.Files,
		t.FilesByVerdict[htaccess.VerdictNative], t.FilesByVerdict[htaccess.VerdictConvertible], t.FilesByVerdict[htaccess.VerdictCompat], t.UnreadableFiles)
	fmt.Fprintf(&b, "directives: %d\n", t.Directives)
	for _, c := range htaccess.Categories {
		fmt.Fprintf(&b, "  %s: %d\n", c, t.DirectivesByCategory[c])
	}
	b.WriteString("compat sites by cause:\n")
	for _, c := range htaccess.Causes {
		fmt.Fprintf(&b, "  %s: %d\n", c, t.CompatSitesByCause[c])
	}
	sets := make([]string, 0, len(t.CompatSitesByCauseSet))
	for set := range t.CompatSitesByCauseSet {
		sets = append(sets, set)
	}
	sort.Strings(sets)
	b.WriteString("compat sites by cause combination:\n")
	for _, set := range sets {
		fmt.Fprintf(&b, "  %s: %d\n", set, t.CompatSitesByCauseSet[set])
	}
	fmt.Fprintf(&b, "compat sites caused only by nested .htaccess files: %d\n", t.CompatSitesNestedOnly)
	fmt.Fprintf(&b, "symbolic links not followed: %d\n", t.SymlinkedDirsNotFollowed)
	if r.Layout == htaccess.LayoutCPanel {
		fmt.Fprintf(&b, "accounts without a document root: %d\n", t.AccountsWithoutDocroot)
	}
	fmt.Fprintf(&b, "unreadable directories: %d\n", t.UnreadableDirs)
	fmt.Fprintf(&b, "truncated sites: %d\n", t.TruncatedSites)
	if r.SitesLimitReached {
		b.WriteString("site limit reached: not every site was scanned\n")
	}
	b.WriteString("top unknown directives:")
	if len(t.TopUnknown) == 0 {
		b.WriteString(" none")
	}
	for _, u := range t.TopUnknown {
		fmt.Fprintf(&b, " %s %d;", u.Name, u.Count)
	}
	b.WriteString("\n")
	if details {
		for _, site := range r.Sites {
			fmt.Fprintf(&b, "site %s: %s %s\n", site.Name, site.Verdict, strings.Join(site.Causes, "+"))
			for _, p := range site.SymlinkedDirs {
				fmt.Fprintf(&b, "  link not followed: %s\n", p)
			}
			for _, p := range site.UnreadableDirs {
				fmt.Fprintf(&b, "  unreadable directory: %s\n", p)
			}
			for _, file := range site.Files {
				fmt.Fprintf(&b, "  %s (%s): %s %s %s\n", file.Path, file.URLPath, file.Verdict, strings.Join(file.Causes, "+"), file.Error)
				for _, p := range file.Problems {
					fmt.Fprintf(&b, "    line %d: %s\n", p.Line, p.Reason)
				}
				for _, g := range file.Findings {
					if g.Honoured || g.Category == htaccess.CategoryStructure {
						continue
					}
					fmt.Fprintf(&b, "    line %d %s [%s]: %s\n", g.Line, g.Directive, g.Category, g.Reason)
				}
				for _, a := range file.AccessRules {
					fmt.Fprintf(&b, "    access %s %s files=%q methods=%q expect=%d\n", a.Kind, a.Path, a.Files, a.Methods, a.ExpectStatus)
				}
			}
		}
	}
	return b.String()
}
