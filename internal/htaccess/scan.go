package htaccess

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type Layout string

const (
	// LayoutSingle treats the root itself as one site.
	LayoutSingle Layout = "single"
	// LayoutDir treats every immediate subdirectory of the root as one site.
	LayoutDir Layout = "dir"
	// LayoutCPanel treats <root>/<user>/public_html as one site per account.
	// Addon and subdomain docroots below public_html belong to that site.
	LayoutCPanel Layout = "cpanel"
)

func ParseLayout(s string) (Layout, error) {
	switch l := Layout(s); l {
	case LayoutSingle, LayoutDir, LayoutCPanel:
		return l, nil
	}
	return "", fmt.Errorf("unknown layout %q", s)
}

// Limits bound one scan. A site that hits a limit is reported as truncated
// and compat, because what was not read could hold an access rule.
type Limits struct {
	MaxDepth          int `json:"max_depth"`
	MaxFilesPerSite   int `json:"max_files_per_site"`
	MaxEntriesPerSite int `json:"max_entries_per_site"`
	MaxSites          int `json:"max_sites"`
}

func DefaultLimits() Limits {
	return Limits{MaxDepth: 40, MaxFilesPerSite: 10000, MaxEntriesPerSite: 2000000, MaxSites: 100000}
}

func (l Limits) valid() bool {
	return l.MaxDepth > 0 && l.MaxFilesPerSite > 0 && l.MaxEntriesPerSite > 0 && l.MaxSites > 0
}

var (
	ErrInvalidOptions = errors.New("invalid htaccess scan options")
	ErrRoot           = errors.New("scan root cannot be opened as a directory")
)

type SiteResult struct {
	// Name is the site directory relative to the scanned root.
	Name    string   `json:"name"`
	Verdict Verdict  `json:"verdict"`
	Causes  []string `json:"causes,omitempty"`
	// Truncated is set when a limit stopped the walk of this site.
	Truncated bool `json:"truncated,omitempty"`
	// SymlinkedDirs are links the scan did not follow: links to directories,
	// and links whose target it cannot see (dangling, absolute, outside the
	// root). Links to regular files are ignored.
	SymlinkedDirs  []string     `json:"symlinked_dirs_not_followed,omitempty"`
	UnreadableDirs []string     `json:"unreadable_dirs,omitempty"`
	Files          []FileResult `json:"files"`
	nestedOnly     bool
}

type NameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type Totals struct {
	Sites                int             `json:"sites"`
	SitesByVerdict       map[Verdict]int `json:"sites_by_verdict"`
	SitesWithoutHtaccess int             `json:"sites_without_htaccess"`
	Files                int             `json:"files"`
	FilesByVerdict       map[Verdict]int `json:"files_by_verdict"`
	// UnreadableFiles counts .htaccess entries that were not classified
	// because they could not be read, exceed 1 MiB or are not regular files.
	UnreadableFiles      int              `json:"unreadable_files"`
	Directives           int              `json:"directives"`
	DirectivesByCategory map[Category]int `json:"directives_by_category"`
	// TopUnknown holds lower-cased unknown directive names. Names that do not
	// look like a directive are counted under one placeholder so stray text
	// cannot leak customer data into the aggregate.
	TopUnknown            []NameCount    `json:"top_unknown_directives"`
	CompatSitesByCause    map[string]int `json:"compat_sites_by_cause"`
	CompatSitesByCauseSet map[string]int `json:"compat_sites_by_cause_set"`
	// CompatSitesNestedOnly counts compat sites whose compat files all sit
	// below the site root, with no site-level cause.
	CompatSitesNestedOnly    int `json:"compat_sites_nested_only"`
	SymlinkedDirsNotFollowed int `json:"symlinked_dirs_not_followed"`
	// AccountsWithoutDocroot counts cPanel-layout entries with no
	// public_html directory; they are not sites.
	AccountsWithoutDocroot int `json:"accounts_without_docroot"`
	UnreadableDirs         int `json:"unreadable_dirs"`
	TruncatedSites         int `json:"truncated_sites"`
}

type Report struct {
	Layout            Layout       `json:"layout"`
	Limits            Limits       `json:"limits"`
	Truncated         bool         `json:"truncated"`
	SitesLimitReached bool         `json:"sites_limit_reached"`
	Totals            Totals       `json:"totals"`
	Sites             []SiteResult `json:"sites,omitempty"`
}

const (
	maxTopUnknown      = 20
	unknownPlaceholder = "(not a directive name)"
	publicHTML         = "public_html"
)

var directiveName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)

// Scan walks dir read-only and classifies every file named exactly
// .htaccess. It never follows symbolic links and stays inside dir.
func Scan(dir string, layout Layout, limits Limits) (Report, error) {
	if _, err := ParseLayout(string(layout)); err != nil || !limits.valid() {
		return Report{}, ErrInvalidOptions
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return Report{}, ErrRoot
	}
	defer root.Close()
	if info, err := root.Stat("."); err != nil || !info.IsDir() {
		return Report{}, ErrRoot
	}
	s := &scanner{root: root, limits: limits}
	report := Report{Layout: layout, Limits: limits}
	sites, err := s.discover(layout, &report)
	if err != nil {
		return Report{}, err
	}
	for i := range sites {
		finishSite(&sites[i])
	}
	report.Sites = sites
	report.Totals = totals(sites, report.Totals.AccountsWithoutDocroot)
	report.Truncated = report.SitesLimitReached || report.Totals.TruncatedSites > 0
	return report, nil
}

type scanner struct {
	root   *os.Root
	limits Limits
}

func (s *scanner) discover(layout Layout, report *Report) ([]SiteResult, error) {
	if layout == LayoutSingle {
		return []SiteResult{s.scanSite(".")}, nil
	}
	entries, truncated, err := s.list(".", s.limits.MaxEntriesPerSite)
	if err != nil {
		return nil, ErrRoot
	}
	report.SitesLimitReached = truncated
	var sites []SiteResult
	add := func(site SiteResult) bool {
		if len(sites) >= s.limits.MaxSites {
			report.SitesLimitReached = true
			return false
		}
		sites = append(sites, site)
		return true
	}
	for _, e := range entries {
		name := e.Name()
		// Account and site names never start with a dot; dot entries are
		// tool state such as .cpan or .cpanel.
		if strings.HasPrefix(name, ".") {
			continue
		}
		site := name
		if layout == LayoutCPanel {
			site = name + "/" + publicHTML
		}
		var ok bool
		switch t := e.Type(); {
		case t&fs.ModeSymlink != 0:
			if !s.linkHidesDir(name) {
				continue
			}
			ok = add(linkedSite(site, name))
		case !t.IsDir():
			continue
		case layout == LayoutDir:
			ok = add(s.scanSite(site))
		default:
			info, err := s.root.Lstat(osPath(site))
			switch {
			case errors.Is(err, fs.ErrNotExist):
				report.Totals.AccountsWithoutDocroot++
				continue
			case err != nil:
				ok = add(SiteResult{Name: site, UnreadableDirs: []string{site}, Files: []FileResult{}})
			case info.Mode()&fs.ModeSymlink != 0:
				if !s.linkHidesDir(site) {
					report.Totals.AccountsWithoutDocroot++
					continue
				}
				ok = add(linkedSite(site, site))
			case !info.IsDir():
				report.Totals.AccountsWithoutDocroot++
				continue
			default:
				ok = add(s.scanSite(site))
			}
		}
		if !ok {
			break
		}
	}
	return sites, nil
}

func linkedSite(name, link string) SiteResult {
	return SiteResult{Name: name, SymlinkedDirs: []string{link}, Files: []FileResult{}}
}

// scanSite walks one site depth-first in sorted order.
func (s *scanner) scanSite(base string) SiteResult {
	site := SiteResult{Name: base, Files: []FileResult{}}
	type pending struct {
		rel   string
		depth int
	}
	stack := []pending{{base, 0}}
	entries := 0
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		list, truncated, err := s.list(cur.rel, s.limits.MaxEntriesPerSite-entries)
		switch {
		case errors.Is(err, errChanged):
			site.SymlinkedDirs = append(site.SymlinkedDirs, cur.rel)
			continue
		case err != nil:
			site.UnreadableDirs = append(site.UnreadableDirs, cur.rel)
			continue
		}
		entries += len(list)
		if truncated {
			site.Truncated = true
		}
		var dirs []string
		for _, e := range list {
			rel := joinRel(cur.rel, e.Name())
			t := e.Type()
			switch {
			case e.Name() == ".htaccess":
				if len(site.Files) >= s.limits.MaxFilesPerSite {
					site.Truncated = true
					continue
				}
				urlPath := siteURLPath(base, cur.rel)
				if !t.IsRegular() {
					site.Files = append(site.Files, unreadFile(rel, urlPath, CauseIrregularFile, "not a regular file"))
					continue
				}
				site.Files = append(site.Files, s.readFile(rel, urlPath))
			case t&fs.ModeSymlink != 0:
				if s.linkHidesDir(rel) {
					site.SymlinkedDirs = append(site.SymlinkedDirs, rel)
				}
			case t.IsDir():
				if cur.depth >= s.limits.MaxDepth {
					site.Truncated = true
					continue
				}
				dirs = append(dirs, rel)
			}
		}
		for i := len(dirs) - 1; i >= 0; i-- {
			stack = append(stack, pending{dirs[i], cur.depth + 1})
		}
		if truncated {
			break
		}
	}
	return site
}

var errChanged = errors.New("directory changed during the scan")

// list reads at most budget entries of a directory, sorted by name. The
// directory must still be the one Lstat saw, so a directory swapped for a
// link mid-scan is not followed.
func (s *scanner) list(rel string, budget int) ([]fs.DirEntry, bool, error) {
	if budget <= 0 {
		return nil, true, nil
	}
	before, err := s.root.Lstat(osPath(rel))
	if err != nil {
		return nil, false, err
	}
	if !before.IsDir() {
		return nil, false, errChanged
	}
	d, err := s.root.Open(osPath(rel))
	if err != nil {
		return nil, false, err
	}
	defer d.Close()
	after, err := d.Stat()
	if err != nil {
		return nil, false, err
	}
	if !os.SameFile(before, after) {
		return nil, false, errChanged
	}
	var out []fs.DirEntry
	truncated := false
	for {
		chunk, err := d.ReadDir(256)
		out = append(out, chunk...)
		if len(out) > budget {
			out, truncated = out[:budget], true
			break
		}
		if errors.Is(err, io.EOF) || (err == nil && len(chunk) == 0) {
			break
		}
		if err != nil {
			return nil, false, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, truncated, nil
}

// linkHidesDir reports whether an unfollowed link could hide a directory.
// Root.Stat refuses absolute targets and targets outside the root, so those
// count as unseen, as do dangling links and loops.
func (s *scanner) linkHidesDir(rel string) bool {
	info, err := s.root.Stat(osPath(rel))
	return err != nil || info.IsDir()
}

// readFile opens a .htaccess without following links and without blocking
// on a FIFO or device swapped in after Lstat.
func (s *scanner) readFile(rel, urlPath string) FileResult {
	before, err := s.root.Lstat(osPath(rel))
	if err != nil {
		return unreadFile(rel, urlPath, CauseUnreadableFile, "could not be read")
	}
	if !before.Mode().IsRegular() {
		return unreadFile(rel, urlPath, CauseIrregularFile, "not a regular file")
	}
	if before.Size() > MaxFileBytes {
		return unreadFile(rel, urlPath, CauseOversizeFile, "larger than 1 MiB")
	}
	f, err := s.root.OpenFile(osPath(rel), openFlags, 0)
	if err != nil {
		return unreadFile(rel, urlPath, CauseUnreadableFile, "could not be read")
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return unreadFile(rel, urlPath, CauseIrregularFile, "changed during the scan")
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return unreadFile(rel, urlPath, CauseUnreadableFile, "could not be read")
	}
	if len(data) > MaxFileBytes {
		return unreadFile(rel, urlPath, CauseOversizeFile, "larger than 1 MiB")
	}
	return ClassifyFile(rel, urlPath, data)
}

func finishSite(site *SiteResult) {
	causes := map[string]bool{}
	verdict := VerdictNative
	rootCompat, nestedCompat := false, false
	for _, f := range site.Files {
		if f.Verdict.rank() > verdict.rank() {
			verdict = f.Verdict
		}
		for _, c := range f.Causes {
			causes[c] = true
		}
		if f.Verdict == VerdictCompat {
			if f.URLPath == "/" {
				rootCompat = true
			} else {
				nestedCompat = true
			}
		}
	}
	siteLevel := false
	if len(site.SymlinkedDirs) > 0 {
		causes[CauseSymlinkNotFollowed], siteLevel = true, true
	}
	if site.Truncated {
		causes[CauseScanTruncated], siteLevel = true, true
	}
	if len(site.UnreadableDirs) > 0 {
		causes[CauseUnreadableDir], siteLevel = true, true
	}
	if len(causes) > 0 {
		verdict = VerdictCompat
		site.Causes = sortedCauses(causes)
	}
	site.Verdict = verdict
	site.nestedOnly = verdict == VerdictCompat && !siteLevel && !rootCompat && nestedCompat
}

func totals(sites []SiteResult, withoutDocroot int) Totals {
	t := Totals{
		SitesByVerdict:         map[Verdict]int{},
		FilesByVerdict:         map[Verdict]int{},
		DirectivesByCategory:   map[Category]int{},
		CompatSitesByCause:     map[string]int{},
		CompatSitesByCauseSet:  map[string]int{},
		TopUnknown:             []NameCount{},
		AccountsWithoutDocroot: withoutDocroot,
	}
	for _, v := range Verdicts {
		t.SitesByVerdict[v], t.FilesByVerdict[v] = 0, 0
	}
	for _, c := range Categories {
		t.DirectivesByCategory[c] = 0
	}
	for _, c := range Causes {
		t.CompatSitesByCause[c] = 0
	}
	unknown := map[string]int{}
	for _, site := range sites {
		t.Sites++
		t.SitesByVerdict[site.Verdict]++
		if len(site.Files) == 0 {
			t.SitesWithoutHtaccess++
		}
		if site.Verdict == VerdictCompat {
			for _, c := range site.Causes {
				t.CompatSitesByCause[c]++
			}
			t.CompatSitesByCauseSet[strings.Join(site.Causes, "+")]++
		}
		if site.nestedOnly {
			t.CompatSitesNestedOnly++
		}
		if site.Truncated {
			t.TruncatedSites++
		}
		t.SymlinkedDirsNotFollowed += len(site.SymlinkedDirs)
		t.UnreadableDirs += len(site.UnreadableDirs)
		for _, f := range site.Files {
			t.Files++
			t.FilesByVerdict[f.Verdict]++
			if f.Error != "" {
				t.UnreadableFiles++
			}
			for _, g := range f.Findings {
				t.Directives++
				t.DirectivesByCategory[g.Category]++
				if g.Category == CategoryUnknown {
					name := strings.Trim(g.Directive, "<>")
					if !directiveName.MatchString(name) {
						name = unknownPlaceholder
					}
					unknown[strings.ToLower(name)]++
				}
			}
		}
	}
	for name, count := range unknown {
		t.TopUnknown = append(t.TopUnknown, NameCount{Name: name, Count: count})
	}
	sort.Slice(t.TopUnknown, func(i, j int) bool {
		a, b := t.TopUnknown[i], t.TopUnknown[j]
		return a.Count > b.Count || (a.Count == b.Count && a.Name < b.Name)
	})
	if len(t.TopUnknown) > maxTopUnknown {
		t.TopUnknown = t.TopUnknown[:maxTopUnknown]
	}
	return t
}

func joinRel(dir, name string) string {
	if dir == "." {
		return name
	}
	return dir + "/" + name
}

func osPath(rel string) string { return filepath.FromSlash(rel) }

// siteURLPath maps a directory below the site base to its URL path.
func siteURLPath(base, dir string) string {
	if dir == base {
		return "/"
	}
	if base != "." {
		dir = strings.TrimPrefix(dir, base+"/")
	}
	return "/" + dir + "/"
}
