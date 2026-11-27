package hostaccounts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"sifruno/internal/htaccess"
	"sifruno/internal/olsweb"
)

// Protected folders are a migrated site's .htaccess access rules, converted
// by internal/htaccess (convert.go) and rendered by olsweb (access.go) into
// the site's vhost: OpenLiteSpeed ignores them in .htaccess. Only a
// migration sets them, from the copied files, and before those files reach
// the home, so a protected folder is never served open. The broker records
// them like the site's domains, journaled as one operation, and writes each
// realm's user file, read from the root-only staging copy, into a root-owned
// file in olsweb.RealmRoot that only the web server user may read (Jev:
// root_copy, 0.91). A later change to the tenant's .htaccess or user file
// changes none of this.

// siteFolders is a record's protected folders and the SHA-256 of each realm
// user file, keyed by its path, so a stored record names the exact files it
// was applied with, and the redirects and error pages the migration
// converted from the root .htaccess (olsweb moved.go). The canonical JSON
// is a string in the record; a set from before the redirects has the same
// JSON as before.
type siteFolders struct {
	Folders    []olsweb.Folder           `json:"folders"`
	Users      map[string]string         `json:"users"`
	Redirects  []olsweb.HtaccessRedirect `json:"redirects,omitempty"`
	ErrorPages []olsweb.ErrorPage        `json:"error_pages,omitempty"`
}

// empty reports a set with nothing to render.
func (f siteFolders) empty() bool {
	return len(f.Folders) == 0 && len(f.Redirects) == 0 && len(f.ErrorPages) == 0
}

// maxFoldersBytes bounds a set as the record holds it (canonical JSON,
// quoted again inside the record), so a record with two sets and two sets
// of domains stays inside maxRecordBytes.
const maxFoldersBytes = 48 << 10

var foldersDigestPattern = regexp.MustCompile(`^folders=[0-9a-f]{64}$`)

func encodeFolders(f siteFolders) string {
	if f.empty() {
		return ""
	}
	b, err := json.Marshal(f)
	if err != nil {
		return ""
	}
	return string(b)
}

func decodeFolders(encoded string) (siteFolders, bool) {
	if encoded == "" {
		return siteFolders{}, true
	}
	if !foldersSized(encoded) {
		return siteFolders{}, false
	}
	var f siteFolders
	d := json.NewDecoder(strings.NewReader(encoded))
	d.DisallowUnknownFields()
	if d.Decode(&f) != nil || f.empty() || encodeFolders(f) != encoded {
		return siteFolders{}, false
	}
	return f, true
}

func foldersDigest(encoded string) string {
	sum := sha256.Sum256([]byte(encoded))
	return "folders=" + hex.EncodeToString(sum[:])
}

// validStoredFolders checks a recorded set against olsweb's own rules for
// the account's site, and that it names a digest for exactly the user files
// its realms use.
func validStoredFolders(id, encoded string) bool {
	f, ok := decodeFolders(encoded)
	if !ok || !idPattern.MatchString(id) {
		return false
	}
	if encoded == "" {
		return true
	}
	if olsweb.CheckFolders(siteName(id), f.Folders) != nil || olsweb.CheckMoved(f.Redirects, f.ErrorPages) != nil {
		return false
	}
	files := olsweb.FolderRealmFiles(f.Folders)
	if len(files) != len(f.Users) {
		return false
	}
	for _, path := range files {
		if !sha256Hex.MatchString(f.Users[path]) {
			return false
		}
	}
	return true
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// siteDirPattern is a site name as siteName makes it, which names the
// site's directory in olsweb.RealmRoot.
var siteDirPattern = regexp.MustCompile(`^u[0-9a-f]{31}$`)

// foldersSized reports whether a set fits maxFoldersBytes as the record
// holds it, quoted inside the record's JSON.
func foldersSized(encoded string) bool {
	quoted, err := json.Marshal(encoded)
	return err == nil && len(quoted) <= maxFoldersBytes
}

// recordProtection is the set a record's site is rendered with: the set an
// unfinished folders operation installs, else the recorded one.
func recordProtection(r record) siteFolders {
	encoded := r.Folders
	if r.Pending != nil && r.Pending.Action == "folders" {
		encoded = r.FoldersNext
	}
	f, _ := decodeFolders(encoded)
	return f
}

// SiteProtection is what a migration's copy converted to: the folders and
// each realm's user file, normalized, keyed by its path in olsweb.RealmRoot,
// and the root .htaccess's redirects and error pages.
type SiteProtection struct {
	Folders    []olsweb.Folder
	Users      map[string][]byte
	Redirects  []olsweb.HtaccessRedirect
	ErrorPages []olsweb.ErrorPage
}

// protectionFolders maps converted rules (sorted by path, as ConvertSite
// returns them) to the site's olsweb folders. A realm's user file becomes
// the site's nth file; userFiles maps each one to the AuthUserFile path the
// old server named.
func protectionFolders(site string, rules []htaccess.FolderRule) (folders []olsweb.Folder, userFiles map[string]string) {
	userFiles = map[string]string{}
	for i, rule := range rules {
		f := olsweb.Folder{Path: rule.Path, Hosts: string(rule.Hosts.Kind), Networks: rule.Hosts.Networks, Allow: rule.Allow}
		if rule.Realm != nil {
			f.Realm = &olsweb.FolderRealm{Name: rule.Realm.Name, UserFile: olsweb.RealmFile(site, i+1), Users: rule.Realm.Users}
			userFiles[f.Realm.UserFile] = rule.Realm.UserFile
		}
		if rule.Deny != nil {
			f.Deny = &olsweb.DenyNames{Names: rule.Deny.Exact, Endings: rule.Deny.Endings}
		}
		folders = append(folders, f)
	}
	return folders, userFiles
}

// protectionMoved maps the converted redirects and error pages.
func protectionMoved(conv htaccess.SiteConversion) ([]olsweb.HtaccessRedirect, []olsweb.ErrorPage) {
	var redirects []olsweb.HtaccessRedirect
	for _, r := range conv.Redirects {
		redirects = append(redirects, olsweb.HtaccessRedirect{Prefix: r.Prefix, Pattern: r.Pattern, Target: r.Target, Status: r.Status})
	}
	var pages []olsweb.ErrorPage
	for _, p := range conv.ErrorPages {
		pages = append(pages, olsweb.ErrorPage{Status: p.Status, URL: p.URL})
	}
	return redirects, pages
}

// converts reports a conversion with anything for the vhost to carry.
func converts(conv htaccess.SiteConversion) bool {
	return len(conv.Rules) > 0 || len(conv.Redirects) > 0 || len(conv.ErrorPages) > 0
}

// MigrationFolder is one converted .htaccess in a migration's tier report:
// the file, the folder it protects, and in plain words what it became.
type MigrationFolder struct {
	File string `json:"file"`
	Path string `json:"path"`
	Rule string `json:"rule"`
}

func migrationFolders(rules []htaccess.FolderRule) []MigrationFolder {
	out := []MigrationFolder{}
	for _, rule := range rules {
		out = append(out, MigrationFolder{File: rule.File, Path: rule.Path, Rule: ruleText(rule)})
	}
	return out
}

// migrationMoved lists the converted redirects and error pages of the root
// .htaccess in the same form: the path or expression, and what it became.
func migrationMoved(conv htaccess.SiteConversion) []MigrationFolder {
	out := []MigrationFolder{}
	for _, r := range conv.Redirects {
		from := r.Prefix
		if from == "" {
			from = r.Pattern
		}
		out = append(out, MigrationFolder{File: ".htaccess", Path: from, Rule: fmt.Sprintf("redirect (%d) to %s", r.Status, r.Target)})
	}
	for _, p := range conv.ErrorPages {
		out = append(out, MigrationFolder{File: ".htaccess", Path: p.URL, Rule: fmt.Sprintf("error page for %d", p.Status)})
	}
	return out
}

func ruleText(rule htaccess.FolderRule) string {
	var parts []string
	switch rule.Hosts.Kind {
	case htaccess.HostsNone:
		parts = append(parts, "closed to everyone (403)")
	case htaccess.HostsOnly:
		parts = append(parts, "open only to "+strings.Join(rule.Hosts.Networks, ", "))
	case htaccess.HostsExcept:
		parts = append(parts, "closed to "+strings.Join(rule.Hosts.Networks, ", "))
	}
	if len(rule.Allow) > 0 {
		parts = append(parts, fmt.Sprintf("except %d named files open to everyone (%s)", len(rule.Allow), strings.Join(rule.Allow, ", ")))
	}
	if rule.Realm != nil {
		who := "any user in its password file"
		if len(rule.Realm.Users) > 0 {
			who = "the users " + strings.Join(rule.Realm.Users, ", ")
		}
		parts = append(parts, fmt.Sprintf("password \"%s\" for %s (401)", rule.Realm.Name, who))
	}
	if rule.Deny != nil {
		names := slices.Clone(rule.Deny.Exact)
		for _, e := range rule.Deny.Endings {
			names = append(names, "*"+e)
		}
		parts = append(parts, "files named "+strings.Join(names, ", ")+" closed to everyone (403)")
	}
	return strings.Join(parts, "; ")
}

// foldersProbes are the folders verify checks: a folder closed to all
// answers 403, a password folder open to every address 401, and a folder
// open to some addresses only carries its rule, from which verify works
// out what each site must answer the address it sees verify come from
// (D-0002).
func foldersProbes(rules []htaccess.FolderRule) []MigrationProbe {
	out := []MigrationProbe{}
	for _, rule := range rules {
		switch kind := closedKind(rule); {
		case kind != "":
			out = append(out, MigrationProbe{Path: rule.Path, Kind: kind})
		case rule.Hosts.Kind == htaccess.HostsOnly || rule.Hosts.Kind == htaccess.HostsExcept:
			out = append(out, MigrationProbe{Path: rule.Path, Kind: "hosts", Hosts: string(rule.Hosts.Kind), Networks: slices.Clone(rule.Hosts.Networks), Realm: rule.Realm != nil})
		}
	}
	return out
}

// closedKind is the probe kind of a folder that answers every address the
// same: deny (403) when it is closed to all, auth (401) when it asks all
// for a password; "" for any other folder.
func closedKind(rule htaccess.FolderRule) string {
	switch {
	case rule.Hosts.Kind == htaccess.HostsNone:
		return "deny"
	case rule.Hosts.Kind == htaccess.HostsAll && rule.Realm != nil:
		return "auth"
	}
	return ""
}

// setSiteFolders records a migrated site's protected folders and puts them
// live: the realm user files first, then the journaled intent, then the
// site list written, tested and reloaded under the web operation's limit,
// or restored and journaled as rejected. The caller (migrateFiles) holds
// the account busy; the folders are set once, before the copy reaches the
// home, and the same set again changes nothing.
func (s *store) setSiteFolders(ctx context.Context, id string, p SiteProtection, actor, reason string) error {
	if snapshotReentry(ctx, s) {
		return ErrConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	want := siteFolders{Folders: p.Folders, Users: map[string]string{}, Redirects: p.Redirects, ErrorPages: p.ErrorPages}
	if !idPattern.MatchString(id) || want.empty() || !validUserFiles(p) || !validText(reason, 500) || !validText(actor, 120) {
		return ErrInvalid
	}
	if s.web == nil {
		return ErrUnavailable
	}
	for _, path := range olsweb.FolderRealmFiles(p.Folders) {
		data, ok := p.Users[path]
		if !ok {
			return ErrInvalid
		}
		sum := sha256.Sum256(data)
		want.Users[path] = hex.EncodeToString(sum[:])
	}
	if len(want.Users) != len(p.Users) {
		return ErrInvalid
	}
	encoded := encodeFolders(want)
	if encoded == "" || !validStoredFolders(id, encoded) {
		return ErrInvalid
	}
	items, err := s.mutationReady(ctx)
	if err != nil {
		return err
	}
	index := slices.IndexFunc(items, func(r record) bool { return r.Account.ID == id })
	if index < 0 {
		return ErrNotFound
	}
	r := items[index]
	if r.Account.State != "active" || !r.Web.enabled() || !s.installing[id] || r.Pending != nil {
		return ErrConflict
	}
	if r.Folders == encoded {
		return nil
	}
	if r.Folders != "" || r.Account.Revision == ^uint64(0) || !historyRoom(r, operationRows, false) {
		return ErrConflict
	}
	if s.native.Verify(ctx, r) != nil {
		return ErrConflict
	}
	applyCtx, cancel := webContext(ctx)
	defer cancel()
	// A site whose folders have no realm (closed folders, address lists)
	// needs no user file.
	if len(p.Users) > 0 {
		if err := s.native.WriteSiteRealms(applyCtx, siteName(id), p.Users); err != nil {
			return err
		}
	}
	r.Pending = &pending{Action: "folders", Target: foldersDigest(encoded), Actor: actor, Reason: reason}
	r.FoldersNext = encoded
	next := append([]record(nil), items...)
	next[index] = r
	sites := webSites(next, "")
	operationID, e := randomID()
	if e != nil {
		return e
	}
	r.Pending.OperationID = operationID
	before := r.Account
	after := r.Account
	after.Revision++
	intent := operationEvent{OperationID: operationID, Action: "folders", Status: "intended", Actor: actor, Reason: reason, Before: &before, After: after}
	if r, err = s.appendEvent(r, intent); err != nil {
		return ErrRecovery
	}
	switch e := s.native.ApplySites(applyCtx, sites, s.tenantBroken(next, id)); {
	case errors.Is(e, ErrWebRejected):
		operation := *r.Pending
		r.Pending, r.FoldersNext = nil, ""
		if _, e := s.resultEvent(r, operation, "rejected"); e != nil {
			return ErrRecovery
		}
		_ = s.native.RemoveSiteRealms(applyCtx, siteName(id))
		return ErrWebRejected
	case e != nil:
		s.recoveryRequired(r, *r.Pending, "site list", e)
		return ErrRecovery
	}
	r.Folders, r.FoldersNext = encoded, ""
	r.Account.Revision++
	r.Account.UpdatedAt = time.Now().UTC()
	r.Actor, r.Reason = actor, reason
	operation := *r.Pending
	r.Pending = nil
	if _, e := s.resultEvent(r, operation, "succeeded"); e != nil {
		return ErrRecovery
	}
	return nil
}

// finishFolders finishes an interrupted folders operation at start: the set
// was durable, and its user files were written, before the config changed,
// and installing the site list is idempotent. A config that now fails its
// test (a user file gone among the causes) ends it rejected, unchanged; any
// other failure leaves it pending for the next start.
func (s *store) finishFolders(ctx context.Context, items []record, r record) error {
	operation := *r.Pending
	applyCtx, cancel := webContext(ctx)
	e := s.native.ApplySites(applyCtx, webSites(items, ""), s.tenantBroken(items, r.Account.ID))
	cancel()
	switch {
	case errors.Is(e, ErrWebRejected):
		r.Pending, r.FoldersNext = nil, ""
		if _, e := s.resultEvent(r, operation, "rejected"); e != nil {
			return ErrRecovery
		}
		s.removeSiteRealms(ctx, r.Account.ID)
		return nil
	case e != nil:
		logRecovery(operation.Action, r, "finish at start", e)
		return nil
	}
	r.Folders, r.FoldersNext = r.FoldersNext, ""
	r.Account.Revision++
	r.Account.UpdatedAt = time.Now().UTC()
	r.Actor, r.Reason = operation.Actor, operation.Reason
	r.Pending = nil
	if _, e := s.resultEvent(r, operation, "reconciled"); e != nil {
		return ErrRecovery
	}
	return nil
}

// removeSiteRealms takes a deleted site's realm user files away once the
// site has left the config. Like removeSiteCache it cannot change the
// delete's answer: files left behind are named by no config, under a name
// no new account gets.
func (s *store) removeSiteRealms(ctx context.Context, id string) {
	if s.web == nil {
		return
	}
	removeCtx, cancel := webContext(ctx)
	defer cancel()
	_ = s.native.RemoveSiteRealms(removeCtx, siteName(id))
}

// validUserFiles checks a protection's user files against the folders: one
// normalized file per realm, at the path olsweb names, nothing else.
func validUserFiles(p SiteProtection) bool {
	files := olsweb.FolderRealmFiles(p.Folders)
	if len(files) != len(p.Users) {
		return false
	}
	for _, path := range files {
		data, ok := p.Users[path]
		if !ok {
			return false
		}
		normal, _, err := htaccess.NormalizeUserFile(data)
		if err != nil || !bytes.Equal(normal, data) {
			return false
		}
	}
	return true
}
