package olsweb

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

// Plan is the file work that turns a previously rendered set into a new one.
// Apply Write in order, then Remove, then restart OpenLiteSpeed gracefully.
type Plan struct {
	// Write lists new or changed files. Virtual host files come first and the
	// server fragment last, so the fragment never registers a vhconf.conf that
	// has not been written yet.
	Write []string
	// Remove lists files no longer rendered, sorted. They are removed after
	// the new server fragment has stopped referencing them.
	Remove []string
}

// MakePlan compares two rendered sets. Every path in both sets must have one
// of the two shapes Render produces, so a corrupted or crafted record of the
// previous set cannot make a reconciler overwrite or delete any other file.
func MakePlan(prev, next map[string][]byte) (Plan, error) {
	if len(prev) > MaxSites+1 || len(next) > MaxSites+1 {
		return Plan{}, fmt.Errorf("olsweb: plan: more than %d files", MaxSites+1)
	}
	for path := range prev {
		if !ownedPath(path) {
			return Plan{}, fmt.Errorf("olsweb: plan: previous set has a path Sifruno does not own: %q", path)
		}
	}
	for path := range next {
		if !ownedPath(path) {
			return Plan{}, fmt.Errorf("olsweb: plan: new set has a path Sifruno does not own: %q", path)
		}
	}
	if _, ok := next[ServerConfigPath]; !ok {
		return Plan{}, fmt.Errorf("olsweb: plan: new set has no %s", ServerConfigPath)
	}
	var p Plan
	for path, data := range next {
		if old, ok := prev[path]; !ok || !bytes.Equal(old, data) {
			p.Write = append(p.Write, path)
		}
	}
	for path := range prev {
		if _, ok := next[path]; !ok {
			p.Remove = append(p.Remove, path)
		}
	}
	sort.Slice(p.Write, func(i, j int) bool {
		a, b := p.Write[i] == ServerConfigPath, p.Write[j] == ServerConfigPath
		if a != b {
			return b
		}
		return p.Write[i] < p.Write[j]
	})
	sort.Strings(p.Remove)
	return p, nil
}

// ownedPath reports whether path is ServerConfigPath or the vhconf.conf of a
// valid site name.
func ownedPath(path string) bool {
	if path == ServerConfigPath {
		return true
	}
	name, ok := strings.CutPrefix(path, "conf/vhosts/"+NamePrefix)
	if !ok {
		return false
	}
	name, ok = strings.CutSuffix(name, "/vhconf.conf")
	return ok && siteNamePattern.MatchString(name)
}
