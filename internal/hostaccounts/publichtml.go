package hostaccounts

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// AdoptInput asks the broker to record the account's current public_html as
// its site folder, after its own user replaced the one the broker recorded
// (the account list's site_folder_changed).
type AdoptInput struct {
	ExpectedRevision uint64 `json:"expected_revision"`
	Reason           string `json:"reason"`
}

// SiteFolderService is implemented by the client; the broker serves it from
// the store.
type SiteFolderService interface {
	AdoptPublicHTML(context.Context, string, AdoptInput, string) (Account, error)
}

func validAdopt(in AdoptInput, actor string) bool {
	return in.ExpectedRevision > 0 && validText(in.Reason, 500) && validText(actor, 120)
}

// An adopt operation's journal target names the directory it records, as
// "<device>:<inode>", so a restart can finish the record from it.
var publicTargetPattern = regexp.MustCompile(`^[0-9]{1,20}:[0-9]{1,20}$`)

func publicTarget(id fileIdentity) string { return fmt.Sprintf("%d:%d", id.Dev, id.Ino) }

func parsePublicTarget(target string) (fileIdentity, bool) {
	if !publicTargetPattern.MatchString(target) {
		return fileIdentity{}, false
	}
	dev, ino, _ := strings.Cut(target, ":")
	d, e1 := strconv.ParseUint(dev, 10, 64)
	i, e2 := strconv.ParseUint(ino, 10, 64)
	id := fileIdentity{Dev: d, Ino: i}
	if e1 != nil || e2 != nil || i == 0 || publicTarget(id) != target {
		return fileIdentity{}, false
	}
	return id, true
}
