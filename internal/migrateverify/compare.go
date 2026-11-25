package migrateverify

import (
	"fmt"
	"net/netip"
	"strings"
)

type sizeTolerance struct {
	percent int
	floor   int64
}

// compareSize passes a body size difference within max(percent of the old
// size, floor), where the floor shrinks to a quarter of the old size for small
// pages so that a mostly emptied small page cannot hide inside 2 KiB. Beyond
// the pass band a difference up to 25% is a warning (nonces, timestamps,
// rotating widgets) and anything larger fails.
func compareSize(oldSize, newSize int64, tol sizeTolerance) Result {
	diff := newSize - oldSize
	if diff < 0 {
		diff = -diff
	}
	allowed := max(oldSize*int64(tol.percent)/100, min(tol.floor, oldSize/4))
	switch {
	case diff <= allowed:
		return Pass
	case diff*4 <= oldSize:
		return Warn
	default:
		return Fail
	}
}

func sizeReason(oldSize, newSize int64) string {
	if oldSize == 0 {
		return fmt.Sprintf("size %d → %d bytes", oldSize, newSize)
	}
	return fmt.Sprintf("size %d → %d bytes (%+.0f%%)", oldSize, newSize, float64(newSize-oldSize)*100/float64(oldSize))
}

func isOpen(status int) bool   { return status >= 200 && status < 400 }
func isClosed(status int) bool { return status == 401 || status == 403 }

// judgePage compares one page. Error and redirect bodies are server
// boilerplate, so size and title are judged on 2xx responses only.
func judgePage(was, now Response, tol sizeTolerance) (Result, bool, string) {
	if was.Error != "" {
		return Fail, false, "old site request failed: " + was.Error
	}
	if now.Error != "" {
		return Fail, false, "new site request failed: " + now.Error
	}
	if isClosed(was.Status) && isOpen(now.Status) {
		return Fail, true, fmt.Sprintf("closed on the old site (%d) but open on the new site (%d)", was.Status, now.Status)
	}
	if was.Status != now.Status {
		return Fail, false, fmt.Sprintf("status %d → %d", was.Status, now.Status)
	}
	if was.Status >= 300 && was.Status < 400 {
		if was.Location != now.Location {
			return Fail, false, fmt.Sprintf("redirect %s → %s", orNone(was.Location), orNone(now.Location))
		}
		return Pass, false, ""
	}
	result := Pass
	var reasons []string
	worsen := func(r Result, reason string) {
		if rank(r) > rank(result) {
			result = r
		}
		reasons = append(reasons, reason)
	}
	if was.ContentType != now.ContentType {
		worsen(Fail, fmt.Sprintf("content type %s → %s", orNone(was.ContentType), orNone(now.ContentType)))
	}
	if was.Status == 401 && was.AuthScheme != now.AuthScheme {
		worsen(Fail, fmt.Sprintf("auth scheme %s → %s", orNone(was.AuthScheme), orNone(now.AuthScheme)))
	}
	if was.Status < 200 || was.Status >= 300 {
		return result, false, strings.Join(reasons, "; ")
	}
	if was.Status == 200 && isHTML(was.ContentType) && isHTML(now.ContentType) && was.Title != now.Title {
		worsen(Fail, fmt.Sprintf("title differs: %q → %q", truncate(was.Title, 80), truncate(now.Title, 80)))
	}
	switch {
	case was.Truncated || now.Truncated:
		worsen(Warn, "body is larger than the read limit; size not compared")
	default:
		if r := compareSize(was.Bytes, now.Bytes, tol); r != Pass {
			worsen(r, sizeReason(was.Bytes, now.Bytes))
		}
	}
	return result, false, strings.Join(reasons, "; ")
}

func rank(r Result) int {
	switch r {
	case Fail:
		return 2
	case Warn:
		return 1
	default:
		return 0
	}
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func expectedStatus(kind ProbeKind) int {
	switch kind {
	case ProbeAuth:
		return 401
	case ProbeAllow:
		return 200
	}
	return 403
}

// judgeProbe applies the closed-URL rules. new_open is checked before the old
// status is judged: a URL that is closed on the old site and open on the new
// one is the critical case even when the probe expected the other closed status.
func judgeProbe(p Probe, was, now Response) ProbeResult {
	r := ProbeResult{Path: p.Path, Kind: p.Kind, Result: Fail, ExpectedStatus: expectedStatus(p.Kind), OldStatus: was.Status, NewStatus: now.Status, OldAuthScheme: was.AuthScheme, NewAuthScheme: now.AuthScheme}
	switch {
	case was.Error != "":
		r.Code, r.Reason = CodeRequestFailed, "old site request failed: "+was.Error
	case now.Error != "":
		r.Code, r.Reason = CodeRequestFailed, "new site request failed: "+now.Error
	case p.Kind == ProbeAllow && was.Status != 200:
		r.Code = CodeOldUnexpectedStatus
		r.Reason = fmt.Sprintf("old site answered %d, expected 200 for a file its rules leave open", was.Status)
	case p.Kind == ProbeAllow && now.Status != 200:
		r.Code = CodeNewDiffers
		r.Reason = fmt.Sprintf("status 200 → %d: the copy closes a file the old site leaves open", now.Status)
	case p.Kind == ProbeAllow:
		r.Result, r.Code = Pass, CodeOK
		r.Reason = "both sites answer 200"
	case isClosed(was.Status) && isOpen(now.Status):
		r.Code, r.Critical = CodeNewOpen, true
		r.Reason = fmt.Sprintf("closed on the old site (%d) but open on the new site (%d)", was.Status, now.Status)
	case isOpen(was.Status):
		r.Code = CodeOldNotClosed
		r.Reason = fmt.Sprintf("old site answered %d, expected %d; the probe list is wrong or the old rule is already broken", was.Status, r.ExpectedStatus)
	case was.Status != r.ExpectedStatus:
		r.Code = CodeOldUnexpectedStatus
		r.Reason = fmt.Sprintf("old site answered %d, expected %d", was.Status, r.ExpectedStatus)
	case now.Status != was.Status:
		r.Code = CodeNewDiffers
		r.Reason = fmt.Sprintf("status %d → %d", was.Status, now.Status)
	case was.Status == 401 && was.AuthScheme != now.AuthScheme:
		r.Code = CodeAuthSchemeDiffers
		r.Reason = fmt.Sprintf("auth scheme %s → %s", orNone(was.AuthScheme), orNone(now.AuthScheme))
	default:
		r.Result, r.Code = Pass, CodeOK
		r.Reason = fmt.Sprintf("both sites answer %d", was.Status)
	}
	return r
}

// hostsStatus is the status a ProbeHosts folder's rule gives a client:
// 403 when its address list keeps the client out, else 401 behind a
// password, else 200. validate checked the networks.
func hostsStatus(p Probe, client netip.Addr) int {
	listed := false
	for _, n := range p.Networks {
		if prefix, err := netip.ParsePrefix(n); err == nil && prefix.Contains(client) {
			listed = true
			break
		}
	}
	switch {
	case listed != (p.Hosts == HostsOnly):
		return 403
	case p.Realm:
		return 401
	}
	return 200
}

// judgeHosts checks a folder open to some addresses only. Each site must
// answer what the folder's rule gives the address that site sees verify
// come from; the statuses come from the rule, never from what the old
// site happens to answer. Without both addresses nothing can be expected,
// and the probe fails. A failure says in plain words what a person should
// check before accepting it.
func judgeHosts(p Probe, was, now Response, oldClient, newClient netip.Addr) ProbeResult {
	r := ProbeResult{Path: p.Path, Kind: p.Kind, Result: Fail, OldStatus: was.Status, NewStatus: now.Status, OldAuthScheme: was.AuthScheme, NewAuthScheme: now.AuthScheme}
	rule := "open only to "
	folder := p.Path + " is open only to some addresses. "
	if p.Hosts == HostsExcept {
		rule, folder = "closed to ", p.Path+" is closed to some addresses. "
	}
	rule += strings.Join(p.Networks, ", ")
	if p.Realm {
		rule += ", then a password"
	}
	next := "Check " + p.Path + " from an address it allows, then accept."
	switch {
	case !oldClient.IsValid():
		r.Code = CodeClientUnknown
		r.Reason = "the address the old server sees verify's requests come from is not known, so what its rule (" + rule + ") gives it cannot be told"
		r.Message = folder + "Sifruno could not learn which address the old server sees this server's requests come from, so it cannot tell what the old site should answer. " + next
		return r
	case !newClient.IsValid():
		r.Code = CodeClientUnknown
		r.Reason = "the address the copy sees verify's requests come from is not known, so what its rule (" + rule + ") gives it cannot be told"
		r.Message = folder + "The address the copy sees this server's requests come from is not known, so Sifruno cannot tell what the copy should answer. Check " + p.Path + " on the copy from an address it allows, then accept."
		return r
	}
	r.ExpectedStatus, r.ExpectedNewStatus = hostsStatus(p, oldClient), hostsStatus(p, newClient)
	switch {
	case was.Error != "":
		r.Code, r.Reason = CodeRequestFailed, "old site request failed: "+was.Error
		r.Message = folder + "The old site could not be read there, so its rule was not checked. Compare again; if it still fails, check " + p.Path + " from an address it allows, then accept."
	case now.Error != "":
		r.Code, r.Reason = CodeRequestFailed, "new site request failed: "+now.Error
		r.Message = folder + "The copy could not be read there, so its rule was not checked. Compare again; if it still fails, check " + p.Path + " on the copy from an address it allows, then accept."
	case isClosed(r.ExpectedNewStatus) && isOpen(now.Status):
		r.Code, r.Critical = CodeNewOpen, true
		r.Reason = fmt.Sprintf("the copy answered %d to %s, which its rule (%s) gives %d", now.Status, newClient, rule, r.ExpectedNewStatus)
		r.Message = folder + fmt.Sprintf("The copy answered %s to this server, where its rule gives %s, so the copy may let in addresses the old site keeps out. Before cutover, check %s on the copy from an address the rule does not allow, and accept only if it is closed.", statusText(now.Status), statusText(r.ExpectedNewStatus), p.Path)
	case was.Status != r.ExpectedStatus:
		r.Code = CodeOldUnexpectedStatus
		r.Reason = fmt.Sprintf("old site answered %d to %s, expected %d by its rule (%s)", was.Status, oldClient, r.ExpectedStatus, rule)
		r.Message = folder + fmt.Sprintf("The old site answered %s to this server, where its rule gives %s, so Sifruno cannot tell whether the copy keeps the same rule. %s", statusText(was.Status), statusText(r.ExpectedStatus), next)
	case now.Status != r.ExpectedNewStatus:
		r.Code = CodeNewDiffers
		r.Reason = fmt.Sprintf("the copy answered %d to %s, expected %d by its rule (%s)", now.Status, newClient, r.ExpectedNewStatus, rule)
		r.Message = folder + fmt.Sprintf("The copy answered %s to this server, where its rule gives %s. Check %s on the copy from an address it allows and from one it does not, then accept.", statusText(now.Status), statusText(r.ExpectedNewStatus), p.Path)
	case was.Status == 401 && now.Status == 401 && was.AuthScheme != now.AuthScheme:
		r.Code = CodeAuthSchemeDiffers
		r.Reason = fmt.Sprintf("auth scheme %s → %s", orNone(was.AuthScheme), orNone(now.AuthScheme))
		r.Message = folder + "The copy asks for the folder's password in another way than the old site. Check " + p.Path + " on the copy from an address it allows, then accept."
	default:
		r.Result, r.Code = Pass, CodeOK
		r.Reason = fmt.Sprintf("old site answered %d to %s and the copy %d to %s, as its rule (%s) gives them", was.Status, oldClient, now.Status, newClient, rule)
	}
	return r
}

// statusText names a status in plain words for a person.
func statusText(status int) string {
	switch status {
	case 200:
		return "200 (open)"
	case 401:
		return "401 (asks for a password)"
	case 403:
		return "403 (closed)"
	}
	return fmt.Sprintf("%d", status)
}

func clientText(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}
