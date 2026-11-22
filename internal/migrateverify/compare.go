package migrateverify

import (
	"fmt"
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
	if kind == ProbeAuth {
		return 401
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
