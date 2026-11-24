package hostaccounts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Scheduled jobs: an account's crontab, which cronie's crond runs as the
// account's user through PAM (README, Scheduled jobs). The broker writes the
// whole job set as one fixed file from validated jobs; root never runs a
// job's command.

// MaxCronJobs bounds one account's job set.
const MaxCronJobs = 50

// maxCronCommand bounds one command, in bytes; maxCronLines bounds the job
// lines of the whole file, so the request stays within cronRequestBytes even
// when the client's JSON escapes every byte as \u00XX.
const (
	maxCronCommand  = 1024
	maxCronSchedule = 100
	maxCronLines    = 16 << 10
)

// cronRequestBytes bounds a request that sets jobs: six bytes per byte of
// job text (Go's JSON encoder writes <, > and & as < and so on), the
// keys of 50 jobs, the reason and the actor.
const cronRequestBytes = 128 << 10

// CronJob is one scheduled job: five cron fields and a command for /bin/sh.
type CronJob struct {
	Schedule string `json:"schedule"`
	Command  string `json:"command"`
}

// CronEntry is a job as the account's job list shows it, with its next run
// in the server's time zone (RFC 3339), or empty when the schedule names no
// date that comes (31 February).
type CronEntry struct {
	CronJob
	NextRun string `json:"next_run"`
}

// CronInput replaces the account's whole job set; an empty list removes
// every job.
type CronInput struct {
	Jobs             []CronJob `json:"jobs"`
	ExpectedRevision uint64    `json:"expected_revision"`
	Reason           string    `json:"reason"`
}

// CronResult is the account with its installed jobs. ServerTime is the
// broker's clock (RFC 3339 with the server's offset): crond reads schedules
// in that time zone.
type CronResult struct {
	Account    Account     `json:"account"`
	Jobs       []CronEntry `json:"jobs"`
	ServerTime string      `json:"server_time"`
}

// cronDigestPattern is a job set's journal target: the SHA-256 of its job
// lines. The journal names a set by digest and never copies a command, which
// may hold a secret such as a URL token.
var cronDigestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// cronFields are the five fields' bounds, as cronie 1.5.7 reads them
// (entry.c, FIRST_* and LAST_*): minute, hour, day of month, month, day of
// week, where 0 and 7 are both Sunday.
var cronFields = [5]struct {
	name   string
	lo, hi int
}{{"minute", 0, 59}, {"hour", 0, 23}, {"day of month", 1, 31}, {"month", 1, 12}, {"day of week", 0, 7}}

// cronSchedule is a parsed schedule: one bit per allowed value of each
// field, and whether the field starts with "*", which decides how cron
// joins the two day fields.
type cronSchedule struct {
	bits [5]uint64
	star [5]bool
}

// CronJobProblem says in plain words why a job is refused, or "" when the
// broker admits it. The grammar is a strict subset of cronie's: per field a
// comma list of "*", "*/step", "n", "n-m" or "n-m/step" with numbers of one
// or two digits, no names, no "@" shortcuts, no "~" ranges, and exactly one
// space between fields. The command is one line of 1 to 1024 bytes of
// printable UTF-8 with no "%", which cron would turn into a new line, and
// does not start with "-" or "*": AlmaLinux 9's cronie reads a leading "-"
// as an option of the entry (its n_option patch, entry.c), and cronie
// refuses an entry whose command starts with "*" as a typo; either way crond
// would skip the job or run something other than the panel shows. Nor may
// it hold a Unicode format character (category Cf), such as a right-to-left
// override or a zero-width space: shown, the command would read otherwise
// than the bytes the shell runs.
func CronJobProblem(j CronJob) string {
	if problem := storedCronJobProblem(j); problem != "" {
		return problem
	}
	if strings.ContainsFunc(j.Command, func(r rune) bool { return unicode.Is(unicode.Cf, r) }) {
		return "The command contains an invisible formatting character, such as a right-to-left mark, so it would not read as it runs. Type the command again without it."
	}
	return ""
}

// storedCronJobProblem is CronJobProblem without the check for format
// characters, which came later: a set an earlier broker stored, and that
// crond already runs, still reads, and a change left pending across the
// upgrade still finishes.
func storedCronJobProblem(j CronJob) string {
	if _, problem := parseCronSchedule(j.Schedule); problem != "" {
		return problem
	}
	switch c := j.Command; {
	case c == "":
		return "The command is empty."
	case len(c) > maxCronCommand:
		return "The command is longer than 1024 bytes."
	case !utf8.ValidString(c):
		return "The command is not valid text."
	case strings.ContainsFunc(c, unicode.IsControl) || strings.ContainsAny(c, "\u2028\u2029"):
		return "The command must be one line, without tabs or other control characters."
	case strings.Contains(c, "%"):
		return "The command contains %, which cron turns into a new line. Put the command in a script and schedule the script."
	case strings.TrimSpace(c) != c:
		return "The command starts or ends with a space."
	case c[0] == '-' || c[0] == '*':
		return "The command starts with - or *, which cron reads as part of the schedule line. Start it with the program to run."
	}
	return ""
}

// validCronJobs admits a new job set; validStoredCronJobs reads a stored one.
func validCronJobs(jobs []CronJob) bool { return cronJobsPass(jobs, CronJobProblem) }

func validStoredCronJobs(jobs []CronJob) bool {
	return cronJobsPass(jobs, storedCronJobProblem)
}

func cronJobsPass(jobs []CronJob, problem func(CronJob) string) bool {
	if len(jobs) > MaxCronJobs {
		return false
	}
	for _, j := range jobs {
		if problem(j) != "" {
			return false
		}
	}
	return len(cronLines(jobs)) <= maxCronLines
}

func validCronInput(in CronInput, actor string) bool {
	return validCronJobs(in.Jobs) && in.ExpectedRevision > 0 && validText(in.Reason, 500) && validText(actor, 120)
}

func parseCronSchedule(s string) (cronSchedule, string) {
	var out cronSchedule
	if s == "" {
		return out, "The schedule is empty."
	}
	if len(s) > maxCronSchedule {
		return out, "The schedule is longer than 100 characters."
	}
	fields := strings.Split(s, " ")
	if len(fields) != 5 {
		return out, "The schedule needs five fields (minute, hour, day of month, month and day of week), one space apart."
	}
	for i, f := range fields {
		bits, ok := parseCronField(f, cronFields[i].lo, cronFields[i].hi)
		if !ok {
			return out, "The " + cronFields[i].name + " field \"" + f + "\" is not valid. Use *, */step, a number from " + strconv.Itoa(cronFields[i].lo) + " to " + strconv.Itoa(cronFields[i].hi) + ", a range n-m, a range with a step n-m/step, or a comma list of these."
		}
		out.bits[i], out.star[i] = bits, f[0] == '*'
	}
	// cronie makes 0 and 7 the same Sunday (entry.c, "make sundays
	// equivalent").
	if out.bits[4]&(1|1<<7) != 0 {
		out.bits[4] |= 1 | 1<<7
	}
	return out, ""
}

// parseCronField reads one field as cronie's get_list, get_range and
// get_number do, minus month and day names: a step is 1 to hi, a range runs
// upwards, and every number lies within lo and hi.
func parseCronField(f string, lo, hi int) (uint64, bool) {
	if f == "" {
		return 0, false
	}
	var bits uint64
	for _, item := range strings.Split(f, ",") {
		rangePart, stepPart, stepped := strings.Cut(item, "/")
		step := 1
		if stepped {
			n, ok := cronNumber(stepPart)
			if !ok || n < 1 || n > hi {
				return 0, false
			}
			step = n
		}
		var first, last int
		switch {
		case rangePart == "*":
			first, last = lo, hi
		default:
			a, b, isRange := strings.Cut(rangePart, "-")
			x, ok := cronNumber(a)
			if !ok {
				return 0, false
			}
			first, last = x, x
			if isRange {
				y, ok := cronNumber(b)
				if !ok {
					return 0, false
				}
				last = y
			} else if stepped {
				// cronie takes a step only after * or a range.
				return 0, false
			}
		}
		if first < lo || last > hi || first > last {
			return 0, false
		}
		for v := first; v <= last; v += step {
			bits |= 1 << uint(v)
		}
	}
	return bits, true
}

func cronNumber(s string) (int, bool) {
	if len(s) < 1 || len(s) > 2 {
		return 0, false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

// cronLines is the jobs as crontab lines: "schedule command\n" each.
func cronLines(jobs []CronJob) []byte {
	var b bytes.Buffer
	for _, j := range jobs {
		b.WriteString(j.Schedule)
		b.WriteByte(' ')
		b.WriteString(j.Command)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// cronDigest names a job set in the journal and in the store.
func cronDigest(jobs []CronJob) string {
	sum := sha256.Sum256(cronLines(jobs))
	return hex.EncodeToString(sum[:])
}

// emptyCronDigest is the digest of no jobs.
var emptyCronDigest = cronDigest(nil)

// cronFileHeader starts every crontab the broker writes. MAILTO="" sends no
// mail: crond would otherwise mail each job's output to the account, which
// has no mailbox (cronie do_command.c: an empty MAILTO means no mail). No
// other variable is written, so a job always runs with cronie's defaults:
// SHELL /bin/sh, HOME the account's home, PATH /usr/bin:/bin.
const cronFileHeader = "# Managed by Sifruno. The panel rewrites this file from its list of scheduled jobs.\nMAILTO=\"\"\n"

// renderCrontab is the whole crontab file for a job set; nil for no jobs,
// whose installed form is no file at all. cronie needs the last line to end
// with a newline (entry.c), which every job line does.
func renderCrontab(jobs []CronJob) []byte {
	if len(jobs) == 0 {
		return nil
	}
	return append([]byte(cronFileHeader), cronLines(jobs)...)
}

// cronSearchDays bounds the next-run search: every schedule that runs at
// all runs within four years and a day (29 February, or a weekday that
// matches only with a rare day of month).
const cronSearchDays = 4*366 + 1

// nextCronRun is the first minute after now, on now's wall clock, that the
// schedule matches, with cronie's rule for the two day fields: when either
// starts with "*" both must match, otherwise either may (cron.c). A minute
// that does not exist on the wall clock (a daylight saving gap) is skipped;
// crond's own handling of such jumps differs, so the time is a guide there.
func nextCronRun(s cronSchedule, now time.Time) (time.Time, bool) {
	loc := now.Location()
	start := now.Truncate(time.Minute).Add(time.Minute)
	y, m, d := start.Date()
	hour, minute := start.Hour(), start.Minute()
	for day := 0; day < cronSearchDays; day++ {
		date := time.Date(y, m, d+day, 0, 0, 0, 0, loc)
		if day > 0 {
			hour, minute = 0, 0
		}
		if !s.matchesDay(date) {
			continue
		}
		for h := hour; h < 24; h++ {
			if s.bits[1]&(1<<uint(h)) == 0 {
				continue
			}
			from := 0
			if h == hour {
				from = minute
			}
			for mi := from; mi < 60; mi++ {
				if s.bits[0]&(1<<uint(mi)) == 0 {
					continue
				}
				t := time.Date(date.Year(), date.Month(), date.Day(), h, mi, 0, 0, loc)
				if t.Hour() == h && t.Minute() == mi && t.Day() == date.Day() && t.After(now) {
					return t, true
				}
			}
		}
	}
	return time.Time{}, false
}

func (s cronSchedule) matchesDay(date time.Time) bool {
	if s.bits[3]&(1<<uint(date.Month())) == 0 {
		return false
	}
	dom := s.bits[2]&(1<<uint(date.Day())) != 0
	dow := s.bits[4]&(1<<uint(date.Weekday())) != 0
	if s.star[2] || s.star[4] {
		return dom && dow
	}
	return dom || dow
}

// cronEntries adds each job's next run after now.
func cronEntries(jobs []CronJob, now time.Time) []CronEntry {
	out := make([]CronEntry, 0, len(jobs))
	for _, j := range jobs {
		e := CronEntry{CronJob: j}
		if s, problem := parseCronSchedule(j.Schedule); problem == "" {
			if next, ok := nextCronRun(s, now); ok {
				e.NextRun = next.Format(time.RFC3339)
			}
		}
		out = append(out, e)
	}
	return out
}

// CronService is the broker's scheduled-jobs surface. Like SSHKeyService it
// is separate from Service; callers assert for it.
type CronService interface {
	Cron(ctx context.Context, id string) (CronResult, error)
	SetCron(ctx context.Context, id string, in CronInput, actor string) (CronResult, error)
}
