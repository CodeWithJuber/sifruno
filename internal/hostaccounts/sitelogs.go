package hostaccounts

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Site logs and usage: the last lines of a site's OpenLiteSpeed logs, its
// disk use against its quota and the bytes it served this month. All are
// read-only for the account (README, Logs and usage).

// LogTail bounds: the broker reads at most the last 256 KiB of a log and
// returns at most its last 200 lines.
const (
	MaxLogTailLines = 200
	maxLogTailBytes = 256 << 10
)

// LogTail is the end of one of a site's logs. Lines are the server's text,
// made valid UTF-8 and otherwise as written; they hold what visitors sent,
// so a reader shows them as text and never interprets them. Truncated says
// the file has earlier lines; Missing that the site has no such log yet.
type LogTail struct {
	Kind      string   `json:"kind"`
	Lines     []string `json:"lines"`
	Truncated bool     `json:"truncated"`
	Size      int64    `json:"size"`
	Missing   bool     `json:"missing"`
}

// SiteUsage is one account's disk use and its site's traffic. Disk comes
// from the account's XFS user quota (KiB; a limit of 0 means none is set).
// Traffic is the response body bytes the site's access log records for the
// month TrafficMonth (YYYY-MM, server time); TrafficComplete is false while
// the broker is still reading earlier log lines, so the number can grow on
// the next read.
type SiteUsage struct {
	AccountID       string `json:"account_id"`
	DiskUsedKiB     int64  `json:"disk_used_kib"`
	DiskLimitKiB    int64  `json:"disk_limit_kib"`
	TrafficMonth    string `json:"traffic_month"`
	TrafficBytes    int64  `json:"traffic_bytes"`
	TrafficComplete bool   `json:"traffic_complete"`
}

// SiteToolsService is the broker's scheduled jobs, logs and usage surface.
type SiteToolsService interface {
	CronService
	SiteLog(ctx context.Context, id, kind string) (LogTail, error)
	SiteUsage(ctx context.Context, id string) (SiteUsage, error)
	UsageAll(ctx context.Context) ([]SiteUsage, error)
}

// logFileNames are the two logs olsweb renders for every site, in
// olsweb.LogRoot/<site name>/.
var logFileNames = map[string]string{"access": "access.log", "error": "error.log"}

// readTail reads at most the last maxLogTailBytes of a log of this size
// and returns its last whole lines.
func readTail(r io.ReaderAt, size int64) ([]string, bool, error) {
	start := max(size-maxLogTailBytes, 0)
	buf := make([]byte, size-start)
	got, err := r.ReadAt(buf, start)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, ErrUnavailable
	}
	lines, truncated := tailLines(buf[:got], start == 0)
	return lines, truncated, nil
}

// tailLines splits the end of a log into whole lines: the first piece is a
// partial line unless the read began at the file's start, a last piece
// without a newline is a line still being written. It keeps the last
// MaxLogTailLines lines and reports whether any earlier text was left out.
func tailLines(b []byte, fromStart bool) ([]string, bool) {
	truncated := !fromStart
	if !fromStart {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			return []string{}, true
		}
		b = b[i+1:]
	}
	if i := bytes.LastIndexByte(b, '\n'); i >= 0 {
		b = b[:i]
	} else {
		b = nil
	}
	lines := []string{}
	if len(b) > 0 {
		for _, l := range bytes.Split(b, []byte{'\n'}) {
			lines = append(lines, strings.ToValidUTF8(string(l), "\uFFFD"))
		}
	}
	if len(lines) > MaxLogTailLines {
		lines, truncated = lines[len(lines)-MaxLogTailLines:], true
	}
	return lines, truncated
}

// ---- Traffic --------------------------------------------------------------

// trafficBudget bounds the log bytes one usage read goes through, for one
// site or for all sites together, so a read of a busy site or of many sites
// stays quick; the rest is read next time.
const trafficBudget = 64 << 20

// maxLogLine bounds one access log line the counter parses; a longer line is
// skipped. OpenLiteSpeed's request line is the bulk of a line.
const maxLogLine = 64 << 10

// maxAccessLogs bounds the rotated logs the counter looks at in one
// directory.
const maxAccessLogs = 4096

// accessLogName matches a site's access log and the copies OpenLiteSpeed
// 1.9.4 rotates it into: <name>.YYYY_MM_DD, then .01, .02 and so on when
// that name is taken (archiveFile in src/log4cxx/logrotate.cpp). olsweb
// renders compressArchive 0, so no .gz copy is made.
var accessLogName = regexp.MustCompile(`^access\.log(\.[0-9]{4}_[0-9]{2}_[0-9]{2}(\.[0-9]{2,4})?)?$`)

// trafficState is a site's counter, kept by the broker in a small file of
// its own: the month counted, its total, and where reading stopped: the
// file (device, inode and modification time when last read) and the offset
// after its last whole line.
type trafficState struct {
	Version int    `json:"version"`
	Month   string `json:"month"`
	Bytes   int64  `json:"bytes"`
	Dev     uint64 `json:"dev"`
	Ino     uint64 `json:"ino"`
	MTime   int64  `json:"mtime"`
	Offset  int64  `json:"offset"`
}

var monthPattern = regexp.MustCompile(`^[0-9]{4}-(0[1-9]|1[0-2])$`)

func decodeTrafficState(b []byte) (trafficState, bool) {
	var st trafficState
	if len(b) == 0 || len(b) > 4096 || json.Unmarshal(b, &st) != nil || st.Version != 1 || !monthPattern.MatchString(st.Month) || st.Bytes < 0 || st.Offset < 0 {
		return trafficState{}, false
	}
	return st, true
}

// logFile is one access log in a site's log directory.
type logFile struct {
	Name     string
	Dev, Ino uint64
	MTime    int64 // nanoseconds
	Size     int64
}

// logDir is a site's log directory as the counter reads it. AccessLogs lists
// the access log and its rotated copies (regular files only); Open opens one
// for reading and must refuse a name that is now another file.
type logDir interface {
	AccessLogs() ([]logFile, error)
	Open(f logFile) (io.ReadCloser, error)
}

// errNoLogs is a site whose log directory does not exist yet.
var errNoLogs = errors.New("no logs yet")

// countTraffic adds the access log lines written since the last read to the
// month's total, reading at most budget bytes. Files are taken oldest
// first: the rotated copies by modification time, the live access.log last.
// Reading resumes in the file and at the offset where it stopped, found by
// its inode whatever its name is now, so a rotation between two reads loses
// nothing; if that file is gone (OpenLiteSpeed removes copies older than
// keepDays), reading resumes with the files written since. Only whole lines
// are counted, and only those of the current month: a new month starts the
// total at 0 and skips the rest of the old month's lines. It returns the new
// state, the bytes read and whether everything written so far was read.
func countTraffic(st trafficState, dir logDir, now time.Time, budget int64) (trafficState, int64, bool, error) {
	month := now.Format("2006-01")
	if st.Version != 1 {
		st = trafficState{Version: 1, Month: month}
	}
	if st.Month != month {
		st.Month, st.Bytes = month, 0
	}
	files, err := dir.AccessLogs()
	if err != nil {
		return st, 0, false, err
	}
	sort.SliceStable(files, func(i, j int) bool {
		a, b := files[i], files[j]
		if (a.Name == "access.log") != (b.Name == "access.log") {
			return b.Name == "access.log"
		}
		if a.MTime != b.MTime {
			return a.MTime < b.MTime
		}
		return a.Ino < b.Ino
	})
	start, offset := -1, int64(0)
	if st.Ino != 0 {
		for i, f := range files {
			if f.Dev == st.Dev && f.Ino == st.Ino {
				start, offset = i, st.Offset
				if f.Size < offset {
					// Truncated or replaced in place: read it again.
					offset = 0
				}
				break
			}
		}
	}
	if start < 0 {
		// First read: this month's files. Otherwise the file read last is
		// gone: the ones written after it.
		since := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()).UnixNano()
		if st.Ino != 0 {
			since = st.MTime + 1
		}
		for i, f := range files {
			if f.MTime >= since || f.Name == "access.log" {
				start = i
				break
			}
		}
	}
	if start < 0 {
		return st, 0, true, nil
	}
	var read int64
	p := accessLineParser{loc: now.Location(), month: month}
	for i := start; i < len(files); i++ {
		f := files[i]
		if i > start {
			offset = 0
		}
		last := i == len(files)-1
		used, sum, n, done, err := p.readFile(dir, f, offset, budget-read, last)
		read += n
		st.Dev, st.Ino, st.MTime, st.Offset = f.Dev, f.Ino, f.MTime, offset+used
		st.Bytes += sum
		if err != nil {
			return st, read, false, err
		}
		if !done {
			return st, read, false, nil
		}
	}
	return st, read, true, nil
}

// accessLineParser reads OpenLiteSpeed's combined access log lines
// (AccessLog::log in src/http/accesslog.cpp, 1.9.4): host, "- -" or the
// user, [time], "request line" (escaped: a quote inside it is \"), status,
// then the response body bytes or "-", then the quoted referer and user
// agent. It keeps the last time it parsed, since consecutive lines usually
// share it.
type accessLineParser struct {
	loc       *time.Location
	month     string
	lastStamp string
	lastMonth string
}

// readFile counts f's whole lines from offset up to its size as listed,
// reading at most budget bytes. used is how far the counted lines reach.
// A file that is not the last also counts a final line without a newline:
// OpenLiteSpeed writes whole lines, and nothing more is written to a rotated
// copy; in the live file such a line is still being written and waits for
// the next read. done: the file was read to its end.
func (p *accessLineParser) readFile(dir logDir, f logFile, offset, budget int64, last bool) (used, sum, read int64, done bool, err error) {
	remaining := f.Size - offset
	if remaining <= 0 {
		return 0, 0, 0, true, nil
	}
	if budget <= 0 {
		return 0, 0, 0, false, nil
	}
	limit := min(remaining, budget)
	rc, err := dir.Open(f)
	if err != nil {
		return 0, 0, 0, false, err
	}
	defer rc.Close()
	if offset > 0 {
		s, ok := rc.(io.Seeker)
		if !ok {
			return 0, 0, 0, false, ErrUnavailable
		}
		if _, err := s.Seek(offset, io.SeekStart); err != nil {
			return 0, 0, 0, false, ErrUnavailable
		}
	}
	r := bufio.NewReaderSize(io.LimitReader(rc, limit), 64<<10)
	var line []byte
	skipping := false
	for {
		chunk, e := r.ReadSlice('\n')
		read += int64(len(chunk))
		switch {
		case errors.Is(e, bufio.ErrBufferFull):
			if !skipping {
				line = append(line, chunk...)
				if len(line) > maxLogLine {
					skipping, line = true, line[:0]
				}
			}
			if skipping {
				// What is skipped stays skipped, so a line longer than the
				// budget cannot stop the counter. Its rest reads as a line
				// of its own next time, which does not parse: every quote
				// in it is escaped.
				used = read
			}
		case e == nil:
			if !skipping && len(line)+len(chunk) <= maxLogLine {
				sum += p.lineBytes(append(line, chunk...))
			}
			used, line, skipping = read, line[:0], false
		case e == io.EOF:
			// The listed end, the file's real end (it shrank), or the budget.
			if read < limit || read == remaining {
				if !last {
					if n := len(line) + len(chunk); !skipping && n > 0 && n <= maxLogLine {
						sum += p.lineBytes(append(line, chunk...))
					}
					used = read
				}
				return used, sum, read, true, nil
			}
			if used == 0 && budget > maxLogLine {
				// No whole line in a budget larger than any line the counter
				// parses: one line too long to count. Skip what was read, so
				// the next read moves on. A smaller budget (what is left
				// after other files) stops before the line instead, and the
				// next read starts there.
				used = read
			}
			return used, sum, read, false, nil
		default:
			return used, sum, read, false, ErrUnavailable
		}
	}
}

// lineBytes is the body bytes one line records for the counted month, or 0.
func (p *accessLineParser) lineBytes(line []byte) int64 {
	stamp, n, ok := parseAccessLine(line)
	if !ok {
		return 0
	}
	if stamp != p.lastStamp {
		t, err := time.Parse("02/Jan/2006:15:04:05 -0700", stamp)
		if err != nil {
			return 0
		}
		p.lastStamp, p.lastMonth = stamp, t.In(p.loc).Format("2006-01")
	}
	if p.lastMonth != p.month {
		return 0
	}
	return n
}

// maxLineBytes bounds a body size read from a line (1 PiB): anything larger
// is not a real response.
const maxLineBytes = 1 << 50

// parseAccessLine finds a line's time stamp and body bytes. It trusts no
// field: the request line, the referer and the user agent are what a client
// sent.
func parseAccessLine(line []byte) (string, int64, bool) {
	line = bytes.TrimSuffix(line, []byte{'\n'})
	i := bytes.IndexByte(line, '[')
	// "[02/Jan/2006:15:04:05 -0700] \""
	if i < 0 || len(line) < i+30 || line[i+27] != ']' || line[i+28] != ' ' || line[i+29] != '"' {
		return "", 0, false
	}
	stamp := string(line[i+1 : i+27])
	j := i + 30
	for ; j < len(line); j++ {
		if line[j] == '\\' {
			j++
			continue
		}
		if line[j] == '"' {
			break
		}
	}
	rest := line[min(j+1, len(line)):]
	// ` 200 1234` then the end or a space.
	if j >= len(line) || len(rest) < 6 || rest[0] != ' ' || rest[4] != ' ' {
		return "", 0, false
	}
	for _, c := range rest[1:4] {
		if c < '0' || c > '9' {
			return "", 0, false
		}
	}
	field := rest[5:]
	if k := bytes.IndexByte(field, ' '); k >= 0 {
		field = field[:k]
	}
	if len(field) == 1 && field[0] == '-' {
		return stamp, 0, true
	}
	if len(field) == 0 || len(field) > 16 {
		return "", 0, false
	}
	var n int64
	for _, c := range field {
		if c < '0' || c > '9' {
			return "", 0, false
		}
		n = n*10 + int64(c-'0')
	}
	if n > maxLineBytes {
		return "", 0, false
	}
	return stamp, n, true
}

// ---- Disk -----------------------------------------------------------------

// quotaUsage is one user's block use and limits from xfs_quota, in KiB.
type quotaUsage struct {
	UsedKiB, SoftKiB, HardKiB int64
}

// parseQuotaReport reads `xfs_quota -x -c "report -u -b -n -N ..."`
// (xfsprogs 6.3 quota/report.c, report_mount): one line per user, "#<uid>"
// then the used, soft and hard block counts in KiB (basic blocks >> 1),
// the warnings and the grace time. Other lines are ignored.
func parseQuotaReport(out []byte) map[int]quotaUsage {
	usage := map[int]quotaUsage{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || !strings.HasPrefix(fields[0], "#") {
			continue
		}
		uid, ok := quotaNumber(fields[0][1:])
		if !ok || uid < firstAccountID || uid > lastAccountID {
			continue
		}
		used, ok1 := quotaNumber(fields[1])
		soft, ok2 := quotaNumber(fields[2])
		hard, ok3 := quotaNumber(fields[3])
		if !ok1 || !ok2 || !ok3 {
			continue
		}
		usage[int(uid)] = quotaUsage{UsedKiB: used, SoftKiB: soft, HardKiB: hard}
	}
	return usage
}

func quotaNumber(s string) (int64, bool) {
	if s == "" || len(s) > 18 {
		return 0, false
	}
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int64(c-'0')
	}
	return n, true
}
