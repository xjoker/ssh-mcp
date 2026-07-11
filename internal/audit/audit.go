// Package audit implements the append-only JSONL audit log.
// SDD §5.9, §9.1–§9.6.
//
// Module boundary: only internal/safety may be imported from internal/*.
package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xjoker/ssh-mcp/internal/safety"
)

// dateLayout is the UTC date format used in filenames.
const dateLayout = "2006-01-02"

// filePrefix is the prefix for audit log filenames.
const filePrefix = "audit-"

// fileSuffix is the suffix for audit log filenames.
const fileSuffix = ".jsonl"

// defaultLimit is the default Query result limit.
const defaultLimit = 100

// maxLimit is the maximum Query result limit.
const maxLimit = 1000

// Entry is a single audit log record. SDD §5.9 / §9.2.
//
// Status / CorrelationID extend SDD §9.2 to support the fail-closed
// pre-record semantics described in §9.3: destructive tools emit a
// "pending" entry before invocation and a "completed" entry after,
// both bearing the same CorrelationID for forensic matching.
type Entry struct {
	Timestamp     time.Time `json:"timestamp"`
	SessionID     string    `json:"session_id"`
	Tool          string    `json:"tool"`
	Server        string    `json:"server,omitempty"`
	AuthMode      string    `json:"auth_mode,omitempty"`
	ArgsRedacted  string    `json:"args_redacted,omitempty"`
	ExitCode      int       `json:"exit_code,omitempty"`
	DurationMs    int64     `json:"duration_ms"`
	BytesIn       int64     `json:"bytes_in,omitempty"`
	BytesOut      int64     `json:"bytes_out,omitempty"`
	ErrorCode     string    `json:"error_code,omitempty"`
	Status        string    `json:"status,omitempty"`
	CorrelationID string    `json:"correlation_id,omitempty"`

	// Stdout / Stderr capture the remote command's output for forensic
	// replay. Populated by ssh_exec / ssh_group_exec / session_send. The
	// dispatcher applies redaction and the configured per-entry size cap
	// (settings.audit_output_max_bytes) before persisting. Truncated
	// payloads append a "\n…[truncated, N bytes total]" suffix so a
	// downstream reader can distinguish a clipped record from a literal
	// short one. Empty when settings.audit_record_output=false.
	Stdout string `json:"stdout,omitempty"`
	Stderr string `json:"stderr,omitempty"`
}

// Filter specifies predicates for Query. SDD §5.9.
type Filter struct {
	Server     string
	Tool       string
	Since      time.Time
	Until      time.Time
	ExitCodeEq *int // nil = any
	ErrorOnly  bool
	Limit      int // default 100, max 1000
}

// Logger is an append-only audit log writer/reader. SDD §5.9.
// All exported methods are safe for concurrent use.
type Logger struct {
	mu            sync.Mutex
	dir           string
	retentionDays int
	currentDate   string // YYYY-MM-DD of open file
	file          *os.File
	bw            *bufio.Writer
	closed        bool
}

// NewReader opens an existing audit directory in read-only mode for Query
// callers (e.g. the `audit query` CLI). Unlike New, it does NOT enforce
// retention (no deletion of old files), does NOT create the directory or
// open today's file for writing, and is safe to use on a directory whose
// retention policy is governed by the running daemon.
//
// The returned Logger MUST NOT be used to Record entries; doing so will
// fail because the underlying file is never opened for writing.
func NewReader(dir string) (*Logger, error) {
	if _, err := os.Stat(dir); err != nil {
		return nil, fmt.Errorf("audit: cannot stat dir %s: %w", dir, err)
	}
	// file/bw stay nil; Record will reject any write attempts via the
	// "audit: logger is closed" path. Close is idempotent and safe.
	return &Logger{dir: dir}, nil
}

// New creates (or opens) the audit directory, deletes files older than
// retentionDays, and opens the current day's log file.
// SDD §9.5.
func New(dir string, retentionDays int) (*Logger, error) {
	if retentionDays <= 0 {
		return nil, fmt.Errorf("audit: retentionDays must be positive, got %d", retentionDays)
	}

	// Create directory with mode 0700.
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("audit: cannot create dir %s: %w", dir, err)
	}

	// Enforce directory permission: set 0700 explicitly in case it already
	// existed with looser permissions. 0700 is intentional — audit log is
	// user-private; only the owning user (the ssh-mcp daemon's UID) needs
	// to traverse / list / create here.
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- audit dir is user-private by design
		return nil, fmt.Errorf("audit: cannot chmod dir %s: %w", dir, err)
	}

	l := &Logger{
		dir:           dir,
		retentionDays: retentionDays,
	}

	// Retention: remove files older than retentionDays. SDD §9.5.
	if err := l.enforceRetention(); err != nil {
		return nil, err
	}

	if err := l.openCurrentFile(); err != nil {
		return nil, err
	}
	return l, nil
}

// enforceRetention deletes audit files older than retentionDays. Runs at New
// and again on each daily rotation so a long-running daemon keeps pruning
// (previously cleanup only happened at startup and the directory grew
// without bound). The cutoff is truncated to date granularity: a file from
// exactly retentionDays ago is kept for the whole day, not deleted at the
// wall-clock minute the daemon happened to start.
func (l *Logger) enforceRetention() error {
	cutoff := time.Now().UTC().AddDate(0, 0, -l.retentionDays).Truncate(24 * time.Hour)
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return fmt.Errorf("audit: cannot read dir %s: %w", l.dir, err)
	}
	for _, de := range entries {
		name := de.Name()
		if !strings.HasPrefix(name, filePrefix) || !strings.HasSuffix(name, fileSuffix) {
			continue
		}
		dateStr := name[len(filePrefix) : len(name)-len(fileSuffix)]
		t, parseErr := time.Parse(dateLayout, dateStr)
		if parseErr != nil {
			continue
		}
		if t.UTC().Before(cutoff) {
			_ = os.Remove(filepath.Join(l.dir, name))
		}
	}
	return nil
}

// openCurrentFile opens (or creates) today's JSONL file.
// Caller must hold l.mu or be in a single-threaded context (New).
func (l *Logger) openCurrentFile() error {
	today := time.Now().UTC().Format(dateLayout)
	path := l.auditFilePath(today)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("audit: cannot open log file %s: %w", path, err)
	}

	// Close previous file if rotating.
	if l.file != nil {
		if l.bw != nil {
			_ = l.bw.Flush()
		}
		_ = l.file.Sync()
		_ = l.file.Close()
	}

	l.file = f
	l.bw = bufio.NewWriter(f)
	l.currentDate = today
	return nil
}

// auditFilePath returns the full path for a given date string.
func (l *Logger) auditFilePath(date string) string {
	return filepath.Join(l.dir, filePrefix+date+fileSuffix)
}

// Record writes a single audit entry to the log.
// If writing or syncing fails, an error is returned and the caller MUST
// refuse to execute the underlying operation (fail-closed; SDD §9.3, S-5).
func (l *Logger) Record(e Entry) error {
	// Redact secrets from ArgsRedacted before write (defence in depth; SDD §9.4).
	e.ArgsRedacted = string(safety.RedactSecret([]byte(e.ArgsRedacted)))

	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: cannot marshal entry: %w", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed || l.bw == nil || l.file == nil {
		return fmt.Errorf("audit: logger is closed")
	}

	// Lazy date rotation: if UTC date changed, open a new file and prune
	// expired files. SDD §9.5. Retention runs at most once per day here;
	// a sweep failure must not block the write (fail-closed applies to
	// recording, not pruning).
	today := time.Now().UTC().Format(dateLayout)
	if today != l.currentDate {
		if err := l.openCurrentFile(); err != nil {
			return fmt.Errorf("audit: rotate failed: %w", err)
		}
		if l.retentionDays > 0 {
			if err := l.enforceRetention(); err != nil {
				fmt.Fprintf(os.Stderr, "audit: retention sweep failed: %v\n", err)
			}
		}
	}

	if _, err := l.bw.Write(data); err != nil {
		return fmt.Errorf("audit: write failed: %w", err)
	}
	if err := l.bw.WriteByte('\n'); err != nil {
		return fmt.Errorf("audit: write newline failed: %w", err)
	}

	// Flush bufio and fsync — caller must be able to trust entry is on disk.
	if err := l.bw.Flush(); err != nil {
		return fmt.Errorf("audit: flush failed: %w", err)
	}
	if err := l.file.Sync(); err != nil {
		return fmt.Errorf("audit: fsync failed: %w", err)
	}
	return nil
}

// Flush flushes any buffered data and syncs to disk.
func (l *Logger) Flush() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.flushLocked()
}

// flushLocked performs flush+sync while holding the lock.
func (l *Logger) flushLocked() error {
	if l.bw == nil || l.file == nil {
		return nil
	}
	if err := l.bw.Flush(); err != nil {
		return fmt.Errorf("audit: flush failed: %w", err)
	}
	if err := l.file.Sync(); err != nil {
		return fmt.Errorf("audit: fsync failed: %w", err)
	}
	return nil
}

// Close flushes, syncs, and closes the underlying file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.file == nil {
		return nil
	}
	flushErr := l.flushLocked()
	closeErr := l.file.Close()
	l.file = nil
	l.bw = nil
	if flushErr != nil {
		return flushErr
	}
	return closeErr
}

// Query returns audit entries matching f, most recent first, up to f.Limit.
// SDD §9.6.
func (l *Logger) Query(f Filter) ([]Entry, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = defaultLimit
	}
	if limit > maxLimit {
		limit = maxLimit
	}

	// Determine date range.
	now := time.Now().UTC()
	since := f.Since
	until := f.Until
	if until.IsZero() {
		until = now
	}

	// Build list of dates to scan, descending (most recent first).
	var dates []string
	if since.IsZero() {
		// Collect all audit files in the directory, descending.
		entries, err := os.ReadDir(l.dir)
		if err != nil {
			return nil, fmt.Errorf("audit: query readdir: %w", err)
		}
		for _, de := range entries {
			name := de.Name()
			if !strings.HasPrefix(name, filePrefix) || !strings.HasSuffix(name, fileSuffix) {
				continue
			}
			dateStr := name[len(filePrefix) : len(name)-len(fileSuffix)]
			if _, parseErr := time.Parse(dateLayout, dateStr); parseErr != nil {
				continue
			}
			// Only include dates up to until.
			t, _ := time.Parse(dateLayout, dateStr)
			if !t.After(until.Truncate(24 * time.Hour)) {
				dates = append(dates, dateStr)
			}
		}
		// Sort descending.
		sort.Sort(sort.Reverse(sort.StringSlice(dates)))
	} else {
		// Walk from until down to since (one date per day).
		cur := until.UTC().Truncate(24 * time.Hour)
		floor := since.UTC().Truncate(24 * time.Hour)
		for !cur.Before(floor) {
			dates = append(dates, cur.Format(dateLayout))
			cur = cur.AddDate(0, 0, -1)
		}
	}

	var results []Entry

	for _, date := range dates {
		if len(results) >= limit {
			break
		}
		path := l.auditFilePath(date)
		fileEntries, err := readFile(path, f, limit)
		if err != nil {
			// File may not exist (e.g. no activity that day) — skip silently.
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("audit: query read %s: %w", path, err)
		}
		results = append(results, fileEntries...)
	}

	// Sort by timestamp descending (entries within a file are appended in order;
	// across files they are already processed newest-first, but within a file
	// the scan is forward). SDD §9.6 step 3.
	sort.Slice(results, func(i, j int) bool {
		return results[i].Timestamp.After(results[j].Timestamp)
	})
	if len(results) > limit {
		results = results[:limit]
	}

	return results, nil
}

// maxAuditLineBytes bounds a single JSONL line during Query. Lines beyond
// this are skipped like malformed rows instead of aborting the whole query
// (bufio.Scanner's ErrTooLong previously made one oversized row poison every
// query forever). 8 MiB comfortably exceeds any configurable per-entry
// output cap.
const maxAuditLineBytes = 8 << 20

// readFile reads entries from a single JSONL file that match the filter,
// keeping only the LAST limit matches (entries are appended in ascending
// time order, and Query wants the most recent). The sliding window bounds
// memory on huge single-day files instead of loading every match. Entries
// are returned in file order (ascending timestamp). limit <= 0 keeps all.
func readFile(path string, f Filter, limit int) ([]Entry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	r := bufio.NewReaderSize(file, 64*1024)
	var results []Entry
	lineNo := 0
	for {
		line, tooLong, rerr := readLineBounded(r, maxAuditLineBytes)
		if rerr != nil && rerr != io.EOF {
			return nil, rerr
		}
		if len(line) > 0 || tooLong {
			lineNo++
		}
		switch {
		case tooLong:
			fmt.Fprintf(os.Stderr, "audit: skip oversized JSONL line at %s:%d (> %d bytes)\n",
				filepath.Base(path), lineNo, maxAuditLineBytes)
		case len(line) > 0:
			var e Entry
			if err := json.Unmarshal(line, &e); err != nil {
				// Skip malformed lines (e.g. truncation from a kill -9) so a
				// single bad row does not poison the entire query. Log to
				// stderr for diagnostics.
				fmt.Fprintf(os.Stderr, "audit: skip malformed JSONL at %s:%d: %v\n",
					filepath.Base(path), lineNo, err)
			} else if matchFilter(e, f) {
				if limit > 0 && len(results) >= limit {
					results = results[1:] // drop oldest; window stays bounded
				}
				results = append(results, e)
			}
		}
		if rerr == io.EOF {
			return results, nil
		}
	}
}

// readLineBounded reads one newline-terminated line (without the newline)
// from r. Lines longer than max are consumed to their end and reported as
// tooLong with a nil payload. err is io.EOF at end of input.
func readLineBounded(r *bufio.Reader, max int) (line []byte, tooLong bool, err error) {
	for {
		chunk, cerr := r.ReadSlice('\n')
		if !tooLong {
			line = append(line, chunk...)
			if len(line) > max {
				tooLong = true
				line = nil
			}
		}
		switch cerr {
		case bufio.ErrBufferFull:
			continue // keep consuming the same line
		case nil:
			if !tooLong {
				line = bytes.TrimRight(line, "\r\n")
			}
			return line, tooLong, nil
		default:
			if !tooLong {
				line = bytes.TrimRight(line, "\r\n")
			}
			return line, tooLong, cerr
		}
	}
}

// matchFilter returns true if e satisfies all predicates in f.
func matchFilter(e Entry, f Filter) bool {
	if f.Server != "" && e.Server != f.Server {
		return false
	}
	if f.Tool != "" && e.Tool != f.Tool {
		return false
	}
	if f.ExitCodeEq != nil && e.ExitCode != *f.ExitCodeEq {
		return false
	}
	if f.ErrorOnly && e.ErrorCode == "" {
		return false
	}
	if !f.Since.IsZero() && e.Timestamp.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && e.Timestamp.After(f.Until) {
		return false
	}
	return true
}
