// Package audit implements the append-only JSONL audit log.
// SDD §5.9, §9.1–§9.6.
//
// Module boundary: only internal/safety may be imported from internal/*.
package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xjoker/mcp-ssh-bridge/internal/safety"
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
}

// New creates (or opens) the audit directory, deletes files older than
// retentionDays, and opens the current day's log file.
// SDD §9.5.
func New(dir string, retentionDays int) (*Logger, error) {
	// Create directory with mode 0700.
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("audit: cannot create dir %s: %w", dir, err)
	}

	// Enforce directory permission: set 0700 explicitly in case it already
	// existed with looser permissions.
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, fmt.Errorf("audit: cannot chmod dir %s: %w", dir, err)
	}

	// Retention: remove files older than retentionDays. SDD §9.5.
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("audit: cannot read dir %s: %w", dir, err)
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
			_ = os.Remove(filepath.Join(dir, name))
		}
	}

	l := &Logger{
		dir:           dir,
		retentionDays: retentionDays,
	}

	if err := l.openCurrentFile(); err != nil {
		return nil, err
	}
	return l, nil
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

	// Lazy date rotation: if UTC date changed, open a new file. SDD §9.5.
	today := time.Now().UTC().Format(dateLayout)
	if today != l.currentDate {
		if err := l.openCurrentFile(); err != nil {
			return fmt.Errorf("audit: rotate failed: %w", err)
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
		fileEntries, err := readFile(path, f, limit-len(results))
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

// readFile reads up to maxResults entries from a single JSONL file that match
// the filter. Entries are returned in file order (ascending timestamp).
func readFile(path string, f Filter, maxResults int) ([]Entry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// 1 MiB buffer per SDD §9.6.
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	var results []Entry
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			// Skip malformed lines.
			continue
		}
		if !matchFilter(e, f) {
			continue
		}
		results = append(results, e)
		if len(results) >= maxResults {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return results, nil
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
