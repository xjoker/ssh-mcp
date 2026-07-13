// Package store manages ssh-mcp operational data in SQLite.
package store

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	defaultLimit  = 100
	maxLimit      = 1000
	legacyPrefix  = "audit-"
	legacySuffix  = ".jsonl"
	maxLegacyLine = 8 << 20
)

// Options configures a writable Store.
type Options struct {
	AuditRetentionDays int
}

// AuditEntry is one append-only operational audit record.
type AuditEntry struct {
	ID            int64     `json:"-"`
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
	ContentSHA256 string    `json:"content_sha256,omitempty"`
	Stdout        string    `json:"stdout,omitempty"`
	Stderr        string    `json:"stderr,omitempty"`
}

// AuditCursor identifies an audit entry for stable descending pagination.
type AuditCursor struct {
	Timestamp time.Time
	ID        int64
}

// AuditFilter specifies predicates for QueryAudit.
type AuditFilter struct {
	Server     string
	Tool       string
	Status     string
	Since      time.Time
	Until      time.Time
	ExitCodeEq *int
	ErrorOnly  bool
	Before     *AuditCursor
	Limit      int
}

// LiveResourceType identifies the runtime resource table that stores a live
// state snapshot.
type LiveResourceType string

const (
	LiveResourceSession    LiveResourceType = "session"
	LiveResourceTunnel     LiveResourceType = "tunnel"
	LiveResourceConnection LiveResourceType = "connection"
)

// LiveEntry is a passive snapshot of one runtime resource owned by an MCP
// process. It contains no credentials, command text, or network endpoints.
type LiveEntry struct {
	ProcessID     string
	ResourceType  LiveResourceType
	ResourceID    string
	Server        string
	Kind          string
	PID           int
	MCPClient     string
	StartedAt     time.Time
	LastHeartbeat time.Time
}

// Store is a concurrency-safe SQLite operational store.
type Store struct {
	mu            sync.RWMutex
	pruneMu       sync.Mutex
	db            *sql.DB
	readOnly      bool
	closed        bool
	retentionDays int
	lastPruneDay  string
}

// Open creates a private writable SQLite database, migrates its schema and
// imports retained legacy JSONL audit files exactly once.
func Open(path string, options ...Options) (*Store, error) {
	if path == "" {
		return nil, errors.New("store: database path is required")
	}
	var option Options
	if len(options) > 0 {
		option = options[0]
	}
	if option.AuditRetentionDays < 0 {
		return nil, fmt.Errorf("store: audit retention days must not be negative")
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("store: create directory %q: %w", dir, err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, fmt.Errorf("store: chmod directory %q: %w", dir, err)
	}

	db, err := sql.Open("sqlite", sqliteDSN(path, false))
	if err != nil {
		return nil, fmt.Errorf("store: open database: %w", err)
	}
	store := &Store{db: db, retentionDays: option.AuditRetentionDays}
	if err := store.initialize(path); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// OpenReadOnly opens an existing operational database without migrations,
// JSONL imports, retention pruning, or write access.
func OpenReadOnly(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("store: database path is required")
	}
	db, err := sql.Open("sqlite", sqliteDSN(path, true))
	if err != nil {
		return nil, fmt.Errorf("store: open read-only database: %w", err)
	}
	store := &Store{db: db, readOnly: true}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: open read-only database: %w", err)
	}
	return store, nil
}

func sqliteDSN(path string, readOnly bool) string {
	uri := url.URL{Scheme: "file", Path: path}
	query := url.Values{}
	if readOnly {
		query.Set("mode", "ro")
		query.Add("_pragma", "query_only(ON)")
	} else {
		query.Add("_pragma", "journal_mode(WAL)")
		query.Add("_pragma", "synchronous(FULL)")
		query.Add("_pragma", "busy_timeout(5000)")
		query.Add("_pragma", "foreign_keys(ON)")
	}
	uri.RawQuery = query.Encode()
	return uri.String()
}

func (store *Store) initialize(path string) error {
	if err := store.db.Ping(); err != nil {
		return fmt.Errorf("store: ping database: %w", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("store: chmod database %q: %w", path, err)
	}
	if err := store.migrateSchema(); err != nil {
		return err
	}
	if err := store.importLegacyJSONL(filepath.Dir(path)); err != nil {
		return err
	}
	return store.pruneAudit(time.Now().UTC())
}

func (store *Store) migrateSchema() error {
	_, err := store.db.Exec(`
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at_sec INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS imported_audit_files (
  name TEXT PRIMARY KEY,
  imported_at_sec INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp_sec INTEGER NOT NULL,
  timestamp_nsec INTEGER NOT NULL,
  session_id TEXT NOT NULL,
  tool TEXT NOT NULL,
  server TEXT NOT NULL,
  auth_mode TEXT NOT NULL,
  args_redacted TEXT NOT NULL,
  exit_code INTEGER NOT NULL,
  duration_ms INTEGER NOT NULL,
  bytes_in INTEGER NOT NULL,
  bytes_out INTEGER NOT NULL,
  error_code TEXT NOT NULL,
  status TEXT NOT NULL,
  correlation_id TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  stdout TEXT NOT NULL,
  stderr TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_timestamp_idx ON audit(timestamp_sec DESC, timestamp_nsec DESC, id DESC);
CREATE INDEX IF NOT EXISTS audit_server_idx ON audit(server, timestamp_sec DESC, timestamp_nsec DESC, id DESC);
CREATE INDEX IF NOT EXISTS audit_tool_idx ON audit(tool, timestamp_sec DESC, timestamp_nsec DESC, id DESC);
CREATE TABLE IF NOT EXISTS live_sessions (
  process_id TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  server TEXT NOT NULL,
  kind TEXT NOT NULL,
  pid INTEGER NOT NULL,
  mcp_client TEXT NOT NULL,
  started_at_sec INTEGER NOT NULL,
  started_at_nsec INTEGER NOT NULL,
  last_heartbeat_sec INTEGER NOT NULL,
  last_heartbeat_nsec INTEGER NOT NULL,
  PRIMARY KEY (process_id, resource_id)
);
CREATE TABLE IF NOT EXISTS live_tunnels (
  process_id TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  server TEXT NOT NULL,
  kind TEXT NOT NULL,
  pid INTEGER NOT NULL,
  mcp_client TEXT NOT NULL,
  started_at_sec INTEGER NOT NULL,
  started_at_nsec INTEGER NOT NULL,
  last_heartbeat_sec INTEGER NOT NULL,
  last_heartbeat_nsec INTEGER NOT NULL,
  PRIMARY KEY (process_id, resource_id)
);
CREATE TABLE IF NOT EXISTS live_connections (
  process_id TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  server TEXT NOT NULL,
  kind TEXT NOT NULL,
  pid INTEGER NOT NULL,
  mcp_client TEXT NOT NULL,
  started_at_sec INTEGER NOT NULL,
  started_at_nsec INTEGER NOT NULL,
  last_heartbeat_sec INTEGER NOT NULL,
  last_heartbeat_nsec INTEGER NOT NULL,
  PRIMARY KEY (process_id, resource_id)
);
CREATE INDEX IF NOT EXISTS live_sessions_heartbeat_idx ON live_sessions(last_heartbeat_sec, last_heartbeat_nsec);
CREATE INDEX IF NOT EXISTS live_tunnels_heartbeat_idx ON live_tunnels(last_heartbeat_sec, last_heartbeat_nsec);
CREATE INDEX IF NOT EXISTS live_connections_heartbeat_idx ON live_connections(last_heartbeat_sec, last_heartbeat_nsec);
INSERT OR IGNORE INTO schema_migrations(version, applied_at_sec) VALUES (1, unixepoch());`)
	if err != nil {
		return fmt.Errorf("store: migrate schema: %w", err)
	}
	if _, err := store.db.Exec("INSERT OR IGNORE INTO schema_migrations(version, applied_at_sec) VALUES (2, unixepoch())"); err != nil {
		return fmt.Errorf("store: record live-state schema migration: %w", err)
	}
	return nil
}

// ReplaceProcessLive atomically replaces every live-state row owned by one
// MCP process. Callers provide a complete current snapshot, so resources that
// closed since the last heartbeat are removed without probing remote systems.
func (store *Store) ReplaceProcessLive(processID string, entries []LiveEntry) error {
	if processID == "" {
		return errors.New("store: live process ID is required")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed || store.db == nil || store.readOnly {
		return errors.New("store: database is closed or read-only")
	}
	for index := range entries {
		if entries[index].ProcessID == "" {
			entries[index].ProcessID = processID
		}
		if entries[index].ProcessID != processID {
			return fmt.Errorf("store: live entry %q belongs to process %q, want %q", entries[index].ResourceID, entries[index].ProcessID, processID)
		}
		if err := validateLiveEntry(entries[index]); err != nil {
			return err
		}
	}

	tx, err := store.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin live-state replacement: %w", err)
	}
	defer tx.Rollback()
	for _, table := range liveTables {
		if _, err := tx.Exec("DELETE FROM "+table+" WHERE process_id = ?", processID); err != nil {
			return fmt.Errorf("store: clear live-state process %q: %w", processID, err)
		}
	}
	for _, entry := range entries {
		table, err := entry.ResourceType.liveTable()
		if err != nil {
			return err
		}
		if _, err := tx.Exec("INSERT INTO "+table+` (
process_id, resource_id, server, kind, pid, mcp_client,
started_at_sec, started_at_nsec, last_heartbeat_sec, last_heartbeat_nsec
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			entry.ProcessID, entry.ResourceID, entry.Server, entry.Kind, entry.PID, entry.MCPClient,
			entry.StartedAt.Unix(), entry.StartedAt.Nanosecond(), entry.LastHeartbeat.Unix(), entry.LastHeartbeat.Nanosecond()); err != nil {
			return fmt.Errorf("store: insert live %s %q: %w", entry.ResourceType, entry.ResourceID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit live-state replacement: %w", err)
	}
	return nil
}

// DeleteProcessLive removes every live-state row owned by one MCP process.
// It is idempotent so clean shutdown can safely race with a disconnected
// transport's cancellation path.
func (store *Store) DeleteProcessLive(processID string) error {
	if processID == "" {
		return nil
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed || store.db == nil || store.readOnly {
		return errors.New("store: database is closed or read-only")
	}
	for _, table := range liveTables {
		if _, err := store.db.Exec("DELETE FROM "+table+" WHERE process_id = ?", processID); err != nil {
			return fmt.Errorf("store: delete live-state process %q: %w", processID, err)
		}
	}
	return nil
}

// ListLive returns live-state rows whose heartbeat is not older than cutoff.
// A zero cutoff returns all rows, including stale rows for diagnostics.
func (store *Store) ListLive(cutoff time.Time) ([]LiveEntry, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed || store.db == nil {
		return nil, errors.New("store: database is closed")
	}
	entries := make([]LiveEntry, 0)
	for _, resourceType := range liveResourceTypes {
		table, _ := resourceType.liveTable()
		query := `SELECT process_id, resource_id, server, kind, pid, mcp_client,
started_at_sec, started_at_nsec, last_heartbeat_sec, last_heartbeat_nsec FROM ` + table
		args := make([]any, 0, 3)
		if !cutoff.IsZero() {
			query += " WHERE last_heartbeat_sec > ? OR (last_heartbeat_sec = ? AND last_heartbeat_nsec >= ?)"
			args = append(args, cutoff.Unix(), cutoff.Unix(), cutoff.Nanosecond())
		}
		query += " ORDER BY last_heartbeat_sec DESC, last_heartbeat_nsec DESC, process_id, resource_id"
		rows, err := store.db.Query(query, args...)
		if err != nil {
			return nil, fmt.Errorf("store: query live %s: %w", resourceType, err)
		}
		for rows.Next() {
			entry := LiveEntry{ResourceType: resourceType}
			var startedSec, heartbeatSec int64
			var startedNSec, heartbeatNSec int
			if err := rows.Scan(&entry.ProcessID, &entry.ResourceID, &entry.Server, &entry.Kind, &entry.PID, &entry.MCPClient,
				&startedSec, &startedNSec, &heartbeatSec, &heartbeatNSec); err != nil {
				rows.Close()
				return nil, fmt.Errorf("store: scan live %s: %w", resourceType, err)
			}
			entry.StartedAt = time.Unix(startedSec, int64(startedNSec)).UTC()
			entry.LastHeartbeat = time.Unix(heartbeatSec, int64(heartbeatNSec)).UTC()
			entries = append(entries, entry)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: iterate live %s: %w", resourceType, err)
		}
		rows.Close()
	}
	return entries, nil
}

// ReapLive physically deletes rows whose heartbeat is older than cutoff.
// Readers must still apply the cutoff in ListLive so crashed-process rows are
// never shown as active before this lazy cleanup runs.
func (store *Store) ReapLive(cutoff time.Time) error {
	if cutoff.IsZero() {
		return nil
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed || store.db == nil || store.readOnly {
		return errors.New("store: database is closed or read-only")
	}
	for _, table := range liveTables {
		if _, err := store.db.Exec("DELETE FROM "+table+" WHERE last_heartbeat_sec < ? OR (last_heartbeat_sec = ? AND last_heartbeat_nsec < ?)", cutoff.Unix(), cutoff.Unix(), cutoff.Nanosecond()); err != nil {
			return fmt.Errorf("store: reap live-state: %w", err)
		}
	}
	return nil
}

var liveResourceTypes = []LiveResourceType{
	LiveResourceSession,
	LiveResourceTunnel,
	LiveResourceConnection,
}

var liveTables = []string{
	"live_sessions",
	"live_tunnels",
	"live_connections",
}

func (resourceType LiveResourceType) liveTable() (string, error) {
	switch resourceType {
	case LiveResourceSession:
		return "live_sessions", nil
	case LiveResourceTunnel:
		return "live_tunnels", nil
	case LiveResourceConnection:
		return "live_connections", nil
	default:
		return "", fmt.Errorf("store: invalid live resource type %q", resourceType)
	}
}

func validateLiveEntry(entry LiveEntry) error {
	if entry.ResourceID == "" {
		return errors.New("store: live resource ID is required")
	}
	if _, err := entry.ResourceType.liveTable(); err != nil {
		return err
	}
	if entry.StartedAt.IsZero() || entry.LastHeartbeat.IsZero() {
		return fmt.Errorf("store: live %s %q requires start and heartbeat times", entry.ResourceType, entry.ResourceID)
	}
	return nil
}

// RecordAudit atomically persists an audit entry. Errors are returned to let
// the caller preserve fail-closed execution semantics.
func (store *Store) RecordAudit(entry AuditEntry) error {
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed || store.db == nil || store.readOnly {
		return errors.New("store: database is closed or read-only")
	}
	if err := store.maybePruneAudit(time.Now().UTC()); err != nil {
		return err
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	_, err := store.db.Exec(`INSERT INTO audit (
timestamp_sec, timestamp_nsec, session_id, tool, server, auth_mode,
args_redacted, exit_code, duration_ms, bytes_in, bytes_out, error_code,
status, correlation_id, content_sha256, stdout, stderr
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.Timestamp.Unix(), entry.Timestamp.Nanosecond(), entry.SessionID, entry.Tool,
		entry.Server, entry.AuthMode, entry.ArgsRedacted, entry.ExitCode, entry.DurationMs,
		entry.BytesIn, entry.BytesOut, entry.ErrorCode, entry.Status, entry.CorrelationID,
		entry.ContentSHA256, entry.Stdout, entry.Stderr)
	if err != nil {
		return fmt.Errorf("store: record audit: %w", err)
	}
	return nil
}

// QueryAudit returns matching entries in descending timestamp order.
func (store *Store) QueryAudit(filter AuditFilter) ([]AuditEntry, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed || store.db == nil {
		return nil, errors.New("store: database is closed")
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = defaultLimit
	}
	if limit > maxLimit {
		limit = maxLimit
	}

	where := make([]string, 0, 8)
	args := make([]any, 0, 13)
	if filter.Server != "" {
		where = append(where, "server = ?")
		args = append(args, filter.Server)
	}
	if filter.Tool != "" {
		where = append(where, "tool = ?")
		args = append(args, filter.Tool)
	}
	if filter.Status != "" {
		where = append(where, "status = ?")
		args = append(args, filter.Status)
	}
	if !filter.Since.IsZero() {
		where = append(where, "(timestamp_sec > ? OR (timestamp_sec = ? AND timestamp_nsec >= ?))")
		args = append(args, filter.Since.Unix(), filter.Since.Unix(), filter.Since.Nanosecond())
	}
	until := filter.Until
	if until.IsZero() {
		until = time.Now().UTC()
	}
	where = append(where, "(timestamp_sec < ? OR (timestamp_sec = ? AND timestamp_nsec <= ?))")
	args = append(args, until.Unix(), until.Unix(), until.Nanosecond())
	if filter.ExitCodeEq != nil {
		where = append(where, "exit_code = ?")
		args = append(args, *filter.ExitCodeEq)
	}
	if filter.ErrorOnly {
		where = append(where, "error_code <> ''")
	}
	if filter.Before != nil {
		where = append(where, `(timestamp_sec < ? OR
(timestamp_sec = ? AND (timestamp_nsec < ? OR (timestamp_nsec = ? AND id < ?))))`)
		args = append(args, filter.Before.Timestamp.Unix(), filter.Before.Timestamp.Unix(),
			filter.Before.Timestamp.Nanosecond(), filter.Before.Timestamp.Nanosecond(), filter.Before.ID)
	}
	query := `SELECT id, timestamp_sec, timestamp_nsec, session_id, tool, server, auth_mode,
args_redacted, exit_code, duration_ms, bytes_in, bytes_out, error_code,
status, correlation_id, content_sha256, stdout, stderr FROM audit`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY timestamp_sec DESC, timestamp_nsec DESC, id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := store.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query audit: %w", err)
	}
	defer rows.Close()
	entries := make([]AuditEntry, 0)
	for rows.Next() {
		var entry AuditEntry
		var seconds int64
		var nanoseconds int
		if err := rows.Scan(&entry.ID, &seconds, &nanoseconds, &entry.SessionID, &entry.Tool, &entry.Server,
			&entry.AuthMode, &entry.ArgsRedacted, &entry.ExitCode, &entry.DurationMs,
			&entry.BytesIn, &entry.BytesOut, &entry.ErrorCode, &entry.Status,
			&entry.CorrelationID, &entry.ContentSHA256, &entry.Stdout, &entry.Stderr); err != nil {
			return nil, fmt.Errorf("store: scan audit: %w", err)
		}
		entry.Timestamp = time.Unix(seconds, int64(nanoseconds)).UTC()
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate audit: %w", err)
	}
	return entries, nil
}

// Close releases the database handle. It is safe to call more than once.
func (store *Store) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	if store.db == nil {
		return nil
	}
	err := store.db.Close()
	store.db = nil
	return err
}

func (store *Store) importLegacyJSONL(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("store: list legacy audit files: %w", err)
	}
	names := make([]string, 0)
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), legacyPrefix) && strings.HasSuffix(entry.Name(), legacySuffix) {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		var imported int
		if err := store.db.QueryRow("SELECT COUNT(*) FROM imported_audit_files WHERE name = ?", name).Scan(&imported); err != nil {
			return fmt.Errorf("store: check legacy import %q: %w", name, err)
		}
		if imported > 0 {
			continue
		}
		if err := store.importLegacyFile(filepath.Join(dir, name), name); err != nil {
			return err
		}
	}
	return nil
}

func (store *Store) importLegacyFile(path, name string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("store: open legacy audit %q: %w", name, err)
	}
	defer file.Close()

	tx, err := store.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin legacy import %q: %w", name, err)
	}
	defer tx.Rollback()
	insert, err := tx.Prepare(`INSERT INTO audit (
timestamp_sec, timestamp_nsec, session_id, tool, server, auth_mode,
args_redacted, exit_code, duration_ms, bytes_in, bytes_out, error_code,
status, correlation_id, content_sha256, stdout, stderr
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("store: prepare legacy import %q: %w", name, err)
	}
	defer insert.Close()

	reader := bufio.NewReaderSize(file, 64*1024)
	for {
		line, tooLong, readErr := readLegacyLine(reader, maxLegacyLine)
		if readErr != nil && readErr != io.EOF {
			return fmt.Errorf("store: read legacy audit %q: %w", name, readErr)
		}
		if !tooLong && len(line) > 0 {
			var entry AuditEntry
			if err := json.Unmarshal(line, &entry); err == nil && !entry.Timestamp.IsZero() {
				if _, err := insert.Exec(entry.Timestamp.Unix(), entry.Timestamp.Nanosecond(), entry.SessionID,
					entry.Tool, entry.Server, entry.AuthMode, entry.ArgsRedacted, entry.ExitCode,
					entry.DurationMs, entry.BytesIn, entry.BytesOut, entry.ErrorCode, entry.Status,
					entry.CorrelationID, entry.ContentSHA256, entry.Stdout, entry.Stderr); err != nil {
					return fmt.Errorf("store: import legacy audit %q: %w", name, err)
				}
			}
		}
		if readErr == io.EOF {
			break
		}
	}
	if _, err := tx.Exec("INSERT INTO imported_audit_files(name, imported_at_sec) VALUES (?, unixepoch())", name); err != nil {
		return fmt.Errorf("store: mark legacy audit %q: %w", name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit legacy audit %q: %w", name, err)
	}
	return nil
}

func readLegacyLine(reader *bufio.Reader, max int) (line []byte, tooLong bool, err error) {
	for {
		chunk, readErr := reader.ReadSlice('\n')
		if !tooLong {
			line = append(line, chunk...)
			if len(line) > max {
				tooLong = true
				line = nil
			}
		}
		switch readErr {
		case bufio.ErrBufferFull:
			continue
		case nil:
			if !tooLong && len(line) > 0 && line[len(line)-1] == '\n' {
				line = line[:len(line)-1]
			}
			return line, tooLong, nil
		case io.EOF:
			return line, tooLong, io.EOF
		default:
			return nil, tooLong, readErr
		}
	}
}

func (store *Store) maybePruneAudit(now time.Time) error {
	store.pruneMu.Lock()
	defer store.pruneMu.Unlock()
	if store.retentionDays == 0 || store.lastPruneDay == now.Format("2006-01-02") {
		return nil
	}
	return store.pruneAudit(now)
}

func (store *Store) pruneAudit(now time.Time) error {
	if store.retentionDays == 0 {
		return nil
	}
	cutoff := now.AddDate(0, 0, -store.retentionDays).Truncate(24 * time.Hour)
	if _, err := store.db.Exec("DELETE FROM audit WHERE timestamp_sec < ?", cutoff.Unix()); err != nil {
		return fmt.Errorf("store: prune audit: %w", err)
	}
	store.lastPruneDay = now.Format("2006-01-02")
	return nil
}
