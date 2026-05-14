package main

// cli_audit.go implements:
//   audit query [--server X] [--tool Y] [--since <duration|RFC3339>] [--limit N]

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/xjoker/ssh-mcp/internal/audit"
)

// jsonMarshalEntry wraps json.Marshal so the call site can stay readable
// even when audit.Entry grows new fields. Kept tiny on purpose.
func jsonMarshalEntry(e audit.Entry) ([]byte, error) { return json.Marshal(e) }

func init() {
	registerSubcommand("audit", auditCmd)
}

// auditCmd is the top-level "audit" dispatcher.
func auditCmd(args []string) int {
	if len(args) == 0 {
		printAuditUsage()
		return 1
	}
	sub := args[0]
	switch sub {
	case "query":
		return auditQueryCmd(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "audit: unknown subcommand %q\n", sub)
		printAuditUsage()
		return 1
	}
}

func printAuditUsage() {
	fmt.Fprintln(os.Stderr, "usage: ssh-mcp audit <subcommand> [flags]")
	fmt.Fprintln(os.Stderr, "  subcommands: query")
	fmt.Fprintln(os.Stderr, "  query flags:")
	fmt.Fprintln(os.Stderr, "    --server X    filter by server name")
	fmt.Fprintln(os.Stderr, "    --tool Y      filter by tool name")
	fmt.Fprintln(os.Stderr, "    --since T     start time: 1h / 24h / 7d / RFC3339 / YYYY-MM-DD")
	fmt.Fprintln(os.Stderr, "    --limit N     max results (1–1000, default 100)")
	fmt.Fprintln(os.Stderr, "    --output      expanded view with stdout/stderr inline")
	fmt.Fprintln(os.Stderr, "    --json        JSONL output (full fidelity, jq-friendly)")
}

// auditQueryCmd handles "audit query [flags]".
func auditQueryCmd(args []string) int {
	fs := flag.NewFlagSet("audit query", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	serverFlag := fs.String("server", "", "filter by server name")
	toolFlag := fs.String("tool", "", "filter by tool name")
	sinceFlag := fs.String("since", "", "start time: relative (1h, 24h, 7d) or RFC3339")
	limitFlag := fs.Int("limit", 100, "maximum number of results (1–1000)")
	outputFlag := fs.Bool("output", false, "expand stdout / stderr / args inline (default: table view shows metadata only)")
	jsonFlag := fs.Bool("json", false, "emit one JSONL entry per record (full fidelity, includes stdout/stderr/args)")

	if err := fs.Parse(args); err != nil {
		// flag already printed the error
		return 1
	}

	since, err := parseSince(*sinceFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit query: --since %q: %v\n", *sinceFlag, err)
		return 1
	}

	limit := *limitFlag
	if limit <= 0 || limit > 1000 {
		fmt.Fprintln(os.Stderr, "audit query: --limit must be between 1 and 1000")
		return 1
	}

	auditDir := os.Getenv("MCP_SSH_BRIDGE_AUDIT_DIR")
	if auditDir == "" {
		auditDir = defaultAuditDirCLI()
	}

	// Use the read-only opener: the CLI must not trigger retention deletion
	// or rotate the daemon's current-day file. The daemon owns retention.
	logger, err := audit.NewReader(auditDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit query: open audit dir %q: %v\n", auditDir, err)
		return 1
	}
	defer logger.Close()

	filter := audit.Filter{
		Server: *serverFlag,
		Tool:   *toolFlag,
		Since:  since,
		Limit:  limit,
	}

	entries, err := logger.Query(filter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit query: %v\n", err)
		return 1
	}

	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "audit query: no matching entries")
		return 0
	}

	switch {
	case *jsonFlag:
		printAuditJSONL(entries)
	case *outputFlag:
		printAuditExpanded(entries)
	default:
		printAuditTable(entries)
	}
	return 0
}

// parseSince converts a --since value to a time.Time.
// Accepts: "" (zero = no filter), "1h", "24h", "7d", or RFC3339.
func parseSince(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}

	// Try relative duration suffixes: Nh / Nd / Nm
	lower := strings.ToLower(strings.TrimSpace(s))
	if strings.HasSuffix(lower, "h") {
		n, err := strconv.Atoi(strings.TrimSuffix(lower, "h"))
		if err == nil {
			return time.Now().UTC().Add(-time.Duration(n) * time.Hour), nil
		}
	}
	if strings.HasSuffix(lower, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(lower, "d"))
		if err == nil {
			return time.Now().UTC().AddDate(0, 0, -n), nil
		}
	}
	if strings.HasSuffix(lower, "m") {
		n, err := strconv.Atoi(strings.TrimSuffix(lower, "m"))
		if err == nil {
			return time.Now().UTC().Add(-time.Duration(n) * time.Minute), nil
		}
	}

	// Try RFC3339.
	t, err := time.Parse(time.RFC3339, s)
	if err == nil {
		return t.UTC(), nil
	}

	// Try date-only: YYYY-MM-DD
	t, err = time.Parse("2006-01-02", s)
	if err == nil {
		return t.UTC(), nil
	}

	return time.Time{}, fmt.Errorf("unrecognised time format %q (use 1h / 24h / 7d or RFC3339)", s)
}

// printAuditTable writes a human-readable table of entries to stdout.
func printAuditTable(entries []audit.Entry) {
	// Header
	fmt.Printf("%-30s  %-20s  %-12s  %-5s  %s\n",
		"TIMESTAMP", "TOOL", "SERVER", "EXIT", "ERROR")
	fmt.Println(strings.Repeat("-", 90))

	for _, e := range entries {
		ts := e.Timestamp.UTC().Format("2006-01-02T15:04:05Z")
		errCode := e.ErrorCode
		if errCode == "" {
			errCode = "-"
		}
		server := e.Server
		if server == "" {
			server = "-"
		}
		fmt.Printf("%-30s  %-20s  %-12s  %-5d  %s\n",
			ts, e.Tool, server, e.ExitCode, errCode)
	}
	fmt.Printf("\n(%d entries)\n", len(entries))
}

// printAuditExpanded emits each entry as a multi-line block with stdout /
// stderr / args inline. Use when you need to read the actual command output
// without parsing JSON.
func printAuditExpanded(entries []audit.Entry) {
	for i, e := range entries {
		if i > 0 {
			fmt.Println(strings.Repeat("=", 80))
		}
		fmt.Printf("timestamp:      %s\n", e.Timestamp.UTC().Format(time.RFC3339))
		fmt.Printf("tool:           %s\n", e.Tool)
		if e.Server != "" {
			fmt.Printf("server:         %s\n", e.Server)
		}
		if e.SessionID != "" {
			fmt.Printf("session_id:     %s\n", e.SessionID)
		}
		if e.CorrelationID != "" {
			fmt.Printf("correlation_id: %s\n", e.CorrelationID)
		}
		if e.AuthMode != "" {
			fmt.Printf("auth_mode:      %s\n", e.AuthMode)
		}
		fmt.Printf("exit_code:      %d\n", e.ExitCode)
		fmt.Printf("duration_ms:    %d\n", e.DurationMs)
		if e.ErrorCode != "" {
			fmt.Printf("error_code:     %s\n", e.ErrorCode)
		}
		if e.Status != "" {
			fmt.Printf("status:         %s\n", e.Status)
		}
		if e.ArgsRedacted != "" {
			fmt.Printf("args:           %s\n", e.ArgsRedacted)
		}
		if e.Stdout != "" {
			fmt.Printf("stdout:\n%s\n", indentBlock(e.Stdout, "  "))
		}
		if e.Stderr != "" {
			fmt.Printf("stderr:\n%s\n", indentBlock(e.Stderr, "  "))
		}
	}
	fmt.Printf("\n(%d entries)\n", len(entries))
}

// printAuditJSONL writes each entry as a JSON object on its own line for
// piping into jq or another structured-search tool.
func printAuditJSONL(entries []audit.Entry) {
	for _, e := range entries {
		b, err := jsonMarshalEntry(e)
		if err != nil {
			fmt.Fprintf(os.Stderr, "audit query: marshal entry: %v\n", err)
			continue
		}
		fmt.Println(string(b))
	}
}

// indentBlock prefixes every line of s with prefix. Returns the indented
// block without a trailing newline.
func indentBlock(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, ln := range lines {
		lines[i] = prefix + ln
	}
	return strings.Join(lines, "\n")
}
