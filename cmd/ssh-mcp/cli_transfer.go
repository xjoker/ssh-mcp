// File-transfer subcommands: upload / download / cp / fetch.
//
// Motivation: the MCP sftp_op tool uses base64-encoded JSON for both reads
// and writes, which collapses for anything beyond ~10 MiB. The MCP layer is
// intentionally narrow ("operate", not "haul"); this CLI layer is the
// dedicated lane for bulk byte movement so an AI agent can shell out via
// `! ssh-mcp upload ...` and not be blocked by JSON payload limits.
//
// Authentication reuses the same config.toml + keychain/agent paths as the
// MCP server (via the existing `cliCredResolver` / `resolveAuthForTest`),
// so no extra setup is required: any server that works for `ssh_exec` works
// here too.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	pkgsftp "github.com/pkg/sftp"
	"golang.org/x/term"

	"github.com/xjoker/ssh-mcp/internal/config"
	sshpkg "github.com/xjoker/ssh-mcp/internal/ssh"
)

func init() {
	registerSubcommand("upload", uploadCmd)
	registerSubcommand("download", downloadCmd)
	registerSubcommand("cp", cpCmd)
	registerSubcommand("fetch", fetchCmd)
}

// --------------------------------------------------------------------------
// Shared connection helper
// --------------------------------------------------------------------------

// transferConn bundles the live SSH + SFTP clients for a single server.
// Callers MUST call Close to release the SSH channel and pool entry.
type transferConn struct {
	ssh  *sshpkg.Client
	sftp *pkgsftp.Client
	pool *sshpkg.Pool
}

// Close releases the SFTP channel and SSH client. The Pool itself is also
// closed since each CLI invocation owns its own short-lived pool.
func (c *transferConn) Close() {
	if c.sftp != nil {
		_ = c.sftp.Close()
	}
	if c.pool != nil {
		c.pool.Close()
	}
}

// dialServer loads config, looks up the named server, dials it, and opens
// an SFTP channel. cfgPath is the path to config.toml (empty → default).
func dialServer(ctx context.Context, cfgPath, serverName string) (*transferConn, error) {
	if cfgPath == "" {
		cfgPath = resolveConfigPath()
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("load config %s: %w", cfgPath, err)
	}
	name := strings.ToLower(serverName)
	if _, ok := cfg.Servers[name]; !ok {
		return nil, fmt.Errorf("server %q not found in %s", name, cfgPath)
	}
	resolver := &cliCredResolver{cfg: cfg}
	pool := sshpkg.NewPool(cfg, resolver)
	client, err := pool.Get(ctx, name)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("dial %q: %w", name, err)
	}
	sc, err := client.SFTP()
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("open SFTP on %q: %w", name, err)
	}
	return &transferConn{ssh: client, sftp: sc, pool: pool}, nil
}

// --------------------------------------------------------------------------
// Progress reporter
// --------------------------------------------------------------------------

// progressWriter is an io.Writer that wraps an inner writer and prints a
// throttled progress line to stderr. total may be 0 (unknown size); in that
// case only "X bytes copied" is shown without a percentage.
//
// In TTY mode (stderr is an interactive terminal) the line updates in-place
// using \r every 500 ms; in non-TTY mode (CI, piped logs) we suppress the
// streaming updates entirely and only emit the single final "— done" line
// to avoid spamming log files with carriage-return reflow.
type progressWriter struct {
	inner    io.Writer
	total    int64
	written  int64
	label    string
	last     time.Time
	started  time.Time
	interval time.Duration
	tty      bool
}

func newProgressWriter(w io.Writer, total int64, label string) *progressWriter {
	now := time.Now()
	return &progressWriter{
		inner:    w,
		total:    total,
		label:    label,
		started:  now,
		last:     now,
		interval: 500 * time.Millisecond,
		tty:      term.IsTerminal(int(os.Stderr.Fd())),
	}
}

func (p *progressWriter) Write(b []byte) (int, error) {
	n, err := p.inner.Write(b)
	p.written += int64(n)
	// Streaming updates only when attached to a TTY. In a non-interactive
	// stderr (CI log, file redirect) the \r-based reflow turns into a wall
	// of garbled lines — skip the throttled updates and let Done emit a
	// single tidy summary.
	if p.tty && time.Since(p.last) >= p.interval {
		p.print(false)
		p.last = time.Now()
	}
	return n, err
}

// Done emits a final progress line (newline-terminated).
func (p *progressWriter) Done() { p.print(true) }

func (p *progressWriter) print(final bool) {
	elapsed := time.Since(p.started)
	rate := float64(p.written) / elapsed.Seconds()
	if elapsed.Seconds() < 0.1 {
		rate = 0
	}

	var line string
	if p.total > 0 {
		pct := float64(p.written) * 100.0 / float64(p.total)
		line = fmt.Sprintf("%s: %s / %s (%.1f%%) at %s/s",
			p.label, humanBytes(p.written), humanBytes(p.total), pct, humanBytes(int64(rate)))
	} else {
		line = fmt.Sprintf("%s: %s at %s/s",
			p.label, humanBytes(p.written), humanBytes(int64(rate)))
	}
	if final {
		fmt.Fprintln(os.Stderr, line+" — done")
	} else {
		// TTY path — reflow in place.
		fmt.Fprintf(os.Stderr, "\r%s", line)
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// --------------------------------------------------------------------------
// upload: local file → remote server
// --------------------------------------------------------------------------

func uploadCmd(args []string) int {
	fs := flag.NewFlagSet("upload", flag.ContinueOnError)
	cfgPath := fs.String("path", "", "config file path")
	mkdirs := fs.Bool("mkdirs", true, "create missing parent directories on the remote")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ssh-mcp upload <server> <local_path> <remote_path>")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Stream a local file to a remote server. No size limit (unlike sftp_op).")
		fmt.Fprintln(os.Stderr, "Authentication reuses the config.toml + keychain/agent setup for <server>.")
		fmt.Fprintln(os.Stderr, "")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	rest := fs.Args()
	if len(rest) != 3 {
		fs.Usage()
		return 1
	}
	server, localPath, remotePath := rest[0], rest[1], rest[2]

	src, err := os.Open(localPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "upload: open local %s: %v\n", localPath, err)
		return 1
	}
	defer func() { _ = src.Close() }()

	info, err := src.Stat()
	if err != nil {
		fmt.Fprintf(os.Stderr, "upload: stat local %s: %v\n", localPath, err)
		return 1
	}
	if info.IsDir() {
		fmt.Fprintf(os.Stderr, "upload: local %s is a directory (directory uploads not supported yet)\n", localPath)
		return 1
	}

	ctx := context.Background()
	conn, err := dialServer(ctx, *cfgPath, server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "upload: %v\n", err)
		return 1
	}
	defer conn.Close()

	if *mkdirs {
		remoteDir := path.Dir(remotePath)
		if remoteDir != "." && remoteDir != "/" && remoteDir != "" {
			if err := conn.sftp.MkdirAll(remoteDir); err != nil {
				fmt.Fprintf(os.Stderr, "upload: mkdir -p %s: %v\n", remoteDir, err)
				return 1
			}
		}
	}

	dst, err := conn.sftp.Create(remotePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "upload: create remote %s: %v\n", remotePath, err)
		return 1
	}

	pw := newProgressWriter(dst, info.Size(), fmt.Sprintf("upload %s → %s:%s", filepath.Base(localPath), server, remotePath))
	written, copyErr := io.Copy(pw, src)
	closeErr := dst.Close()
	pw.Done()

	if copyErr != nil {
		fmt.Fprintf(os.Stderr, "upload: stream: %v\n", copyErr)
		return 1
	}
	// Close() must run AFTER io.Copy to flush — SFTP servers often surface
	// quota / disk-full errors only on close. Treating Close errors as
	// success would silently leave the user with a corrupted remote file.
	if closeErr != nil {
		fmt.Fprintf(os.Stderr, "upload: close remote %s:%s: %v (remote file may be truncated/incomplete)\n", server, remotePath, closeErr)
		return 1
	}
	fmt.Fprintf(os.Stderr, "upload: %d bytes written to %s:%s\n", written, server, remotePath)
	return 0
}

// --------------------------------------------------------------------------
// download: remote server → local file
// --------------------------------------------------------------------------

func downloadCmd(args []string) int {
	fs := flag.NewFlagSet("download", flag.ContinueOnError)
	cfgPath := fs.String("path", "", "config file path")
	mkdirs := fs.Bool("mkdirs", true, "create missing parent directories on the local side")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ssh-mcp download <server> <remote_path> <local_path>")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Stream a remote file to local disk. No size limit (unlike sftp_op).")
		fmt.Fprintln(os.Stderr, "")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	rest := fs.Args()
	if len(rest) != 3 {
		fs.Usage()
		return 1
	}
	server, remotePath, localPath := rest[0], rest[1], rest[2]

	ctx := context.Background()
	conn, err := dialServer(ctx, *cfgPath, server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "download: %v\n", err)
		return 1
	}
	defer conn.Close()

	src, err := conn.sftp.Open(remotePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "download: open remote %s:%s: %v\n", server, remotePath, err)
		return 1
	}
	defer func() { _ = src.Close() }()

	info, err := conn.sftp.Stat(remotePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "download: stat remote %s:%s: %v\n", server, remotePath, err)
		return 1
	}

	if *mkdirs {
		localDir := filepath.Dir(localPath)
		if localDir != "." && localDir != "" {
			// 0o700: download destination is user-private. The user explicitly
			// chose this path; we don't second-guess by relaxing to 0o755 the
			// way mkdir(1) would. Matches the audit dir convention.
			if err := os.MkdirAll(localDir, 0o700); err != nil {
				fmt.Fprintf(os.Stderr, "download: mkdir -p %s: %v\n", localDir, err)
				return 1
			}
		}
	}

	dst, err := os.Create(localPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "download: create local %s: %v\n", localPath, err)
		return 1
	}

	pw := newProgressWriter(dst, info.Size(), fmt.Sprintf("download %s:%s → %s", server, remotePath, filepath.Base(localPath)))
	written, copyErr := io.Copy(pw, src)
	closeErr := dst.Close()
	pw.Done()

	if copyErr != nil {
		fmt.Fprintf(os.Stderr, "download: stream: %v\n", copyErr)
		// Leave the partial file on disk so the user can inspect / resume manually.
		return 1
	}
	if closeErr != nil {
		// Local disk-full / FS errors usually surface only at close.
		fmt.Fprintf(os.Stderr, "download: close local %s: %v (file may be truncated/incomplete)\n", localPath, closeErr)
		return 1
	}
	fmt.Fprintf(os.Stderr, "download: %d bytes written to %s\n", written, localPath)
	return 0
}

// --------------------------------------------------------------------------
// cp: server-A:path → server-B:path (local pipe, no SSH inter-trust needed)
// --------------------------------------------------------------------------

func cpCmd(args []string) int {
	fs := flag.NewFlagSet("cp", flag.ContinueOnError)
	cfgPath := fs.String("path", "", "config file path")
	mkdirs := fs.Bool("mkdirs", true, "create missing parent directories on the destination server")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ssh-mcp cp <src_server>:<src_path> <dst_server>:<dst_path>")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Stream a file between two servers via the local host. Avoids the need")
		fmt.Fprintln(os.Stderr, "for SSH trust between the two remote machines.")
		fmt.Fprintln(os.Stderr, "")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	rest := fs.Args()
	if len(rest) != 2 {
		fs.Usage()
		return 1
	}

	srcServer, srcPath, ok := splitServerPath(rest[0])
	if !ok {
		fmt.Fprintln(os.Stderr, "cp: source must be of form <server>:<path>")
		return 1
	}
	dstServer, dstPath, ok := splitServerPath(rest[1])
	if !ok {
		fmt.Fprintln(os.Stderr, "cp: destination must be of form <server>:<path>")
		return 1
	}
	// Server name canonicalisation matches the rest of the codebase (config
	// keys are stored lower-cased; dialServer also lower-cases). Compare in
	// canonical form so `Prod:/x → prod:/x` is correctly recognised as the
	// same server and rejected — otherwise the destination `Create` could
	// truncate the very file being read on the source side.
	if strings.EqualFold(srcServer, dstServer) {
		fmt.Fprintln(os.Stderr, "cp: source and destination are the same server; use a remote shell command (mv/cp) instead")
		return 1
	}

	ctx := context.Background()
	srcConn, err := dialServer(ctx, *cfgPath, srcServer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cp: source: %v\n", err)
		return 1
	}
	defer srcConn.Close()

	dstConn, err := dialServer(ctx, *cfgPath, dstServer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cp: dest: %v\n", err)
		return 1
	}
	defer dstConn.Close()

	srcFile, err := srcConn.sftp.Open(srcPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cp: open %s:%s: %v\n", srcServer, srcPath, err)
		return 1
	}
	defer func() { _ = srcFile.Close() }()

	info, err := srcConn.sftp.Stat(srcPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cp: stat %s:%s: %v\n", srcServer, srcPath, err)
		return 1
	}

	if *mkdirs {
		dstDir := path.Dir(dstPath)
		if dstDir != "." && dstDir != "/" && dstDir != "" {
			if err := dstConn.sftp.MkdirAll(dstDir); err != nil {
				fmt.Fprintf(os.Stderr, "cp: mkdir -p %s:%s: %v\n", dstServer, dstDir, err)
				return 1
			}
		}
	}

	dstFile, err := dstConn.sftp.Create(dstPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cp: create %s:%s: %v\n", dstServer, dstPath, err)
		return 1
	}

	pw := newProgressWriter(dstFile, info.Size(), fmt.Sprintf("cp %s:%s → %s:%s", srcServer, srcPath, dstServer, dstPath))
	written, copyErr := io.Copy(pw, srcFile)
	closeErr := dstFile.Close()
	pw.Done()

	if copyErr != nil {
		fmt.Fprintf(os.Stderr, "cp: stream: %v\n", copyErr)
		return 1
	}
	if closeErr != nil {
		fmt.Fprintf(os.Stderr, "cp: close %s:%s: %v (destination may be truncated/incomplete)\n", dstServer, dstPath, closeErr)
		return 1
	}
	fmt.Fprintf(os.Stderr, "cp: %d bytes copied %s:%s → %s:%s\n", written, srcServer, srcPath, dstServer, dstPath)
	return 0
}

// splitServerPath splits "server:path" into its two parts. Returns ok=false
// when the input doesn't contain a colon at all.
func splitServerPath(spec string) (server, p string, ok bool) {
	i := strings.IndexByte(spec, ':')
	if i <= 0 || i == len(spec)-1 {
		return "", "", false
	}
	return spec[:i], spec[i+1:], true
}

// --------------------------------------------------------------------------
// fetch: HTTP(S) URL → remote server (proxied via the local host)
// --------------------------------------------------------------------------

func fetchCmd(args []string) int {
	fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
	cfgPath := fs.String("path", "", "config file path")
	mkdirs := fs.Bool("mkdirs", true, "create missing parent directories on the remote")
	timeout := fs.Duration("timeout", 30*time.Minute, "overall fetch timeout")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ssh-mcp fetch <server> <url> <remote_path>")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Download <url> on the LOCAL host and stream it to <remote_path> on")
		fmt.Fprintln(os.Stderr, "<server>. Useful when the remote server cannot reach the URL (GFW,")
		fmt.Fprintln(os.Stderr, "egress restrictions) but the local host can.")
		fmt.Fprintln(os.Stderr, "")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	rest := fs.Args()
	if len(rest) != 3 {
		fs.Usage()
		return 1
	}
	server, url, remotePath := rest[0], rest[1], rest[2]

	if !(strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")) {
		fmt.Fprintf(os.Stderr, "fetch: url must start with http:// or https:// (got %q)\n", url)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetch: build request: %v\n", err)
		return 1
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetch: HTTP GET %s: %v\n", url, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "fetch: HTTP %s returned %d %s\n", url, resp.StatusCode, resp.Status)
		return 1
	}

	conn, err := dialServer(ctx, *cfgPath, server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetch: %v\n", err)
		return 1
	}
	defer conn.Close()

	if *mkdirs {
		remoteDir := path.Dir(remotePath)
		if remoteDir != "." && remoteDir != "/" && remoteDir != "" {
			if err := conn.sftp.MkdirAll(remoteDir); err != nil {
				fmt.Fprintf(os.Stderr, "fetch: mkdir -p %s:%s: %v\n", server, remoteDir, err)
				return 1
			}
		}
	}

	dst, err := conn.sftp.Create(remotePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetch: create remote %s:%s: %v\n", server, remotePath, err)
		return 1
	}

	pw := newProgressWriter(dst, resp.ContentLength, fmt.Sprintf("fetch %s → %s:%s", url, server, remotePath))
	written, copyErr := io.Copy(pw, resp.Body)
	closeErr := dst.Close()
	pw.Done()

	if copyErr != nil {
		fmt.Fprintf(os.Stderr, "fetch: stream: %v\n", copyErr)
		return 1
	}
	if closeErr != nil {
		fmt.Fprintf(os.Stderr, "fetch: close remote %s:%s: %v (remote file may be truncated/incomplete)\n", server, remotePath, closeErr)
		return 1
	}
	fmt.Fprintf(os.Stderr, "fetch: %d bytes written to %s:%s\n", written, server, remotePath)
	return 0
}
