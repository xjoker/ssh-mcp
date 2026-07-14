// Package safety centralizes input validation and escape logic.
// Every other module MUST use this package, never its own ad-hoc validation.
// SDD §5.4, §5.5, §9.4.
package safety

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// --------------------------------------------------------------------------
// Types
// --------------------------------------------------------------------------

// RemotePath is a validated absolute POSIX path on a remote host.
// Only constructable through ValidateRemotePath / Realpath.
type RemotePath struct{ p string }

func (r RemotePath) String() string { return r.p }
func (r RemotePath) IsZero() bool   { return r.p == "" }

// NewRemotePathUnchecked is intended ONLY for internal use by sftp.Realpath
// (which receives an already-resolved absolute path from the remote server).
// All other call sites MUST go through ValidateRemotePath.
func NewRemotePathUnchecked(p string) RemotePath { return RemotePath{p: p} }

// RemoteCommand is the only way to materialize a command string for ssh exec.
type RemoteCommand struct{ raw string }

func (c RemoteCommand) Raw() string { return c.raw }

const RemoteTimeoutUnavailableMessage = "ssh-mcp: terminate_on_timeout requires remote setsid and timeout utilities"

// --------------------------------------------------------------------------
// Sentinel errors
// --------------------------------------------------------------------------

var (
	// ErrInvalidPath is returned by ValidateRemotePath when the path fails
	// any validation rule.
	ErrInvalidPath = errors.New("safety: invalid remote path")

	// ErrPathNotAllowed is returned by CheckAllowed when no prefix matches.
	ErrPathNotAllowed = errors.New("safety: path not in allowed prefixes")
)

// --------------------------------------------------------------------------
// ValidateRemotePath — SDD §5.4
// --------------------------------------------------------------------------

// ValidateRemotePath parses and rejects:
//   - empty strings
//   - paths containing NUL bytes (\x00)
//   - paths exceeding 4096 bytes
//   - non-absolute paths (not starting with '/')
//
// It does NOT resolve '~'; that is SFTP Realpath's responsibility.
// On success it calls path.Clean and returns a RemotePath.
func ValidateRemotePath(p string) (RemotePath, error) {
	if p == "" {
		return RemotePath{}, fmt.Errorf("%w: empty path", ErrInvalidPath)
	}
	if strings.ContainsRune(p, '\x00') {
		return RemotePath{}, fmt.Errorf("%w: contains NUL byte", ErrInvalidPath)
	}
	if len(p) > 4096 {
		return RemotePath{}, fmt.Errorf("%w: exceeds 4096 bytes", ErrInvalidPath)
	}
	if !strings.HasPrefix(p, "/") {
		return RemotePath{}, fmt.Errorf("%w: not an absolute path", ErrInvalidPath)
	}
	cleaned := path.Clean(p)
	return RemotePath{p: cleaned}, nil
}

// --------------------------------------------------------------------------
// CheckAllowed — SDD §5.4
// --------------------------------------------------------------------------

// CheckAllowed returns nil if path is within any of allowedPrefixes,
// else ErrPathNotAllowed. Empty allowedPrefixes means "all allowed".
// Comparison uses path.Clean and is prefix-aware: allowed=/var
// permits /var/log but not /var-other.
func CheckAllowed(rp RemotePath, allowedPrefixes []string) error {
	if len(allowedPrefixes) == 0 {
		return nil
	}
	cleanedPath := path.Clean(rp.p)
	for _, prefix := range allowedPrefixes {
		cleanedPrefix := path.Clean(prefix)
		// "/" allows everything. Without this special case the generic
		// check below would test HasPrefix(path, "//"), which never matches,
		// so explicitly allowing the root would instead deny every path.
		if cleanedPrefix == "/" {
			return nil
		}
		if cleanedPath == cleanedPrefix {
			return nil
		}
		if strings.HasPrefix(cleanedPath, cleanedPrefix+"/") {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrPathNotAllowed, rp.p)
}

// --------------------------------------------------------------------------
// RedactSecret — SDD §5.4 / §9.4
// --------------------------------------------------------------------------

var (
	// PEM block — multiline DOTALL.
	rePEM = regexp.MustCompile(`(?s)-----BEGIN [^-\n]+-----.*?-----END [^-\n]+-----`)

	// password/passwd/secret/token/apikey/api_key followed by : or = and a value.
	reKV = regexp.MustCompile(`(?i)(password|passwd|secret|token|apikey|api_key)\s*[:=]\s*\S+`)

	// URLs with userinfo: https?://user:pass@...
	reURL = regexp.MustCompile(`(?i)(https?://)([^/\s:@]+:[^/\s@]+@)`)

	// AWS access key patterns (AKIA... or ASIA... + 16 uppercase alphanumeric chars).
	reAWSKey = regexp.MustCompile(`(?:AKIA|ASIA)[0-9A-Z]{16}`)

	// CLI flag forms that embed a password inline. SDD §5.9 calls these
	// out specifically (mysql -p, sshpass -p). Long form matches glued
	// (--password=x) and space-separated (--password x) values; short form
	// only glued (-px / -p=x) — `-p value` is ambiguous (mysql -p dbname
	// prompts and treats the operand as a database name, not a password).
	// Group 1 = leading separator, group 2 = flag incl. '='/space separator;
	// the value is everything after group 2 and is replaced wholesale (no
	// splitting on characters inside the value — '=' in a base64 password
	// must not become the boundary). [ \t]+ (not \s+) so the space form
	// cannot swallow a token on the following line.
	reCLIFlagPwd = regexp.MustCompile(`(^|\s)(--password(?:=|[ \t]+)|-p=?)\S+`)

	// `sshpass -p VALUE` (space form, separate from above which also covers it).
	reSshpass = regexp.MustCompile(`(?i)\bsshpass\s+-p\s+\S+`)

	// HTTP Authorization header lines: `Authorization: Bearer xxxx`,
	// `Authorization: Basic xxxx`, `Proxy-Authorization: ...`. Matches the
	// header name (case-insensitive) + scheme + token. Common when audit
	// records stdout/stderr of curl, http clients, log dumps.
	reAuthHeader = regexp.MustCompile(`(?i)((?:proxy-)?authorization)\s*:\s*(bearer|basic|digest|token)\s+\S+`)

	// Bare provider-prefix tokens commonly leaked in CLI output:
	//   - GitHub:  ghp_/gho_/ghu_/ghs_/ghr_  + base62
	//   - OpenAI / Anthropic: sk-...  (≥ 20 chars after prefix)
	//   - npm:     npm_ + 36 base62
	//   - Slack:   xox[bpar]-NNN-NNN-NNN-hex
	// These intentionally use loose length lower bounds because some
	// providers have multiple key formats (e.g. sk-proj-…). False positives
	// against natural text are unlikely thanks to the distinctive prefixes.
	reGithubToken = regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`)
	reSkToken     = regexp.MustCompile(`\bsk-[A-Za-z0-9_\-]{20,}`)
	reNpmToken    = regexp.MustCompile(`\bnpm_[A-Za-z0-9]{30,}`)
	reSlackToken  = regexp.MustCompile(`\bxox[bpars]-[A-Za-z0-9-]{10,}`)
	// JWT (header.payload.signature with base64url segments). Limit length
	// to avoid matching every dotted identifier.
	reJWT = regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`)
)

// sensitiveFieldNames is the canonical set of JSON field names whose values
// must never be retained in audit logs, regardless of nesting depth.
// Comparison is case-insensitive and matches as a substring of the key
// (so "ssh_password", "user_passphrase", "private_key_pem" all hit).
var sensitiveFieldNames = []string{
	"password",
	"passwd",
	"passphrase",
	"private_key_pem",
	"key_pem",
	"private_key",
	"secret",
	"token",
	"apikey",
	"api_key",
	"authorization",
}

// sensitiveContainerNames are entire object/array values that must be
// replaced wholesale (e.g. inline.{host,user,password,...}) — too risky
// to walk field-by-field.
var sensitiveContainerNames = []string{
	"inline",
}

// redactedPlaceholder is the value substituted for any matched secret.
const redactedPlaceholder = "***REDACTED***"

// redactMaxBytes is the maximum input size for JSON-aware redaction.
// Inputs larger than this skip the JSON walk and fall back to the byte-regex
// sweep on a truncated copy, bounding CPU/memory consumption (M03).
const redactMaxBytes = 1 << 20 // 1 MiB

// RedactSecret scans b for known secret patterns and returns a new byte
// slice with matches replaced. The input slice is never modified.
//
// SDD §5.4 / §9.4. The redactor operates in two modes:
//
//  1. JSON-aware (preferred). If b parses as JSON, recursively walk the
//     value and replace any field whose name matches sensitiveFieldNames
//     (substring match, case-insensitive). Fields named in
//     sensitiveContainerNames have their entire value replaced with
//     {"redacted":true}.
//
//  2. Byte regex (fallback). Used when b is not JSON (e.g. a remote
//     command body). Catches PEM blocks, key=value/key:value patterns,
//     URL userinfo, and AWS access key prefixes.
//
// JSON-aware redaction is critical because handler args reach the audit
// logger as `json.RawMessage`; the regex path alone would miss
// `"password":"…"` entirely (S-6 / S-14).
//
// M03: inputs larger than redactMaxBytes bypass the JSON walk and fall back
// to the byte-regex sweep on a truncated copy to bound CPU/stack usage.
func RedactSecret(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	// M03: large inputs skip the recursive JSON walk entirely.
	if len(b) > redactMaxBytes {
		return redactBytes(b[:redactMaxBytes])
	}
	if redacted, ok := tryRedactJSON(b); ok {
		return redacted
	}
	return redactBytes(b)
}

// redactMaxDepth is the maximum JSON nesting depth for redactJSONValue.
// Values nested beyond this depth are replaced with a sentinel string to
// prevent stack exhaustion from deeply-nested inputs (M03).
const redactMaxDepth = 32

// tryRedactJSON returns (redactedJSON, true) if b parses as JSON;
// otherwise (nil, false). Whitespace-only input is treated as non-JSON.
func tryRedactJSON(b []byte) ([]byte, bool) {
	trimmed := bytes_TrimSpace(b)
	if len(trimmed) == 0 {
		return nil, false
	}
	switch trimmed[0] {
	case '{', '[', '"':
		// likely JSON
	default:
		return nil, false
	}
	var v any
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	v = redactJSONValue(v, 0)
	out, err := json.Marshal(v)
	if err != nil {
		return nil, false
	}
	return out, true
}

// redactJSONValue walks a decoded JSON value and rewrites secrets.
// depth tracks the current nesting level; values beyond redactMaxDepth are
// replaced with a sentinel string rather than recursed into (M03).
func redactJSONValue(v any, depth int) any {
	// M03: guard against deeply-nested inputs consuming excessive stack/CPU.
	if depth > redactMaxDepth {
		return "***DEPTH_EXCEEDED***"
	}
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			lk := strings.ToLower(k)
			if matchesAny(lk, sensitiveContainerNames) {
				x[k] = map[string]any{"redacted": true}
				continue
			}
			if matchesAny(lk, sensitiveFieldNames) {
				x[k] = redactedPlaceholder
				continue
			}
			x[k] = redactJSONValue(val, depth+1)
		}
		return x
	case []any:
		for i := range x {
			x[i] = redactJSONValue(x[i], depth+1)
		}
		return x
	case string:
		// Run the byte-regex sweep on string values as a second line of
		// defence (e.g. command bodies that happen to be passed in JSON).
		out := redactBytes([]byte(x))
		return string(out)
	default:
		return v
	}
}

func matchesAny(lowerKey string, patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(lowerKey, p) {
			return true
		}
	}
	return false
}

// bytes_TrimSpace returns b with leading/trailing ASCII whitespace removed.
// Avoids importing the `bytes` package only for this one helper.
func bytes_TrimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end {
		c := b[start]
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			break
		}
		start++
	}
	for end > start {
		c := b[end-1]
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			break
		}
		end--
	}
	return b[start:end]
}

// redactBytes runs the legacy regex sweep over a byte slice. SDD §9.4:
//   - PEM blocks
//   - key=value / key:value for password/passwd/secret/token/apikey/api_key
//   - URLs with userinfo (https://user:pass@host)
//   - AWS access key prefixes (AKIA/ASIA + 16 chars)
func redactBytes(b []byte) []byte {
	out := b
	out = rePEM.ReplaceAll(out, []byte("-----BEGIN REDACTED-----"))
	out = reKV.ReplaceAllFunc(out, func(m []byte) []byte {
		s := string(m)
		for i, c := range s {
			if c == ':' || c == '=' {
				return []byte(s[:i+1] + redactedPlaceholder)
			}
		}
		return []byte(redactedPlaceholder)
	})
	out = reURL.ReplaceAll(out, []byte("${1}***:***@"))
	out = reAWSKey.ReplaceAll(out, []byte(redactedPlaceholder))
	// Template replacement: keep separator + flag, drop the whole value.
	// (An earlier callback split at the first '=' in the match, which for a
	// space-form value containing '=' — e.g. base64 padding — leaked the
	// value prefix into the audit log.)
	out = reCLIFlagPwd.ReplaceAll(out, []byte("${1}${2}"+redactedPlaceholder))
	out = reSshpass.ReplaceAll(out, []byte("sshpass -p "+redactedPlaceholder))

	// Header / token forms commonly seen in stdout/stderr of curl, HTTP
	// clients, package managers, and log dumps. Important now that audit
	// log captures command output (settings.audit_record_output).
	out = reAuthHeader.ReplaceAllFunc(out, func(m []byte) []byte {
		s := string(m)
		// Preserve "<HeaderName>: <Scheme> " then replace the token.
		// Find the second whitespace (after scheme) and cut.
		colon := strings.IndexByte(s, ':')
		if colon < 0 {
			return []byte(redactedPlaceholder)
		}
		rest := strings.TrimLeft(s[colon+1:], " \t")
		schemeEnd := strings.IndexAny(rest, " \t")
		if schemeEnd < 0 {
			return []byte(s[:colon+1] + " " + redactedPlaceholder)
		}
		return []byte(s[:colon+1] + " " + rest[:schemeEnd] + " " + redactedPlaceholder)
	})
	out = reGithubToken.ReplaceAll(out, []byte(redactedPlaceholder))
	out = reSkToken.ReplaceAll(out, []byte(redactedPlaceholder))
	out = reNpmToken.ReplaceAll(out, []byte(redactedPlaceholder))
	out = reSlackToken.ReplaceAll(out, []byte(redactedPlaceholder))
	out = reJWT.ReplaceAll(out, []byte(redactedPlaceholder))
	return out
}

// --------------------------------------------------------------------------
// HostKeyCallback — SDD §5.4
// --------------------------------------------------------------------------

// knownHostsFilePath returns the default ~/.ssh/known_hosts path.
func knownHostsFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("safety: cannot determine home dir: %w", err)
	}
	return path.Join(home, ".ssh", "known_hosts"), nil
}

// khWriteMu guards appends to known_hosts to prevent concurrent duplicate writes.
var khWriteMu sync.Mutex

// HostKeyCallback returns a callback for ssh.ClientConfig.HostKeyCallback
// that reads from ~/.ssh/known_hosts and rejects mismatches.
//
// Fail-closed contract (SDD §13 / S-3):
//
//   - Known and matching key → return nil
//   - Known host, different key (mismatch) → HOST_KEY_MISMATCH (always
//     rejected, regardless of acceptNew)
//   - Unknown host, acceptNew=false → HOST_KEY_UNKNOWN
//   - Unknown host, acceptNew=true → APPEND to known_hosts, then nil ONLY
//     on a successful, fsync'd append. Any failure (cannot resolve path,
//     read existing file, create .ssh dir, open / write / sync the file)
//     MUST be surfaced to the caller; we never silently allow an
//     unverified host on the back of a filesystem error.
func HostKeyCallback(acceptNew bool) cryptoSSH.HostKeyCallback {
	khPath, pathErr := knownHostsFilePath()

	return func(hostname string, remote net.Addr, key cryptoSSH.PublicKey) error {
		// Path resolution failure is always fail-closed. Even with
		// acceptNew=true we cannot persist trust without knowing where
		// the file lives.
		if pathErr != nil {
			return fmt.Errorf("HOST_KEY_UNKNOWN: cannot resolve known_hosts path: %w", pathErr)
		}

		cb, khErr := knownhosts.New(khPath)
		if khErr != nil {
			if !os.IsNotExist(khErr) {
				// Read failure is fail-closed regardless of acceptNew —
				// we have no way to verify the host is genuinely
				// unknown vs. mismatched against an unreadable file.
				return fmt.Errorf("HOST_KEY_UNKNOWN: cannot read known_hosts: %w", khErr)
			}
			// File does not exist — treat as empty (acceptable; will be
			// created in the append path below if acceptNew=true).
			cb = nil
		}

		if cb != nil {
			cbErr := cb(hostname, remote, key)
			if cbErr == nil {
				// Known and matching.
				return nil
			}
			var ke *knownhosts.KeyError
			if errors.As(cbErr, &ke) {
				if len(ke.Want) > 0 {
					// Host is known but key does not match — always reject.
					return fmt.Errorf("HOST_KEY_MISMATCH for %s: %w", hostname, cbErr)
				}
				// len(ke.Want)==0 means unknown host.
				if !acceptNew {
					return fmt.Errorf("HOST_KEY_UNKNOWN for %s: not in known_hosts", hostname)
				}
				// Fall through to append path below.
			} else {
				return fmt.Errorf("HOST_KEY_UNKNOWN: callback error: %w", cbErr)
			}
		}
		if !acceptNew {
			return fmt.Errorf("HOST_KEY_UNKNOWN for %s: not in known_hosts", hostname)
		}

		// acceptNew=true and host is unknown — append to known_hosts.
		// Every step is fail-closed: if we cannot persist the trust
		// decision, we do not pretend to have done so.
		khWriteMu.Lock()
		defer khWriteMu.Unlock()

		sshDir := path.Dir(khPath)
		if mkErr := os.MkdirAll(sshDir, 0o700); mkErr != nil {
			return fmt.Errorf("HOST_KEY_UNKNOWN: cannot create .ssh dir: %w", mkErr)
		}

		f, openErr := os.OpenFile(khPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if openErr != nil {
			return fmt.Errorf("HOST_KEY_UNKNOWN: cannot open known_hosts for append: %w", openErr)
		}

		line := knownhosts.Line([]string{hostname}, key) + "\n"
		if _, writeErr := f.WriteString(line); writeErr != nil {
			_ = f.Close()
			return fmt.Errorf("HOST_KEY_UNKNOWN: cannot write known_hosts entry: %w", writeErr)
		}
		// fsync to disk before closing so a crash between Write and
		// Close cannot leave us thinking the host is trusted.
		if syncErr := f.Sync(); syncErr != nil {
			_ = f.Close()
			return fmt.Errorf("HOST_KEY_UNKNOWN: cannot fsync known_hosts: %w", syncErr)
		}
		if closeErr := f.Close(); closeErr != nil {
			return fmt.Errorf("HOST_KEY_UNKNOWN: cannot close known_hosts: %w", closeErr)
		}
		return nil
	}
}

// --------------------------------------------------------------------------
// ModernAlgorithms — SDD §5.4
// --------------------------------------------------------------------------

// weakAlgorithms maps a known-weak algorithm name to the ssh.Config field
// it belongs to. Only names in this map are accepted via optIn.
var weakAlgorithms = map[string]string{
	"ssh-rsa":                     "HostKeyAlgorithms",
	"hmac-sha1":                   "MACs",
	"hmac-sha1-etm@openssh.com":   "MACs",
	"aes128-cbc":                  "Ciphers",
	"aes192-cbc":                  "Ciphers",
	"aes256-cbc":                  "Ciphers",
	"3des-cbc":                    "Ciphers",
	"diffie-hellman-group14-sha1": "KeyExchanges",
}

// ModernAlgorithms returns ssh.Config with conservative, modern defaults
// (no CBC ciphers, no SHA1 HMAC, no DH-group14-SHA1, no ssh-rsa SHA1).
//
// optIn names that appear in the weak-algorithm whitelist are appended to
// the appropriate Ciphers/MACs/KeyExchanges field.
// Unknown optIn names produce a stderr warning and are silently dropped.
//
// Note: ssh.Config does not have a HostKeyAlgorithms field; callers that
// need to restrict host key algorithms should set ClientConfig.HostKeyAlgorithms
// using ModernHostKeyAlgorithms().
func ModernAlgorithms(optIn []string) cryptoSSH.Config {
	cfg := cryptoSSH.Config{
		KeyExchanges: []string{
			"curve25519-sha256",
			"curve25519-sha256@libssh.org",
			"ecdh-sha2-nistp256",
			"ecdh-sha2-nistp384",
			"ecdh-sha2-nistp521",
			"diffie-hellman-group16-sha512",
			"diffie-hellman-group18-sha512",
		},
		Ciphers: []string{
			"chacha20-poly1305@openssh.com",
			"aes256-gcm@openssh.com",
			"aes128-gcm@openssh.com",
			"aes256-ctr",
			"aes192-ctr",
			"aes128-ctr",
		},
		MACs: []string{
			"hmac-sha2-256-etm@openssh.com",
			"hmac-sha2-512-etm@openssh.com",
			"hmac-sha2-256",
			"hmac-sha2-512",
		},
	}

	for _, name := range optIn {
		category, known := weakAlgorithms[name]
		if !known {
			fmt.Fprintf(os.Stderr, "safety: ModernAlgorithms: unknown optIn algorithm %q — ignored\n", name)
			continue
		}
		switch category {
		case "KeyExchanges":
			cfg.KeyExchanges = append(cfg.KeyExchanges, name)
		case "Ciphers":
			cfg.Ciphers = append(cfg.Ciphers, name)
		case "MACs":
			cfg.MACs = append(cfg.MACs, name)
		case "HostKeyAlgorithms":
			// ssh.Config has no HostKeyAlgorithms field — this optIn affects
			// ClientConfig.HostKeyAlgorithms which callers must handle separately.
			// Silently drop for now (documented above).
		}
	}

	return cfg
}

// ModernHostKeyAlgorithms returns the default modern host key algorithm list
// (excluding ssh-rsa SHA1). Callers should assign this to
// ssh.ClientConfig.HostKeyAlgorithms.
func ModernHostKeyAlgorithms() []string {
	return []string{
		"sk-ssh-ed25519@openssh.com",
		"ssh-ed25519",
		"sk-ecdsa-sha2-nistp256@openssh.com",
		"ecdsa-sha2-nistp256",
		"ecdsa-sha2-nistp384",
		"ecdsa-sha2-nistp521",
		"rsa-sha2-512",
		"rsa-sha2-256",
	}
}

// --------------------------------------------------------------------------
// NewRemoteCommand — SDD §5.5
// --------------------------------------------------------------------------

// NewRemoteCommand builds a RemoteCommand, optionally prefixed with
// `cd '<escaped-dir>' && `.
//
// Rules (SDD §5.5):
//   - dir == "" → raw = cmd (no cd prefix)
//   - dir != "" and not absolute → error
//   - dir is single-quoted with internal ' escaped as '\”
//   - cmd is passed through verbatim (the LLM may write arbitrary shell pipelines)
func NewRemoteCommand(cmd string, dir string) (RemoteCommand, error) {
	if dir == "" {
		return RemoteCommand{raw: cmd}, nil
	}
	if !strings.HasPrefix(dir, "/") {
		return RemoteCommand{}, fmt.Errorf("safety: NewRemoteCommand: dir must be absolute, got %q", dir)
	}
	// Single-quote escape: replace every ' with '\''
	escaped := strings.ReplaceAll(dir, "'", "'\\''")
	raw := "cd '" + escaped + "' && " + cmd
	return RemoteCommand{raw: raw}, nil
}

// WithRemoteTimeout wraps a validated remote command in an opt-in watchdog.
// The watchdog starts one second after the caller's local deadline so the MCP
// response keeps its existing timeout semantics while the detached remote
// process group is still terminated after the SSH channel is closed.
//
// The remote host must provide setsid and timeout. The preflight runs before
// the user command and fails with exit 125 if either utility is unavailable.
func WithRemoteTimeout(cmd RemoteCommand, timeout, killGrace time.Duration) (RemoteCommand, error) {
	if timeout <= 0 {
		return RemoteCommand{}, fmt.Errorf("safety: remote timeout must be positive")
	}
	if killGrace <= 0 {
		return RemoteCommand{}, fmt.Errorf("safety: remote timeout kill grace must be positive")
	}

	watchdogSeconds := durationCeilSeconds(timeout) + 1
	graceSeconds := durationCeilSeconds(killGrace)
	quotedCommand := shellSingleQuote(cmd.Raw())
	raw := fmt.Sprintf(
		"command -v setsid >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1 || "+
			"{ printf '%%s\\n' '%s' >&2; exit 125; }; "+
			"setsid timeout -s TERM -k %ds %ds sh -c %s",
		RemoteTimeoutUnavailableMessage,
		graceSeconds,
		watchdogSeconds,
		quotedCommand,
	)
	return RemoteCommand{raw: raw}, nil
}

func durationCeilSeconds(d time.Duration) int64 {
	return int64((d + time.Second - 1) / time.Second)
}

func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
