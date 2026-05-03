// Package safety centralizes input validation and escape logic.
// Every other module MUST use this package, never its own ad-hoc validation.
// SDD §5.4, §5.5, §9.4.
package safety

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"

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
)

// RedactSecret scans b for known secret patterns and returns a new
// byte slice with matches replaced. The input slice is never modified.
// Patterns (SDD §9.4):
//   - PEM blocks
//   - key=value / key:value for password/passwd/secret/token/apikey/api_key
//   - URLs with userinfo (https://user:pass@host)
//   - AWS access key prefixes (AKIA/ASIA + 16 chars)
func RedactSecret(b []byte) []byte {
	out := b

	// PEM blocks → -----BEGIN REDACTED-----
	out = rePEM.ReplaceAll(out, []byte("-----BEGIN REDACTED-----"))

	// key=value → key=***REDACTED*** (keep separator character)
	out = reKV.ReplaceAllFunc(out, func(m []byte) []byte {
		s := string(m)
		for i, c := range s {
			if c == ':' || c == '=' {
				return []byte(s[:i+1] + "***REDACTED***")
			}
		}
		return []byte("***REDACTED***")
	})

	// URL userinfo: https://user:pass@host → https://***:***@host
	out = reURL.ReplaceAll(out, []byte("${1}***:***@"))

	// AWS keys
	out = reAWSKey.ReplaceAll(out, []byte("***REDACTED***"))

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
//   - Known and matching key → return nil
//   - Known host, different key (mismatch) → error containing "HOST_KEY_MISMATCH"
//     (always rejected, regardless of acceptNew)
//   - Unknown host, acceptNew=false → error containing "HOST_KEY_UNKNOWN"
//   - Unknown host, acceptNew=true → append entry to known_hosts, return nil
func HostKeyCallback(acceptNew bool) cryptoSSH.HostKeyCallback {
	khPath, pathErr := knownHostsFilePath()

	return func(hostname string, remote net.Addr, key cryptoSSH.PublicKey) error {
		if pathErr != nil {
			if !acceptNew {
				return fmt.Errorf("HOST_KEY_UNKNOWN: cannot load known_hosts: %w", pathErr)
			}
			fmt.Fprintf(os.Stderr, "safety: HostKeyCallback: cannot resolve known_hosts path: %v\n", pathErr)
			return nil
		}

		cb, khErr := knownhosts.New(khPath)
		if khErr != nil {
			if !os.IsNotExist(khErr) {
				if !acceptNew {
					return fmt.Errorf("HOST_KEY_UNKNOWN: cannot read known_hosts: %w", khErr)
				}
				fmt.Fprintf(os.Stderr, "safety: HostKeyCallback: cannot read known_hosts: %v\n", khErr)
				return nil
			}
			// File does not exist — treat as empty.
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

		// acceptNew=true and host is unknown — append to known_hosts atomically.
		khWriteMu.Lock()
		defer khWriteMu.Unlock()

		sshDir := path.Dir(khPath)
		if mkErr := os.MkdirAll(sshDir, 0700); mkErr != nil {
			return fmt.Errorf("safety: cannot create .ssh dir: %w", mkErr)
		}

		f, openErr := os.OpenFile(khPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if openErr != nil {
			return fmt.Errorf("safety: cannot open known_hosts for append: %w", openErr)
		}
		defer f.Close()

		line := knownhosts.Line([]string{hostname}, key) + "\n"
		if _, writeErr := f.WriteString(line); writeErr != nil {
			return fmt.Errorf("safety: cannot write known_hosts entry: %w", writeErr)
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
//   - dir is single-quoted with internal ' escaped as '\''
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
