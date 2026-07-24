package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	gossh "golang.org/x/crypto/ssh"

	"github.com/xjoker/ssh-mcp/internal/config"
	"github.com/xjoker/ssh-mcp/internal/envelope"
	"github.com/xjoker/ssh-mcp/internal/knownhosts"
)

func init() { Registered = append(Registered, toolSSHHostScan()) }

type hostScanInput struct {
	Server string `json:"server,omitempty"`
	Host   string `json:"host,omitempty"`
	Port   int    `json:"port,omitempty"`
}

type hostScanOutput struct {
	Host              string `json:"host"`
	Port              int    `json:"port"`
	KeyType           string `json:"key_type"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	KnownHostsStatus  string `json:"known_hosts_status"`
	TrustCommand      string `json:"trust_command,omitempty"`
	VerificationHint  string `json:"verification_hint,omitempty"`
}

var safeHostName = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$`)

var sshHostScanSchema = json.RawMessage(`{
  "type":"object",
  "additionalProperties":false,
  "properties": {
    "server":{"type":"string","minLength":1,"description":"Configured or temporary server name."},
    "host":{"type":"string","minLength":1,"description":"Direct hostname or IP address (alternative to server)."},
    "port":{"type":"integer","minimum":1,"maximum":65535,"description":"SSH port for direct host; defaults to 22."}
  },
  "oneOf":[
    {"required":["server"],"not":{"anyOf":[{"required":["host"]},{"required":["port"]}]}},
    {"required":["host"],"not":{"required":["server"]}}
  ]
}`)

func toolSSHHostScan() Tool {
	return Tool{
		Name:        "ssh_host_scan",
		Description: "Fetch an SSH host key before authentication. Never reads credentials or writes known_hosts; use it to inspect the SHA256 fingerprint before manually trusting a host.",
		InputSchema: sshHostScanSchema,
		Handle:      handleSSHHostScan,
		Annotations: &Annotations{Title: "Scan SSH host key", ReadOnlyHint: true, DestructiveHint: false, IdempotentHint: false, OpenWorldHint: true},
	}
}

func handleSSHHostScan(ctx context.Context, deps *Deps, args json.RawMessage) envelope.Response {
	home, err := os.UserHomeDir()
	if err != nil {
		return envelope.Err(envelope.CodeInternalError, "resolve home directory: "+err.Error(), false)
	}
	return handleSSHHostScanAtPathContext(ctx, deps, args, filepath.Join(home, ".ssh", "known_hosts"))
}

func handleSSHHostScanAtPath(deps *Deps, args json.RawMessage, knownHostsPath string) envelope.Response {
	return handleSSHHostScanAtPathContext(context.Background(), deps, args, knownHostsPath)
}

func handleSSHHostScanAtPathContext(ctx context.Context, deps *Deps, args json.RawMessage, knownHostsPath string) envelope.Response {
	var input hostScanInput
	if err := json.Unmarshal(args, &input); err != nil {
		return envelope.Err(envelope.CodeInvalidArgument, "invalid JSON: "+err.Error(), false)
	}
	host, port, err := resolveHostScanTarget(deps, input)
	if err != nil {
		return envelope.Err(envelope.CodeInvalidArgument, err.Error(), false)
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	key, err := knownhosts.FetchHostKeyContext(ctx, addr)
	if err != nil {
		return envelope.Err(envelope.CodeConnFailed, err.Error(), true)
	}
	status, err := knownhosts.Check(knownHostsPath, addr, key)
	if err != nil {
		return envelope.Err(envelope.CodeInternalError, err.Error(), false)
	}
	out := hostScanOutput{Host: host, Port: port, KeyType: key.Type(), FingerprintSHA256: gossh.FingerprintSHA256(key), KnownHostsStatus: string(status)}
	if status == knownhosts.StatusUnknown {
		out.TrustCommand = scanTrustCommand(host, port)
	} else if status == knownhosts.StatusMismatch {
		out.VerificationHint = "The scanned key differs from known_hosts. Verify the fingerprint through a trusted channel and repair known_hosts manually; do not automatically trust this key."
	}
	return envelope.OK(out)
}

func scanTrustCommand(host string, port int) string {
	return fmt.Sprintf("ssh-mcp trust --host %s --port %d", host, port)
}

func resolveHostScanTarget(deps *Deps, input hostScanInput) (string, int, error) {
	if (input.Server == "") == (input.Host == "") {
		return "", 0, fmt.Errorf("exactly one of 'server' or 'host' must be provided")
	}
	if input.Server != "" {
		if input.Port != 0 {
			return "", 0, fmt.Errorf("'port' cannot be used with 'server'")
		}
		srv, ok := scanServerConfig(deps, input.Server)
		if !ok {
			return "", 0, fmt.Errorf("server %q not found in configuration", input.Server)
		}
		port := srv.Port
		if port == 0 {
			port = 22
		}
		if err := validateHostScanTarget(srv.Host, port); err != nil {
			return "", 0, err
		}
		return srv.Host, port, nil
	}
	port := input.Port
	if port == 0 {
		port = 22
	}
	if err := validateHostScanTarget(input.Host, port); err != nil {
		return "", 0, err
	}
	return input.Host, port, nil
}

func scanServerConfig(deps *Deps, name string) (config.ServerConfig, bool) {
	name = strings.ToLower(name)
	if deps != nil && deps.Pool != nil {
		if srv, ok := deps.Pool.LookupTempServer(name); ok {
			return srv, true
		}
	}
	if deps != nil && deps.Cfg != nil {
		if srv, ok := deps.Cfg.Servers[name]; ok {
			return srv, true
		}
	}
	return config.ServerConfig{}, false
}

func validateHostScanTarget(host string, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() == "" || safeIPv6Zone(addr.Zone()) {
			return nil
		}
		return fmt.Errorf("host contains unsafe characters")
	}
	if !safeDNSName(host) {
		return fmt.Errorf("host contains unsafe characters")
	}
	return nil
}

func safeIPv6Zone(zone string) bool {
	if zone == "" || len(zone) > 64 {
		return false
	}
	for _, char := range zone {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '_' || char == '.' || char == '-' {
			continue
		}
		return false
	}
	return true
}

func safeDNSName(host string) bool {
	if strings.HasSuffix(host, ".") {
		host = strings.TrimSuffix(host, ".")
	}
	if host == "" || len(host) > 253 || !safeHostName.MatchString(host) {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}
