// Per-server command policy engine. SDD: docs/design/command-policy.md.
//
// This file is a pure function engine: it knows nothing about config.Config
// or MCP tools. Callers compile a *Policy once (from ServerConfig fields)
// and evaluate raw AI-supplied commands against it before they reach the
// remote shell.
package safety

import (
	"fmt"
	"regexp"
	"strings"
)

// Mode identifies a per-server command policy mode.
// docs/design/command-policy.md §3.
type Mode string

const (
	// ModeUnrestricted is the default: no filtering, identical to the
	// current (pre-policy) behaviour. Equivalent to mode == "".
	ModeUnrestricted Mode = "unrestricted"
	// ModeReadonly allows only a built-in conservative observation
	// allowlist (plus any user allow_patterns), rejects shell metacharacters
	// outright, and lets deny_patterns override.
	ModeReadonly Mode = "readonly"
	// ModeRestricted requires every command to match at least one
	// allow_patterns entry and no deny_patterns entry. Empty allow_patterns
	// denies everything (fail-closed).
	ModeRestricted Mode = "restricted"
)

// Policy is a compiled per-server command policy produced by CompilePolicy.
// A nil *Policy means unrestricted / no policy configured — every method on
// *Policy is nil-receiver safe and treats nil as "permit everything".
type Policy struct {
	mode  Mode
	allow []*regexp.Regexp
	deny  []*regexp.Regexp
}

// metaCharPattern matches shell metacharacters that let a second command
// ride along behind a prefix-anchored allow regex: ; & | > < ` and $(.
// Applied only in ModeReadonly (docs/design/command-policy.md §3.2) — the
// built-in allowlist is system-provided and must not be bypassable this
// way; ModeRestricted allow_patterns are user-authored and the user owns
// anchoring their own regexes.
var metaCharPattern = regexp.MustCompile("[;&|<>`]|\\$\\(")

// readonlyAllowPatterns is the built-in conservative observation allowlist
// for mode="readonly". Every entry is anchored at the start of the line and
// bounded by a following space or end-of-string so prefix collisions (e.g.
// "ls" vs "lsattr", "ls" vs "lsblk") cannot occur.
var readonlyAllowPatterns = []string{
	`^ls( |$)`,
	`^cat( |$)`,
	`^head( |$)`,
	`^tail( |$)`,
	`^grep( |$)`,
	`^stat( |$)`,
	`^file( |$)`,
	`^wc( |$)`,
	`^pwd( |$)`,
	`^df( |$)`,
	`^du( |$)`,
	`^free( |$)`,
	`^ps( |$)`,
	`^uname( |$)`,
	`^whoami( |$)`,
	`^id( |$)`,
	// hostname with any argument (or -F) SETS the hostname — bare form only.
	`^hostname$`,
	// date -s / --set / -f mutate the system clock — permit only the bare
	// form and +FORMAT output.
	`^date($| \+)`,
	`^uptime( |$)`,
	`^printenv( |$)`,
	`^lsblk( |$)`,
	`^lsof( |$)`,
	`^ss( |$)`,
	`^sha256sum( |$)`,
	`^md5sum( |$)`,
	`^journalctl( |$)`,
	`^docker (ps|logs|inspect|images|version|info)( |$)`,
	`^kubectl (get|describe|logs|version)( |$)`,
	`^systemctl (status|list-units|list-unit-files|is-active|is-enabled|is-failed)( |$)`,
	// ip: only read forms of addr/address/route/link. Bare form (defaults to
	// show) or an explicit "show"/"list" subcommand are permitted; anything
	// else (add/del/set/flush/...) is not, so "ip link set eth0 down" must
	// NOT match here.
	`^ip (addr|address|route|link)($| (show|list)( |$))`,
}

// readonlyDenyPatterns is a built-in deny list applied in mode="readonly"
// ahead of user deny_patterns. It blocks mutating maintenance flags on
// otherwise-allowed observation commands: journalctl --vacuum-*/--rotate/
// --flush destroy or move logs, --setup-keys writes FSS sealing keys, and
// --sync forces a disk flush. Matching any line denies it — a rare false
// positive (e.g. grep for the literal string "--rotate") is the accepted
// cost of a conservative readonly mode.
var readonlyDenyPatterns = []string{
	`(^| )--vacuum`,
	`(^| )--rotate( |$)`,
	`(^| )--flush( |$)`,
	`(^| )--setup-keys( |$)`,
	`(^| )--sync( |$)`,
}

var (
	compiledReadonlyAllow = mustCompileAll(readonlyAllowPatterns)
	compiledReadonlyDeny  = mustCompileAll(readonlyDenyPatterns)
)

func mustCompileAll(patterns []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		out[i] = regexp.MustCompile(p)
	}
	return out
}

// CompilePolicy compiles a per-server command policy.
//
// mode must be one of "", "unrestricted", "readonly", "restricted"; any
// other value is an error. "" and "unrestricted" both return a nil *Policy
// (the zero-overhead path: no filtering, matching current behaviour).
//
// allowPatterns / denyPatterns are Go regexp (RE2) source strings; an
// invalid pattern is an error naming its index.
func CompilePolicy(mode string, allowPatterns, denyPatterns []string) (*Policy, error) {
	m := Mode(mode)
	switch m {
	case "", ModeUnrestricted:
		return nil, nil
	case ModeReadonly, ModeRestricted:
		// handled below
	default:
		return nil, fmt.Errorf("safety: invalid policy mode %q (must be unrestricted, readonly, or restricted)", mode)
	}

	p := &Policy{mode: m}
	if m == ModeReadonly {
		p.allow = append(p.allow, compiledReadonlyAllow...)
		p.deny = append(p.deny, compiledReadonlyDeny...)
	}
	for i, pat := range allowPatterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("safety: allow_patterns[%d] %q: %w", i, pat, err)
		}
		p.allow = append(p.allow, re)
	}
	for i, pat := range denyPatterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("safety: deny_patterns[%d] %q: %w", i, pat, err)
		}
		p.deny = append(p.deny, re)
	}
	return p, nil
}

// EvaluateCommand judges a raw AI-supplied command (the argument to
// ssh_exec / ssh_group_exec / session_send, before NewRemoteCommand wraps
// it with a `cd '<dir>' &&` prefix) against the policy.
//
// A nil *Policy always permits (matches current, pre-policy behaviour).
// Otherwise the command is split into non-empty trimmed lines and each line
// is evaluated independently; any denied line denies the whole command. The
// returned error names the offending line and the specific reason (deny
// match / no allow match / metacharacter), suitable for a POLICY_DENIED
// audit entry.
func (p *Policy) EvaluateCommand(command string) error {
	if p == nil {
		return nil
	}
	sawLine := false
	for i, raw := range strings.Split(command, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		sawLine = true
		if err := p.evaluateLine(line); err != nil {
			return fmt.Errorf("policy: line %d: %w", i+1, err)
		}
	}
	if !sawLine {
		return fmt.Errorf("policy: command denied: empty command")
	}
	return nil
}

func (p *Policy) evaluateLine(line string) error {
	if p.mode == ModeReadonly && metaCharPattern.MatchString(line) {
		return fmt.Errorf("command denied: contains disallowed shell metacharacter (mode=readonly)")
	}
	for _, re := range p.deny {
		if re.MatchString(line) {
			return fmt.Errorf("command denied: matches deny pattern %q", re.String())
		}
	}
	for _, re := range p.allow {
		if re.MatchString(line) {
			return nil
		}
	}
	return fmt.Errorf("command denied: no allow pattern matched (mode=%s)", p.mode)
}

// DenyNonCommandWrites reports whether the policy forbids write-channel
// tools that have no command semantics to evaluate: sftp_op, sftp_upload,
// tunnel (docs/design/command-policy.md §3.3, D2). Any non-nil Policy
// (readonly or restricted) denies these outright — a nil Policy (no mode
// configured) does not.
func (p *Policy) DenyNonCommandWrites() bool {
	return p != nil
}
