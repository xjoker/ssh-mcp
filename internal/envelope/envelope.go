// Package envelope defines the unified Response shape returned by every tool.
// SDD §5.1.
package envelope

// AuditMeta carries optional supplementary fields that the dispatcher copies
// into the audit entry. Tool handlers that have meaningful real exit codes,
// byte counts, or auth labels (e.g. ssh_exec, sftp_op) populate this struct
// via Response.WithAudit. The Audit field is never serialised to the LLM.
// SDD §9.2.
type AuditMeta struct {
	// AuthMode is a human-readable label for the authentication method used
	// (e.g. "key", "password", "agent"). Empty string means "not available".
	AuthMode string

	// BytesIn is the number of bytes sent to the remote (e.g. SFTP write payload).
	BytesIn int64

	// BytesOut is the number of bytes received from the remote (stdout+stderr or
	// SFTP read payload).
	BytesOut int64

	// ExitCode is the real remote command exit code. 0 is also the "not
	// applicable" sentinel for non-exec tools; callers that legitimately
	// return exit 0 may still set this (it will correctly overwrite the
	// default 0 in the audit entry).
	ExitCode int

	// Stdout and Stderr carry the remote command's output for forensic
	// replay. They are populated by handlers that genuinely produce shell
	// output (ssh_exec, ssh_group_exec, session_send). The dispatcher
	// applies redaction and the configured per-entry size cap before
	// writing them to the audit log; tools should pass the raw text and
	// not pre-truncate.
	Stdout string
	Stderr string

	// ContentSHA256 is the hex-encoded sha256 of the file content transferred
	// by the operation (e.g. sftp_upload's local source). Empty string means
	// "not computed / not applicable". SDD design §3.4.
	ContentSHA256 string
}

// Response is encoded as JSON inside a single MCP TextContent.
type Response struct {
	OK    bool   `json:"ok"`
	Data  any    `json:"data,omitempty"`
	Error *Error `json:"error,omitempty"`

	// Audit is populated by tool handlers and consumed by the dispatcher to
	// enrich the audit entry. It is excluded from JSON serialisation so the
	// LLM never sees internal metadata.
	Audit *AuditMeta `json:"-"`
}

// WithAudit returns a copy of r with the Audit field set to m. Use this in
// handler return statements:
//
//	return envelope.OK(data).WithAudit(envelope.AuditMeta{ExitCode: 0, BytesOut: n})
func (r Response) WithAudit(m AuditMeta) Response {
	r.Audit = &m
	return r
}

type Error struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retriable bool   `json:"retriable"`
	Hint      string `json:"hint,omitempty"`
}

func OK(data any) Response { return Response{OK: true, Data: data} }

func Err(code, msg string, retriable bool) Response {
	return Response{OK: false, Error: &Error{Code: code, Message: msg, Retriable: retriable}}
}

func ErrWithHint(code, msg, hint string, retriable bool) Response {
	return Response{OK: false, Error: &Error{Code: code, Message: msg, Retriable: retriable, Hint: hint}}
}
