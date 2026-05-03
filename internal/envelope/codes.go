package envelope

// Error codes — SDD §10.1. The complete authoritative set.
// All packages MUST reference these constants rather than literal strings.
const (
	CodeInvalidArgument         = "INVALID_ARGUMENT"
	CodeAuthFailed              = "AUTH_FAILED"
	CodePermissionDenied        = "PERMISSION_DENIED"
	CodeNotFound                = "NOT_FOUND"
	CodeTimeout                 = "TIMEOUT"
	CodeConflict                = "CONFLICT"
	CodeRateLimited             = "RATE_LIMITED"
	CodeInternalError           = "INTERNAL_ERROR"
	CodeConnFailed              = "CONN_FAILED"
	CodeSessionDead             = "SESSION_DEAD"
	CodeHostKeyUnknown          = "HOST_KEY_UNKNOWN"
	CodeHostKeyMismatch         = "HOST_KEY_MISMATCH"
	CodeSftpError               = "SFTP_ERROR"
	CodeInlineCredsDisabled     = "INLINE_CREDS_DISABLED"
	CodePlaintextPasswordDisabled = "PLAINTEXT_PASSWORD_DISABLED"
	CodeUserDeclined            = "USER_DECLINED"
	CodeAuditFailed             = "AUDIT_FAILED"
	CodePartialFailure          = "PARTIAL_FAILURE"
	CodeSessionLimit            = "SESSION_LIMIT"
)
