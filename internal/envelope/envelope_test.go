package envelope

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestOKSerializationNoError verifies OK(data) serializes to {"ok":true,"data":...}
// with no "error" field present.
func TestOKSerializationNoError(t *testing.T) {
	r := OK(map[string]string{"key": "value"})
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	s := string(b)

	if !strings.Contains(s, `"ok":true`) {
		t.Errorf("expected ok:true in %s", s)
	}
	if !strings.Contains(s, `"data"`) {
		t.Errorf("expected data field in %s", s)
	}
	if strings.Contains(s, `"error"`) {
		t.Errorf("unexpected error field in %s", s)
	}
}

// TestErrSerializationNoHint verifies Err(code,msg,false) produces
// {"ok":false,"error":{"code":"CODE","message":"msg","retriable":false}}
// with no "hint" field and no "data" field.
func TestErrSerializationNoHint(t *testing.T) {
	r := Err("CODE", "msg", false)
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	s := string(b)

	if !strings.Contains(s, `"ok":false`) {
		t.Errorf("expected ok:false in %s", s)
	}
	if !strings.Contains(s, `"error"`) {
		t.Errorf("expected error field in %s", s)
	}
	if !strings.Contains(s, `"code":"CODE"`) {
		t.Errorf("expected code:CODE in %s", s)
	}
	if !strings.Contains(s, `"message":"msg"`) {
		t.Errorf("expected message:msg in %s", s)
	}
	if !strings.Contains(s, `"retriable":false`) {
		t.Errorf("expected retriable:false in %s", s)
	}
	if strings.Contains(s, `"hint"`) {
		t.Errorf("unexpected hint field in %s", s)
	}
	if strings.Contains(s, `"data"`) {
		t.Errorf("unexpected data field in %s", s)
	}
}

// TestErrWithHintContainsHint verifies ErrWithHint includes the hint field.
func TestErrWithHintContainsHint(t *testing.T) {
	r := ErrWithHint("CODE", "msg", "do something", true)
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	s := string(b)

	if !strings.Contains(s, `"hint":"do something"`) {
		t.Errorf("expected hint field in %s", s)
	}
	if !strings.Contains(s, `"retriable":true`) {
		t.Errorf("expected retriable:true in %s", s)
	}
}

// TestRetriableFalseNotOmitted verifies that retriable:false is serialized
// (i.e. not dropped by omitempty), which is required for bool business fields.
func TestRetriableFalseNotOmitted(t *testing.T) {
	r := Err("X", "y", false)
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	s := string(b)

	if !strings.Contains(s, `"retriable":false`) {
		t.Errorf("retriable:false was omitted — missing omitempty guard is broken. got: %s", s)
	}
}

// TestRetriableTruePresent verifies retriable:true is also serialized.
func TestRetriableTruePresent(t *testing.T) {
	r := Err("X", "y", true)
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	s := string(b)

	if !strings.Contains(s, `"retriable":true`) {
		t.Errorf("retriable:true missing. got: %s", s)
	}
}

// TestCodeConstants verifies every error code constant matches the
// authoritative string value from SDD §10.1.
func TestCodeConstants(t *testing.T) {
	expected := map[string]string{
		"CodeInvalidArgument":           "INVALID_ARGUMENT",
		"CodeAuthFailed":                "AUTH_FAILED",
		"CodePermissionDenied":          "PERMISSION_DENIED",
		"CodeNotFound":                  "NOT_FOUND",
		"CodeTimeout":                   "TIMEOUT",
		"CodeConflict":                  "CONFLICT",
		"CodeRateLimited":               "RATE_LIMITED",
		"CodeInternalError":             "INTERNAL_ERROR",
		"CodeConnFailed":                "CONN_FAILED",
		"CodeSessionDead":               "SESSION_DEAD",
		"CodeHostKeyUnknown":            "HOST_KEY_UNKNOWN",
		"CodeHostKeyMismatch":           "HOST_KEY_MISMATCH",
		"CodeSftpError":                 "SFTP_ERROR",
		"CodeInlineCredsDisabled":       "INLINE_CREDS_DISABLED",
		"CodePlaintextPasswordDisabled": "PLAINTEXT_PASSWORD_DISABLED",
		"CodeUserDeclined":              "USER_DECLINED",
		"CodeAuditFailed":               "AUDIT_FAILED",
		"CodePartialFailure":            "PARTIAL_FAILURE",
		"CodeSessionLimit":              "SESSION_LIMIT",
		"CodeUploadDisabled":            "UPLOAD_DISABLED",
	}

	actual := map[string]string{
		"CodeInvalidArgument":           CodeInvalidArgument,
		"CodeAuthFailed":                CodeAuthFailed,
		"CodePermissionDenied":          CodePermissionDenied,
		"CodeNotFound":                  CodeNotFound,
		"CodeTimeout":                   CodeTimeout,
		"CodeConflict":                  CodeConflict,
		"CodeRateLimited":               CodeRateLimited,
		"CodeInternalError":             CodeInternalError,
		"CodeConnFailed":                CodeConnFailed,
		"CodeSessionDead":               CodeSessionDead,
		"CodeHostKeyUnknown":            CodeHostKeyUnknown,
		"CodeHostKeyMismatch":           CodeHostKeyMismatch,
		"CodeSftpError":                 CodeSftpError,
		"CodeInlineCredsDisabled":       CodeInlineCredsDisabled,
		"CodePlaintextPasswordDisabled": CodePlaintextPasswordDisabled,
		"CodeUserDeclined":              CodeUserDeclined,
		"CodeAuditFailed":               CodeAuditFailed,
		"CodePartialFailure":            CodePartialFailure,
		"CodeSessionLimit":              CodeSessionLimit,
		"CodeUploadDisabled":            CodeUploadDisabled,
	}

	if len(actual) != len(expected) {
		t.Errorf("code count mismatch: got %d, want %d", len(actual), len(expected))
	}

	for name, want := range expected {
		got, ok := actual[name]
		if !ok {
			t.Errorf("constant %s not found", name)
			continue
		}
		if got != want {
			t.Errorf("constant %s: got %q, want %q", name, got, want)
		}
	}
}

// TestOKDataNilOmitted verifies that OK(nil) does not emit a "data" key.
func TestOKDataNilOmitted(t *testing.T) {
	r := OK(nil)
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	s := string(b)

	if strings.Contains(s, `"data"`) {
		t.Errorf("nil data should be omitted via omitempty, got: %s", s)
	}
}

// TestWithAuditNotSerialised verifies that the Audit field is NOT included in
// the JSON output (json:"-") so audit metadata is never sent to the LLM.
func TestWithAuditNotSerialised(t *testing.T) {
	r := OK("payload").WithAudit(AuditMeta{
		ExitCode: 42,
		BytesIn:  100,
		BytesOut: 200,
		AuthMode: "key",
	})

	// Audit field must be populated.
	if r.Audit == nil {
		t.Fatal("Audit should not be nil after WithAudit")
	}
	if r.Audit.ExitCode != 42 {
		t.Errorf("Audit.ExitCode: got %d, want 42", r.Audit.ExitCode)
	}

	// JSON serialisation must not include audit metadata.
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	s := string(b)
	if strings.Contains(s, "audit") {
		t.Errorf("JSON must not contain 'audit', got: %s", s)
	}
	if strings.Contains(s, "exit_code") {
		t.Errorf("JSON must not contain 'exit_code', got: %s", s)
	}
	if strings.Contains(s, "auth_mode") {
		t.Errorf("JSON must not contain 'auth_mode', got: %s", s)
	}
	// The actual data payload should still be present.
	if !strings.Contains(s, `"data":"payload"`) {
		t.Errorf("data payload should still be serialised, got: %s", s)
	}
}

// TestWithAuditChaining verifies that calling WithAudit twice replaces the
// previous AuditMeta (last-write wins) and does not mutate the original.
func TestWithAuditChaining(t *testing.T) {
	original := OK("x")
	first := original.WithAudit(AuditMeta{ExitCode: 1})
	second := first.WithAudit(AuditMeta{ExitCode: 2})

	if original.Audit != nil {
		t.Error("WithAudit should not mutate the original response")
	}
	if first.Audit == nil || first.Audit.ExitCode != 1 {
		t.Errorf("first.Audit.ExitCode: got %v, want 1", first.Audit)
	}
	if second.Audit == nil || second.Audit.ExitCode != 2 {
		t.Errorf("second.Audit.ExitCode: got %v, want 2", second.Audit)
	}
}

// TestRoundTripErr verifies that an Err response can be unmarshalled back
// to the same structure values.
func TestRoundTripErr(t *testing.T) {
	original := Err(CodeTimeout, "operation timed out", true)
	b, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Response
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.OK {
		t.Error("decoded.OK should be false")
	}
	if decoded.Error == nil {
		t.Fatal("decoded.Error should not be nil")
	}
	if decoded.Error.Code != CodeTimeout {
		t.Errorf("code: got %q, want %q", decoded.Error.Code, CodeTimeout)
	}
	if decoded.Error.Message != "operation timed out" {
		t.Errorf("message: got %q", decoded.Error.Message)
	}
	if !decoded.Error.Retriable {
		t.Error("retriable should be true")
	}
}
