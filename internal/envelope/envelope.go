// Package envelope defines the unified Response shape returned by every tool.
// SDD §5.1.
package envelope

// Response is encoded as JSON inside a single MCP TextContent.
type Response struct {
	OK    bool   `json:"ok"`
	Data  any    `json:"data,omitempty"`
	Error *Error `json:"error,omitempty"`
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
