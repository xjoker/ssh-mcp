package config

import "regexp"

// HasServerBlock reports whether content contains a real (non-commented)
// [servers.<name>] TOML table header. Used by the append-only config writers
// (CLI add-server, ssh_persistent_setup) for duplicate detection.
//
// A plain substring search would false-positive on commented-out headers —
// the default template ships "# [servers.example]" — and on names embedded
// in longer names. The pattern anchors to line start (optional indentation
// only) and to the closing bracket, allowing a trailing TOML comment.
func HasServerBlock(content []byte, name string) bool {
	re := regexp.MustCompile(`(?m)^[ \t]*\[servers\.` + regexp.QuoteMeta(name) + `\][ \t]*(#.*)?$`)
	return re.Match(content)
}
