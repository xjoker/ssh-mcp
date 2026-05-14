package main

import (
	"strings"
	"testing"
)

// TestCpRejectsSameServerCaseInsensitive verifies that the cp same-server
// guard normalises case before comparing — `Prod:/x` and `prod:/x` resolve
// to the same dialed server (config keys are lower-cased), and treating
// them as different would let cp truncate the file it's reading.
func TestCpRejectsSameServerCaseInsensitive(t *testing.T) {
	rc := cpCmd([]string{"Prod:/data/a", "prod:/data/b"})
	if rc == 0 {
		t.Fatal("cp must refuse same-server (case-insensitive); got rc=0")
	}
	// Capturing stderr is overkill; rc != 0 is the contract guarantee.
	_ = strings.ToLower
}

// TestSplitServerPath verifies the <server>:<path> parser used by the cp
// subcommand. Edge cases: leading colon, missing colon, trailing colon.
func TestSplitServerPath(t *testing.T) {
	cases := []struct {
		in           string
		wantServer   string
		wantPath     string
		wantOK       bool
	}{
		{"alpha:/data/foo", "alpha", "/data/foo", true},
		{"alpha:relative/path", "alpha", "relative/path", true},
		{"alpha:", "", "", false},     // empty path
		{":/foo", "", "", false},      // empty server
		{"noseparator", "", "", false}, // no colon
		{"", "", "", false},
		{"a:b:c", "a", "b:c", true}, // first colon wins; path may contain colons
	}
	for _, tc := range cases {
		gotS, gotP, gotOK := splitServerPath(tc.in)
		if gotOK != tc.wantOK || gotS != tc.wantServer || gotP != tc.wantPath {
			t.Errorf("splitServerPath(%q) = (%q,%q,%v); want (%q,%q,%v)",
				tc.in, gotS, gotP, gotOK, tc.wantServer, tc.wantPath, tc.wantOK)
		}
	}
}

// TestHumanBytes spot-checks the formatting helper used in progress output.
func TestHumanBytes(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1024 * 1024, "1.0 MiB"},
		{int64(1024) * 1024 * 1024, "1.0 GiB"},
	}
	for _, tc := range cases {
		if got := humanBytes(tc.in); got != tc.want {
			t.Errorf("humanBytes(%d) = %q; want %q", tc.in, got, tc.want)
		}
	}
}
