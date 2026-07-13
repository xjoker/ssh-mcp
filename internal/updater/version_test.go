package updater

import "testing"

// Version comparison must handle the new YYYYMMDD.V scheme, the legacy X.Y.Z
// scheme, and — crucially — order a legacy→new upgrade correctly during the
// transition (a date-stamped version's leading component dominates any legacy
// 0.0.x). A "-dev" (or any prerelease) build ranks below its plain release.
func TestIsNewer(t *testing.T) {
	cases := []struct {
		current, latest string
		want            bool
		why             string
	}{
		// --- new YYYYMMDD.V scheme ---
		{"20260713.1", "20260713.2", true, "same day, higher build"},
		{"20260713.2", "20260713.1", false, "same day, lower build is not newer"},
		{"20260713.9", "20260714.1", true, "next day beats higher build of prior day"},
		{"20260713.1", "20260713.1", false, "equal is not newer"},
		{"20260713.1", "20260713.10", true, "build compared numerically, not lexically (10>1)"},

		// --- legacy -> new transition (the update path real users hit) ---
		{"0.0.7", "20260713.1", true, "date scheme's leading component dominates legacy 0.0.x"},
		{"20260713.1", "0.0.7", false, "must never 'downgrade' from date scheme to legacy"},
		{"0.0.7-dev.20260506.1", "20260713.1", true, "legacy dev build -> new release is an upgrade"},

		// --- dev / prerelease ranks below its release ---
		{"20260713.1-dev", "20260713.1", true, "release is newer than its own -dev build"},
		{"20260713.1", "20260713.1-dev", false, "a -dev of the same version is not newer"},

		// --- v-prefix tolerance ---
		{"v20260713.1", "v20260713.2", true, "leading v is stripped"},

		// --- variable component count (missing = 0) ---
		{"20260713", "20260713.1", true, "missing trailing component treated as 0 (.1 > 0)"},
		{"20260713.1", "20260713", false, "extra .1 over bare date is newer, so reverse is not"},

		// --- malformed -> fail-closed (never report an upgrade we can't parse) ---
		{"garbage", "20260713.1", false, "unparseable current -> no update"},
		{"20260713.1", "garbage", false, "unparseable latest -> no update"},
	}
	for _, c := range cases {
		if got := IsNewer(c.current, c.latest); got != c.want {
			t.Errorf("IsNewer(%q, %q) = %v, want %v — %s", c.current, c.latest, got, c.want, c.why)
		}
	}
}
