// Package updater handles version checking and binary self-update for
// ssh-mcp. It fetches release metadata from GitHub and can atomically
// replace the running binary with a newer version.
package updater

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// httpClient is used for all outbound requests. The 5-minute Timeout is a
// transport-level backstop; callers also set context deadlines (1.5 s for
// startup checks, 60 s for user-triggered updates).
var httpClient = &http.Client{Timeout: 5 * time.Minute}

const (
	releaseLatestURL = "https://api.github.com/repos/xjoker/ssh-mcp/releases/latest"
	// releasesListURL returns all releases including pre-releases (newest first).
	releasesListURL = "https://api.github.com/repos/xjoker/ssh-mcp/releases?per_page=5"
)

// Release holds metadata for a published GitHub release.
type Release struct {
	Version  string // numeric only, e.g. "0.0.2"
	TagName  string // e.g. "v0.0.2"
	AssetURL string // direct download URL for current OS/arch
	SHA256   string // expected hex digest (empty if no checksum file)
}

// CheckLatest fetches the latest release from GitHub.
// When includePrerelease is true the full releases list is queried so dev
// builds can receive pre-release updates; otherwise only stable releases are
// considered.
// Returns an error if the API is unreachable, the response is malformed, or
// no binary asset matches the current OS/arch.
func CheckLatest(ctx context.Context, includePrerelease bool) (*Release, error) {
	apiURL := releaseLatestURL
	if includePrerelease {
		apiURL = releasesListURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("updater: build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "ssh-mcp-updater/1")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("updater: fetch latest: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("updater: GitHub API %d", resp.StatusCode)
	}

	type ghAsset struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	}
	type ghRelease struct {
		TagName string    `json:"tag_name"`
		Assets  []ghAsset `json:"assets"`
	}

	var gh ghRelease
	if includePrerelease {
		// Response is an array; take the first (newest) entry.
		var list []ghRelease
		if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
			return nil, fmt.Errorf("updater: decode response: %w", err)
		}
		if len(list) == 0 {
			return nil, fmt.Errorf("updater: no releases found")
		}
		gh = list[0]
	} else {
		if err := json.NewDecoder(resp.Body).Decode(&gh); err != nil {
			return nil, fmt.Errorf("updater: decode response: %w", err)
		}
	}

	binName := assetName(runtime.GOOS, runtime.GOARCH)
	var assetURL, checksumURL string
	for _, a := range gh.Assets {
		switch a.Name {
		case binName:
			assetURL = a.BrowserDownloadURL
		case "checksums.sha256":
			checksumURL = a.BrowserDownloadURL
		}
	}
	if assetURL == "" {
		return nil, fmt.Errorf("updater: no asset for %s/%s (want %q)", runtime.GOOS, runtime.GOARCH, binName)
	}

	rel := &Release{
		Version:  strings.TrimPrefix(gh.TagName, "v"),
		TagName:  gh.TagName,
		AssetURL: assetURL,
	}

	if checksumURL != "" {
		sum, err := fetchSHA256(ctx, checksumURL, binName)
		if err != nil {
			return nil, fmt.Errorf("updater: fetch checksum: %w", err)
		}
		rel.SHA256 = sum
	}
	return rel, nil
}

// IsNewer reports whether latest is strictly newer than current. Both are
// parsed by parseVer (YYYYMMDD.V or legacy X.Y.Z); an unparseable operand
// yields false (fail-closed: never claim an upgrade we cannot verify).
func IsNewer(current, latest string) bool {
	cv := parseVer(current)
	lv := parseVer(latest)
	if cv == nil || lv == nil {
		return false
	}
	return cmpVer(lv, cv) > 0
}

// Download fetches the release binary, verifies its SHA-256, and atomically
// replaces destPath. It enforces HTTPS-only downloads and uses a
// cryptographically random temp file name to prevent TOCTOU attacks.
func Download(ctx context.Context, rel *Release, destPath string) error {
	if !strings.HasPrefix(rel.AssetURL, "https://") {
		return fmt.Errorf("updater: asset URL must use https (got %q)", rel.AssetURL)
	}

	dir := filepath.Dir(destPath)
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return fmt.Errorf("updater: generate temp name: %w", err)
	}
	tmpPath := filepath.Join(dir, fmt.Sprintf(".ssh-mcp-update-%s-%x", rel.Version, rnd))

	// Create the temp file non-executable (0600). The execute bit is only
	// granted after the SHA-256 check passes, so a partially-downloaded or
	// tampered binary is never executable on disk (TOCTOU hardening).
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("updater: create temp file: %w", err)
	}
	// Ensure cleanup on any failure path before rename.
	cleanupOnce := true
	fileClosed := false
	defer func() {
		if !fileClosed {
			f.Close()
		}
		if cleanupOnce {
			os.Remove(tmpPath)
		}
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rel.AssetURL, nil)
	if err != nil {
		return fmt.Errorf("updater: build download request: %w", err)
	}
	req.Header.Set("User-Agent", "ssh-mcp-updater/1")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("updater: download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("updater: download HTTP %d", resp.StatusCode)
	}

	h := sha256.New()
	if _, err := io.Copy(f, io.TeeReader(resp.Body, h)); err != nil {
		return fmt.Errorf("updater: write binary: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("updater: close temp: %w", err)
	}
	fileClosed = true

	// SHA-256 fail-closed: reject mismatched or missing checksum.
	if rel.SHA256 == "" {
		return fmt.Errorf("updater: no checksum available; refusing to install unverified binary")
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != rel.SHA256 {
		return fmt.Errorf("updater: SHA-256 mismatch (want %s, got %s)", rel.SHA256, got)
	}

	// Checksum verified — now grant execute (user-only; installs are per-user,
	// group/other have no legitimate need).
	if err := os.Chmod(tmpPath, 0o700); err != nil { // #nosec G302 -- 0700 is the tightened permission, not the wide one gosec assumes
		return fmt.Errorf("updater: chmod verified binary: %w", err)
	}

	// Atomic rename — after this point the temp file is "owned" by the rename.
	cleanupOnce = false
	if err := os.Rename(tmpPath, destPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("updater: replace binary: %w", err)
	}
	return nil
}

// assetName returns the GitHub release asset file name for the given platform.
func assetName(goos, goarch string) string {
	name := "ssh-mcp_" + goos + "_" + goarch
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

// fetchSHA256 downloads a checksums.sha256 file and returns the digest for
// the named binary. Format: "<hex>  <filename>" (sha256sum output).
func fetchSHA256(ctx context.Context, url, binName string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "ssh-mcp-updater/1")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.Fields(line)
		// sha256sum binary mode prefixes the filename with '*'.
		if len(parts) == 2 && strings.TrimPrefix(parts[1], "*") == binName {
			return parts[0], nil
		}
	}
	return "", fmt.Errorf("no checksum entry for %q", binName)
}

// --------------------------------------------------------------------------
// Version comparison
// --------------------------------------------------------------------------

// version is a parsed version compared as a sequence of dot-separated integer
// components plus a "prerelease" flag. This single model spans both the current
// YYYYMMDD.V scheme (e.g. "20260713.1") and the legacy X.Y.Z scheme (e.g.
// "0.0.7"), and orders a legacy→new upgrade correctly: a date-stamped version's
// leading component (20260713) dominates any legacy 0.0.x. A prerelease build
// ("-dev", or any "-suffix") ranks below the plain release of the same number.
type version struct {
	parts      []int
	prerelease bool
}

func parseVer(s string) *version {
	s = strings.TrimPrefix(s, "v")
	prerelease := false
	// Any "-suffix" (e.g. "-dev", "-dev.20260506.1", "-rc1") marks a
	// prerelease and is dropped before numeric parsing.
	if idx := strings.IndexByte(s, '-'); idx >= 0 {
		prerelease = true
		s = s[:idx]
	}
	segs := strings.Split(s, ".")
	parts := make([]int, 0, len(segs))
	for _, seg := range segs {
		n, err := strconv.Atoi(seg)
		if err != nil {
			return nil // unparseable → caller treats as "cannot compare"
		}
		parts = append(parts, n)
	}
	if len(parts) == 0 {
		return nil
	}
	return &version{parts: parts, prerelease: prerelease}
}

// cmpVer returns >0 if a > b, 0 if equal, <0 if a < b. Components are compared
// pairwise; a missing component (shorter version) is treated as 0 so that
// "20260713.1" > "20260713". Among numerically-equal versions, a plain release
// outranks a prerelease.
func cmpVer(a, b *version) int {
	n := len(a.parts)
	if len(b.parts) > n {
		n = len(b.parts)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(a.parts) {
			av = a.parts[i]
		}
		if i < len(b.parts) {
			bv = b.parts[i]
		}
		if av != bv {
			return av - bv
		}
	}
	switch {
	case a.prerelease && !b.prerelease:
		return -1
	case !a.prerelease && b.prerelease:
		return 1
	default:
		return 0
	}
}
