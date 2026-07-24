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
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	versioncontract "github.com/xjoker/ssh-mcp/internal/version"
)

// httpClient is used for all outbound requests. The 5-minute Timeout is a
// transport-level backstop; callers also set context deadlines (1.5 s for
// startup checks, 60 s for user-triggered updates).
var httpClient = &http.Client{Timeout: 5 * time.Minute}

const (
	releaseLatestURL = "https://api.github.com/repos/xjoker/ssh-mcp/releases/latest"
	// releasesListURL returns all releases including pre-releases (newest first).
	releasesListURL = "https://api.github.com/repos/xjoker/ssh-mcp/releases?per_page=100"
)

// Release holds metadata for a published GitHub release.
type Release struct {
	Version  string // e.g. "20260724.1" or "20260724.1-dev"
	TagName  string // e.g. "v20260724.1"
	AssetURL string // direct download URL for current OS/arch
	SHA256   string // expected hex digest (empty if no checksum file)
}

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
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

	var releases []ghRelease
	if includePrerelease {
		if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
			return nil, fmt.Errorf("updater: decode response: %w", err)
		}
	} else {
		var gh ghRelease
		if err := json.NewDecoder(resp.Body).Decode(&gh); err != nil {
			return nil, fmt.Errorf("updater: decode response: %w", err)
		}
		releases = []ghRelease{gh}
	}

	binName := assetName(runtime.GOOS, runtime.GOARCH)
	gh, err := selectRelease(releases, includePrerelease, binName)
	if err != nil {
		return nil, err
	}
	var assetURL, checksumURL string
	for _, a := range gh.Assets {
		switch a.Name {
		case binName:
			assetURL = a.BrowserDownloadURL
		case "checksums.sha256":
			checksumURL = a.BrowserDownloadURL
		}
	}
	rel := &Release{
		Version:  strings.TrimPrefix(gh.TagName, "v"),
		TagName:  gh.TagName,
		AssetURL: assetURL,
	}

	sum, err := fetchSHA256(ctx, checksumURL, binName)
	if err != nil {
		return nil, fmt.Errorf("updater: fetch checksum: %w", err)
	}
	rel.SHA256 = sum
	return rel, nil
}

func selectRelease(releases []ghRelease, includePrerelease bool, binName string) (ghRelease, error) {
	var selected *ghRelease
	for i := range releases {
		candidate := &releases[i]
		version, ok := releaseVersion(candidate.TagName, includePrerelease)
		if !ok {
			continue
		}
		if selected == nil || cmpVer(parseVer(version), parseVer(strings.TrimPrefix(selected.TagName, "v"))) > 0 {
			selected = candidate
		}
	}
	if selected == nil {
		return ghRelease{}, fmt.Errorf("updater: no valid release found")
	}

	hasBinary, hasChecksum := false, false
	for _, asset := range selected.Assets {
		switch asset.Name {
		case binName:
			hasBinary = asset.BrowserDownloadURL != ""
		case "checksums.sha256":
			hasChecksum = asset.BrowserDownloadURL != ""
		}
	}
	if !hasBinary {
		return ghRelease{}, fmt.Errorf("updater: release %s has no asset for %s/%s (want %q)", selected.TagName, runtime.GOOS, runtime.GOARCH, binName)
	}
	if !hasChecksum {
		return ghRelease{}, fmt.Errorf("updater: release %s has no checksum asset", selected.TagName)
	}
	return *selected, nil
}

func releaseVersion(tag string, includePrerelease bool) (string, bool) {
	if !strings.HasPrefix(tag, "v") {
		return "", false
	}
	version := strings.TrimPrefix(tag, "v")
	if err := versioncontract.ValidateBase(version); err == nil {
		return version, true
	}
	if includePrerelease && strings.HasSuffix(version, "-dev") {
		base := strings.TrimSuffix(version, "-dev")
		if err := versioncontract.ValidateBase(base); err == nil {
			return version, true
		}
	}
	// Keep the one-way upgrade path from the legacy 0.0.x line until the first
	// stable date-version release is universally available.
	legacyVersion := version
	if strings.Contains(legacyVersion, "-") {
		if !includePrerelease || strings.Count(legacyVersion, "-") != 1 || !strings.HasSuffix(legacyVersion, "-dev") {
			return "", false
		}
		legacyVersion = strings.TrimSuffix(legacyVersion, "-dev")
	}
	parsed := parseVer(legacyVersion)
	if parsed == nil || len(parsed.parts) != 3 || parsed.parts[0] != 0 || parsed.parts[1] != 0 {
		return "", false
	}
	return version, true
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
	return downloadWithHooks(ctx, rel, destPath, installHooks{
		prepare: prepareDownloadedBinary,
		verify:  verifyDownloadedBinary,
		replace: replaceDownloadedBinary,
	})
}

type installHooks struct {
	prepare func(context.Context, string) error
	verify  func(context.Context, string, string) error
	replace func(string, string) error
}

func downloadWithHooks(ctx context.Context, rel *Release, destPath string, hooks installHooks) error {
	if !strings.HasPrefix(rel.AssetURL, "https://") {
		return fmt.Errorf("updater: asset URL must use https (got %q)", rel.AssetURL)
	}

	dir := filepath.Dir(destPath)
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return fmt.Errorf("updater: generate temp name: %w", err)
	}
	tmpPath := filepath.Join(dir, downloadTempName(runtime.GOOS, rel.Version, rnd))

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
	if err := hooks.prepare(ctx, tmpPath); err != nil {
		return fmt.Errorf("updater: prepare verified binary: %w", err)
	}
	if err := hooks.verify(ctx, tmpPath, rel.Version); err != nil {
		return fmt.Errorf("updater: %w", err)
	}

	// After this point the temp file is owned by the platform replacement path.
	cleanupOnce = false
	if err := hooks.replace(tmpPath, destPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("updater: replace binary: %w", err)
	}
	return nil
}

func downloadTempName(goos, version string, random [8]byte) string {
	name := fmt.Sprintf(".ssh-mcp-update-%s-%x", version, random)
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

func verifyDownloadedBinary(ctx context.Context, path, wantVersion string) error {
	output, err := exec.CommandContext(ctx, path, "version").Output()
	if err != nil {
		return fmt.Errorf("execute downloaded binary: %w", err)
	}
	return verifyVersionOutput(string(output), wantVersion)
}

func verifyVersionOutput(output, wantVersion string) error {
	line := strings.SplitN(strings.TrimSpace(output), "\n", 2)[0]
	prefix := "ssh-mcp " + wantVersion + " (commit "
	if !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, ")") {
		return fmt.Errorf("embedded version mismatch: got %q, want ssh-mcp %s with commit", line, wantVersion)
	}
	commit := strings.TrimSuffix(strings.TrimPrefix(line, prefix), ")")
	if commit == "" || commit == "unknown" {
		return fmt.Errorf("embedded commit is missing in %q", line)
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
