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

// IsNewer reports whether latest is strictly newer than current.
// Dev versions (with "-dev" suffix) are treated as pre-releases and are
// considered older than the same numeric release version.
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

	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o755)
	if err != nil {
		return fmt.Errorf("updater: create temp file: %w", err)
	}
	// Ensure cleanup on any failure path before rename.
	cleanupOnce := true
	defer func() {
		f.Close()
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

	// SHA-256 fail-closed: reject mismatched or missing checksum.
	if rel.SHA256 == "" {
		return fmt.Errorf("updater: no checksum available; refusing to install unverified binary")
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != rel.SHA256 {
		return fmt.Errorf("updater: SHA-256 mismatch (want %s, got %s)", rel.SHA256, got)
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
		if len(parts) == 2 && parts[1] == binName {
			return parts[0], nil
		}
	}
	return "", fmt.Errorf("no checksum entry for %q", binName)
}

// --------------------------------------------------------------------------
// Version comparison
// --------------------------------------------------------------------------

type semver struct {
	major, minor, patch int
	dev                 bool
	preRelease          string // suffix after "-dev." e.g. "20260506.1"
}

func parseVer(s string) *semver {
	s = strings.TrimPrefix(s, "v")
	var preRelease string
	dev := false
	if idx := strings.Index(s, "-dev"); idx >= 0 {
		dev = true
		rest := s[idx+4:] // everything after "-dev"
		if strings.HasPrefix(rest, ".") {
			preRelease = rest[1:] // "20260506.1"
		}
		s = s[:idx] // keep only "major.minor.patch"
	}
	parts := strings.SplitN(s, ".", 3)
	if len(parts) != 3 {
		return nil
	}
	major, e1 := strconv.Atoi(parts[0])
	minor, e2 := strconv.Atoi(parts[1])
	patch, e3 := strconv.Atoi(parts[2])
	if e1 != nil || e2 != nil || e3 != nil {
		return nil
	}
	return &semver{major, minor, patch, dev, preRelease}
}

// cmpVer returns >0 if a > b, 0 if equal, <0 if a < b.
// Among equal numeric versions: release > dev. Among two dev builds with the
// same numeric base, the pre-release suffix is compared lexicographically
// (date-stamped suffixes like "20260506.1" < "20260506.2" sort correctly).
func cmpVer(a, b *semver) int {
	if d := a.major - b.major; d != 0 {
		return d
	}
	if d := a.minor - b.minor; d != 0 {
		return d
	}
	if d := a.patch - b.patch; d != 0 {
		return d
	}
	switch {
	case a.dev && !b.dev:
		return -1
	case !a.dev && b.dev:
		return 1
	case a.dev && b.dev:
		return strings.Compare(a.preRelease, b.preRelease)
	default:
		return 0
	}
}
