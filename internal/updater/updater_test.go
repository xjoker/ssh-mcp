package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// serveBinary starts a TLS test server that serves body at /bin and swaps the
// package httpClient so Download's https-only check and TLS both pass.
func serveBinary(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	orig := httpClient
	httpClient = srv.Client()
	t.Cleanup(func() { httpClient = orig })
	return srv
}

func TestDownload_verified_binary_is_executable(t *testing.T) {
	body := []byte("fake-binary-contents")
	srv := serveBinary(t, body)
	sum := sha256.Sum256(body)

	dest := filepath.Join(t.TempDir(), "ssh-mcp")
	rel := &Release{Version: "9.9.9", AssetURL: srv.URL + "/bin", SHA256: hex.EncodeToString(sum[:])}

	if err := downloadWithHooks(context.Background(), rel, dest, installHooks{
		prepare: func(context.Context, string) error { return nil },
		verify:  func(context.Context, string, string) error { return nil },
		replace: os.Rename,
	}); err != nil {
		t.Fatalf("downloadWithHooks: %v", err)
	}
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("stat dest: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Errorf("installed binary mode = %o, want 0700", info.Mode().Perm())
	}
}

func TestDownload_version_mismatch_preserves_existing_binary(t *testing.T) {
	body := []byte("checksum-valid-but-wrong-version")
	srv := serveBinary(t, body)
	sum := sha256.Sum256(body)

	dir := t.TempDir()
	dest := filepath.Join(dir, "ssh-mcp")
	if err := os.WriteFile(dest, []byte("old-binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	rel := &Release{Version: "20260724.1", AssetURL: srv.URL + "/bin", SHA256: hex.EncodeToString(sum[:])}

	err := downloadWithHooks(context.Background(), rel, dest, installHooks{
		prepare: func(context.Context, string) error { return nil },
		verify: func(context.Context, string, string) error {
			return errors.New("embedded version mismatch")
		},
		replace: os.Rename,
	})
	if err == nil || !strings.Contains(err.Error(), "embedded version mismatch") {
		t.Fatalf("want embedded version mismatch, got %v", err)
	}
	got, readErr := os.ReadFile(dest)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "old-binary" {
		t.Fatalf("existing binary changed after version mismatch: %q", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "ssh-mcp" {
		t.Fatalf("unexpected files after rejected update: %v", entries)
	}
}

func TestVerifyVersionOutput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		output  string
		want    string
		wantErr bool
	}{
		{name: "matching version with toolchain line", output: "ssh-mcp 20260724.1-dev (commit abc1234)\nGo go1.26.5\n", want: "20260724.1-dev"},
		{name: "wrong version", output: "ssh-mcp 20260724.1 (commit abc1234)\n", want: "20260724.2", wantErr: true},
		{name: "unknown commit", output: "ssh-mcp 20260724.1 (commit unknown)\n", want: "20260724.1", wantErr: true},
		{name: "malformed", output: "20260724.1\n", want: "20260724.1", wantErr: true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := verifyVersionOutput(tt.output, tt.want)
			if (err != nil) != tt.wantErr {
				t.Fatalf("verifyVersionOutput(%q, %q) error = %v, wantErr %v", tt.output, tt.want, err, tt.wantErr)
			}
		})
	}
}

func TestSelectReleaseChoosesHighestValidVersion(t *testing.T) {
	t.Parallel()

	binName := assetName(runtime.GOOS, runtime.GOARCH)
	assets := func() []ghAsset {
		return []ghAsset{
			{Name: binName, BrowserDownloadURL: "https://example.test/bin"},
			{Name: "checksums.sha256", BrowserDownloadURL: "https://example.test/checksums"},
		}
	}
	list := []ghRelease{
		{TagName: "v20260724.1-dev", Assets: assets()},
		{TagName: "not-a-version", Assets: assets()},
		{TagName: "v20260723.9", Assets: assets()},
		{TagName: "v20260724.2-dev", Assets: assets()},
	}

	got, err := selectRelease(list, true, binName)
	if err != nil {
		t.Fatal(err)
	}
	if got.TagName != "v20260724.2-dev" {
		t.Fatalf("selected %q, want v20260724.2-dev", got.TagName)
	}
}

func TestSelectReleaseRejectsMissingChecksum(t *testing.T) {
	t.Parallel()

	binName := assetName(runtime.GOOS, runtime.GOARCH)
	_, err := selectRelease([]ghRelease{{
		TagName: "v20260724.1",
		Assets:  []ghAsset{{Name: binName, BrowserDownloadURL: "https://example.test/bin"}},
	}}, false, binName)
	if err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("want missing checksum error, got %v", err)
	}
}

func TestReleaseVersionRejectsUnknownLegacyPrereleaseSuffix(t *testing.T) {
	t.Parallel()

	if _, ok := releaseVersion("v0.0.7-evil", true); ok {
		t.Fatal("releaseVersion accepted an unsupported legacy prerelease suffix")
	}
}

func TestDownloadTempNameUsesExecutableSuffixOnWindows(t *testing.T) {
	t.Parallel()

	if got := downloadTempName("windows", "20260724.1", [8]byte{}); !strings.HasSuffix(got, ".exe") {
		t.Fatalf("Windows update temp name %q has no .exe suffix", got)
	}
}

func TestDownload_checksum_mismatch_leaves_no_executable_temp(t *testing.T) {
	srv := serveBinary(t, []byte("tampered-contents"))

	dir := t.TempDir()
	dest := filepath.Join(dir, "ssh-mcp")
	rel := &Release{Version: "9.9.9", AssetURL: srv.URL + "/bin", SHA256: strings.Repeat("0", 64)}

	err := Download(context.Background(), rel, dest)
	if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("want SHA-256 mismatch error, got %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("temp/dest files left behind after failed verify: %v", entries)
	}
}

func TestDownload_rejects_http_url(t *testing.T) {
	rel := &Release{Version: "9.9.9", AssetURL: "http://example.com/bin", SHA256: strings.Repeat("0", 64)}
	if err := Download(context.Background(), rel, filepath.Join(t.TempDir(), "x")); err == nil {
		t.Fatal("want error for non-https URL, got nil")
	}
}
