package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

	if err := Download(context.Background(), rel, dest); err != nil {
		t.Fatalf("Download: %v", err)
	}
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("stat dest: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Errorf("installed binary mode = %o, want 0700", info.Mode().Perm())
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
