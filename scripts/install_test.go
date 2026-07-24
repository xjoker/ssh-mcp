package scripts_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	if version := os.Getenv("SSH_MCP_INSTALL_TEST_VERSION"); version != "" && len(os.Args) == 2 && os.Args[1] == "version" {
		commit := os.Getenv("SSH_MCP_INSTALL_TEST_COMMIT")
		if commit == "" {
			commit = "test"
		}
		if trace := os.Getenv("SSH_MCP_INSTALL_TEST_TRACE"); trace != "" {
			file, err := os.OpenFile(trace, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
			if err == nil {
				_, _ = file.WriteString("execute version\n")
				_ = file.Close()
			}
		}
		fmt.Printf("ssh-mcp %s (commit %s)\n", version, commit)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestInstallShChecksumMismatchPreservesExistingBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash installer is not used on Windows")
	}
	prefix := t.TempDir()
	dest := filepath.Join(prefix, "ssh-mcp")
	if err := os.WriteFile(dest, []byte("old-binary"), 0o700); err != nil {
		t.Fatal(err)
	}

	cmd := installShCommand(t, prefix, "mismatch", "test", "Linux", "")
	if output, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("install.sh succeeded with a mismatched checksum:\n%s", output)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("existing binary was removed after checksum failure: %v", err)
	}
	if string(got) != "old-binary" {
		t.Fatalf("existing binary changed after checksum failure: %q", got)
	}
	assertNoInstallTemps(t, prefix)
}

func TestInstallShVerifiedDownloadReplacesExistingBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash installer is not used on Windows")
	}
	prefix := t.TempDir()
	dest := filepath.Join(prefix, "ssh-mcp")
	if err := os.WriteFile(dest, []byte("old-binary"), 0o700); err != nil {
		t.Fatal(err)
	}

	cmd := installShCommand(t, prefix, "match", "test", "Linux", "")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install.sh failed with a verified download: %v\n%s", err, output)
	}
	assertInstalledTestExecutable(t, dest)
}

func TestInstallShVersionMismatchPreservesExistingBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash installer is not used on Windows")
	}
	prefix := t.TempDir()
	dest := filepath.Join(prefix, "ssh-mcp")
	if err := os.WriteFile(dest, []byte("old-binary"), 0o700); err != nil {
		t.Fatal(err)
	}

	cmd := installShCommand(t, prefix, "match", "wrong-version", "Linux", "")
	if output, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("install.sh succeeded with a mismatched binary version:\n%s", output)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("existing binary was removed after version failure: %v", err)
	}
	if string(got) != "old-binary" {
		t.Fatalf("existing binary changed after version failure: %q", got)
	}
	assertNoInstallTemps(t, prefix)
}

func TestInstallShUnknownCommitPreservesExistingBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash installer is not used on Windows")
	}
	prefix := t.TempDir()
	dest := filepath.Join(prefix, "ssh-mcp")
	if err := os.WriteFile(dest, []byte("old-binary"), 0o700); err != nil {
		t.Fatal(err)
	}

	cmd := installShCommand(t, prefix, "match", "test", "Linux", "")
	cmd.Env = append(cmd.Env, "SSH_MCP_INSTALL_TEST_COMMIT=unknown")
	if output, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("install.sh accepted a binary without an embedded commit:\n%s", output)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("existing binary was removed after commit failure: %v", err)
	}
	if string(got) != "old-binary" {
		t.Fatalf("existing binary changed after commit failure: %q", got)
	}
	assertNoInstallTemps(t, prefix)
}

func TestInstallShDarwinPreparesCandidateBeforeVersionCheck(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash installer is not used on Windows")
	}
	prefix := t.TempDir()
	trace := filepath.Join(t.TempDir(), "trace")
	cmd := installShCommand(t, prefix, "match", "test", "Darwin", trace)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install.sh failed for Darwin candidate: %v\n%s", err, output)
	}
	got, err := os.ReadFile(trace)
	if err != nil {
		t.Fatal(err)
	}
	want := "xattr -cr\ncodesign --force --sign -\ncodesign --verify --strict\nexecute version\n"
	if string(got) != want {
		t.Fatalf("Darwin candidate preparation order = %q, want %q", got, want)
	}
}

func TestInstallPowerShellSafetyContract(t *testing.T) {
	content, err := os.ReadFile("install.ps1")
	if err != nil {
		t.Fatal(err)
	}
	script := string(content)
	for _, required := range []string{
		"/releases/latest",
		"checksums.sha256",
		"Get-FileHash",
		"[System.IO.File]::Replace",
		"& $Temp version",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("install.ps1 missing %q", required)
		}
	}
	if strings.Contains(script, "$releases[0]") {
		t.Error("install.ps1 must not select the first release, which may be a prerelease")
	}
}

func TestPowerShellEnvironmentSeparatesWindowsPowerShellFromPwsh(t *testing.T) {
	inherited := []string{
		"PATH=C:\\tools",
		"PSModulePath=C:\\Program Files\\PowerShell\\Modules",
		"OTHER=value",
	}

	for _, entry := range powerShellEnvironment("powershell.exe", inherited) {
		if strings.EqualFold(strings.SplitN(entry, "=", 2)[0], "PSModulePath") {
			t.Fatalf("powershell.exe inherited pwsh PSModulePath: %q", entry)
		}
	}
	if got := strings.Join(powerShellEnvironment("pwsh.exe", inherited), "\x00"); got != strings.Join(inherited, "\x00") {
		t.Fatalf("pwsh.exe environment changed: %q", got)
	}
}

func TestInstallPowerShellChecksumMismatchPreservesExistingBinary(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PowerShell installer behavior is verified on Windows")
	}
	powerShell := findPowerShell(t)
	prefix := t.TempDir()
	dest := filepath.Join(prefix, "ssh-mcp.exe")
	if err := os.WriteFile(dest, []byte("old-binary"), 0o600); err != nil {
		t.Fatal(err)
	}

	output, err := runPowerShellInstaller(t, powerShell, prefix, strings.Repeat("0", 64), "stable")
	if err == nil {
		t.Fatalf("install.ps1 succeeded with a mismatched checksum:\n%s", output)
	}
	got, readErr := os.ReadFile(dest)
	if readErr != nil {
		t.Fatalf("existing binary was removed after checksum failure: %v", readErr)
	}
	if string(got) != "old-binary" {
		t.Fatalf("existing binary changed after checksum failure: %q", got)
	}
	assertNoInstallTemps(t, prefix)
}

func TestInstallPowerShellVerifiedDownloadReplacesExistingBinary(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PowerShell installer behavior is verified on Windows")
	}
	powerShell := findPowerShell(t)
	prefix := t.TempDir()
	dest := filepath.Join(prefix, "ssh-mcp.exe")
	if err := os.WriteFile(dest, []byte("old-binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := testExecutableChecksum(t)

	output, err := runPowerShellInstaller(t, powerShell, prefix, sum, "stable")
	if err != nil {
		t.Fatalf("install.ps1 failed with a verified download: %v\n%s", err, output)
	}
	assertInstalledTestExecutable(t, dest)
	assertNoInstallTemps(t, prefix)
}

func TestInstallPowerShellVersionMismatchPreservesExistingBinary(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PowerShell installer behavior is verified on Windows")
	}
	powerShell := findPowerShell(t)
	prefix := t.TempDir()
	dest := filepath.Join(prefix, "ssh-mcp.exe")
	if err := os.WriteFile(dest, []byte("old-binary"), 0o600); err != nil {
		t.Fatal(err)
	}

	output, err := runPowerShellInstaller(t, powerShell, prefix, testExecutableChecksum(t), "wrong-version")
	if err == nil {
		t.Fatalf("install.ps1 succeeded with a mismatched binary version:\n%s", output)
	}
	got, readErr := os.ReadFile(dest)
	if readErr != nil {
		t.Fatalf("existing binary was removed after version failure: %v", readErr)
	}
	if string(got) != "old-binary" {
		t.Fatalf("existing binary changed after version failure: %q", got)
	}
	assertNoInstallTemps(t, prefix)
}

func installShCommand(t *testing.T, prefix, checksumMode, version, osName, trace string) *exec.Cmd {
	t.Helper()
	fakeBin := t.TempDir()
	payload := testExecutable(t)
	payloadPath := filepath.Join(t.TempDir(), "ssh-mcp-payload")
	if err := os.WriteFile(payloadPath, payload, 0o700); err != nil {
		t.Fatal(err)
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(payload))
	curl := filepath.Join(fakeBin, "curl")
	script := fmt.Sprintf(`#!/usr/bin/env bash
set -eu
url=""
out=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    http*) url="$1"; shift ;;
    *) shift ;;
  esac
done
case "$url" in
  *checksums.sha256)
    value=%s
    if [ "${FAKE_CHECKSUM_MODE:-}" = mismatch ]; then
      value=%s
    fi
    for name in ssh-mcp_darwin_amd64 ssh-mcp_darwin_arm64 ssh-mcp_linux_amd64 ssh-mcp_linux_arm64; do
      printf '%%s  %%s\n' "$value" "$name"
    done > "$out"
    ;;
  *) cp "$FAKE_PAYLOAD" "$out" ;;
esac
`, sum, strings.Repeat("0", 64))
	if err := os.WriteFile(curl, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, script := range map[string]string{
		"uname":    fmt.Sprintf("#!/usr/bin/env bash\n[ \"$1\" = -s ] && { printf '%%s\\n' %s; exit; }\nprintf 'x86_64\\n'\n", shellQuote(osName)),
		"xattr":    "#!/usr/bin/env bash\nprintf 'xattr %s\\n' \"$1\" >> \"$SSH_MCP_INSTALL_TEST_TRACE\"\n",
		"codesign": "#!/usr/bin/env bash\ncase \"$1\" in\n  --force) printf 'codesign --force --sign -\\n' ;;\n  --verify) printf 'codesign --verify --strict\\n' ;;\nesac >> \"$SSH_MCP_INSTALL_TEST_TRACE\"\n",
	} {
		if err := os.WriteFile(filepath.Join(fakeBin, name), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	cmd := exec.Command("bash", "install.sh")
	cmd.Env = append(os.Environ(),
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"PREFIX="+prefix,
		"VERSION=vtest",
		"FAKE_CHECKSUM_MODE="+checksumMode,
		"FAKE_PAYLOAD="+payloadPath,
		"SSH_MCP_INSTALL_TEST_VERSION="+version,
		"SSH_MCP_INSTALL_TEST_TRACE="+trace,
	)
	return cmd
}

func findPowerShell(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"powershell.exe", "pwsh.exe"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	t.Fatal("PowerShell executable not found")
	return ""
}

func powerShellEnvironment(powerShell string, inherited []string) []string {
	if !strings.EqualFold(filepath.Base(powerShell), "powershell.exe") {
		return inherited
	}

	// Windows PowerShell rebuilds its own default module path when PSModulePath is absent.
	env := make([]string, 0, len(inherited))
	for _, entry := range inherited {
		name, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(name, "PSModulePath") {
			continue
		}
		env = append(env, entry)
	}
	return env
}

func runPowerShellInstaller(t *testing.T, powerShell, prefix, checksum, version string) (string, error) {
	t.Helper()
	installer, err := filepath.Abs("install.ps1")
	if err != nil {
		t.Fatal(err)
	}
	harness := filepath.Join(t.TempDir(), "install-harness.ps1")
	apiLog := filepath.Join(t.TempDir(), "api-url.txt")
	payloadPath := filepath.Join(t.TempDir(), "ssh-mcp-payload.exe")
	if err := os.WriteFile(payloadPath, testExecutable(t), 0o700); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf(`
# Load Get-FileHash before mocking commands exported by the same module.
Import-Module Microsoft.PowerShell.Utility
$env:PREFIX = '%s'
Remove-Item Env:VERSION -ErrorAction SilentlyContinue
function Invoke-RestMethod {
  param([string]$Uri)
  Set-Content -LiteralPath '%s' -Value $Uri
  return [pscustomobject]@{ tag_name = 'vstable' }
}
function Invoke-WebRequest {
  param([string]$Uri, [string]$OutFile, [switch]$UseBasicParsing)
  if ($Uri -like '*checksums.sha256') {
    Set-Content -LiteralPath $OutFile -Value '%s  ssh-mcp_windows_amd64.exe'
  } else {
    [System.IO.File]::Copy('%s', $OutFile, $true)
  }
}
. '%s'
exit $LASTEXITCODE
`, psQuote(prefix), psQuote(apiLog), checksum, psQuote(payloadPath), psQuote(installer))
	if err := os.WriteFile(harness, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(powerShell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", harness)
	cmd.Env = append(powerShellEnvironment(powerShell, os.Environ()), "SSH_MCP_INSTALL_TEST_VERSION="+version)
	output, runErr := cmd.CombinedOutput()
	if apiURL, readErr := os.ReadFile(apiLog); readErr == nil && !strings.HasSuffix(strings.TrimSpace(string(apiURL)), "/releases/latest") {
		t.Errorf("install.ps1 queried non-stable API: %s", apiURL)
	}
	return string(output), runErr
}

func testExecutable(t *testing.T) []byte {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func testExecutableChecksum(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%x", sha256.Sum256(testExecutable(t)))
}

func assertInstalledTestExecutable(t *testing.T, path string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(testExecutable(t)) {
		t.Fatal("installed binary does not match the verified executable payload")
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func psQuote(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

func assertNoInstallTemps(t *testing.T, prefix string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(prefix, ".ssh-mcp-install-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("installer left temporary files behind: %v", matches)
	}
}
