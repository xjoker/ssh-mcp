//go:build !windows

package safety

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestWithRemoteTimeoutMissingToolsFailsBeforeUserCommand(t *testing.T) {
	markerPath := t.TempDir() + "/user-command-ran"
	cmd, err := NewRemoteCommand("printf ran > "+shellSingleQuote(markerPath), "")
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := WithRemoteTimeout(cmd, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	process := exec.Command("sh", "-c", wrapped.Raw())
	process.Env = append(os.Environ(), "PATH=")
	output, runErr := process.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(runErr, &exitErr) || exitErr.ExitCode() != 125 {
		t.Fatalf("missing-tool preflight exit: got err=%v output=%q, want exit 125", runErr, output)
	}
	if !strings.Contains(string(output), RemoteTimeoutUnavailableMessage) {
		t.Fatalf("missing fixed preflight error in %q", output)
	}
	if _, statErr := os.Stat(markerPath); !os.IsNotExist(statErr) {
		t.Fatalf("user command ran despite failed preflight: stat err=%v", statErr)
	}
}
