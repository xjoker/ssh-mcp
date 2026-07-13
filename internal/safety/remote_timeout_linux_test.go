//go:build linux

package safety

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestWithRemoteTimeoutSurvivesOuterShellAndKillsProcessGroup(t *testing.T) {
	for _, name := range []string{"setsid", "timeout"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("remote timeout integration requires %s: %v", name, err)
		}
	}

	pidPath := t.TempDir() + "/pids"
	userCommand := fmt.Sprintf(
		"trap '' TERM; sleep 30 & child=$!; printf '%%s %%s' \"$$\" \"$child\" > %s; wait \"$child\"",
		shellSingleQuote(pidPath),
	)
	cmd, err := NewRemoteCommand(userCommand, "")
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := WithRemoteTimeout(cmd, 100*time.Millisecond, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	outer := exec.Command("sh", "-c", wrapped.Raw())
	if err := outer.Start(); err != nil {
		t.Fatalf("start wrapped command: %v", err)
	}

	pids := waitForPIDFile(t, pidPath, 2*time.Second)
	defer func() {
		for _, pid := range pids {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}()

	// Simulate the SSH server closing the channel's outer shell. The setsid
	// watchdog must survive this and reap both the TERM-ignoring shell and its
	// child when its own remote deadline expires.
	if err := outer.Process.Kill(); err != nil {
		t.Fatalf("kill outer shell: %v", err)
	}
	_ = outer.Wait()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		allGone := true
		for _, pid := range pids {
			if processExists(pid) {
				allGone = false
				break
			}
		}
		if allGone {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("remote watchdog left process group members alive: %v", pids)
}

func waitForPIDFile(t *testing.T, path string, timeout time.Duration) []int {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			fields := strings.Fields(string(data))
			if len(fields) == 2 {
				pids := make([]int, 0, 2)
				for _, field := range fields {
					pid, convErr := strconv.Atoi(field)
					if convErr != nil {
						t.Fatalf("parse PID %q: %v", field, convErr)
					}
					pids = append(pids, pid)
				}
				return pids
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for PID file %s", path)
	return nil
}

func processExists(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || !errors.Is(err, syscall.ESRCH)
}
