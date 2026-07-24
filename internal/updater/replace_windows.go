//go:build windows

package updater

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

const detachedProcess = 0x00000008

func replaceDownloadedBinary(source, destination string) error {
	if _, err := os.Stat(destination); errors.Is(err, os.ErrNotExist) {
		return os.Rename(source, destination)
	} else if err != nil {
		return err
	}

	return replaceWindowsBinary(source, destination, func(backup string) error {
		return startWindowsCleanup(backup, os.Getpid())
	})
}

func replaceWindowsBinary(source, destination string, startCleanup func(string) error) error {
	backup := source + ".previous"
	if _, err := os.Lstat(backup); err == nil {
		return fmt.Errorf("backup path already exists: %s", backup)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check backup path: %w", err)
	}

	// Windows cannot overwrite an image that the current process is running.
	// Renaming that image is permitted, so first move it aside and then put the
	// verified candidate at the public path. Success is reported only after the
	// public path already names the new binary.
	if err := os.Rename(destination, backup); err != nil {
		return fmt.Errorf("move running binary aside: %w", err)
	}
	if err := os.Rename(source, destination); err != nil {
		if rollbackErr := os.Rename(backup, destination); rollbackErr != nil {
			return errors.Join(
				fmt.Errorf("install verified binary: %w", err),
				fmt.Errorf("restore previous binary: %w", rollbackErr),
			)
		}
		return fmt.Errorf("install verified binary: %w", err)
	}

	if err := startCleanup(backup); err != nil {
		if rollbackCandidateErr := os.Rename(destination, source); rollbackCandidateErr != nil {
			return errors.Join(
				fmt.Errorf("start old-binary cleanup: %w", err),
				fmt.Errorf("restore candidate after cleanup failure: %w", rollbackCandidateErr),
			)
		}
		if rollbackOldErr := os.Rename(backup, destination); rollbackOldErr != nil {
			restoreNewErr := os.Rename(source, destination)
			return errors.Join(
				fmt.Errorf("start old-binary cleanup: %w", err),
				fmt.Errorf("restore previous binary: %w", rollbackOldErr),
				restoreNewErr,
			)
		}
		return fmt.Errorf("start old-binary cleanup: %w", err)
	}
	return nil
}

func startWindowsCleanup(backup string, parentPID int) error {
	scriptPath := backup + ".cleanup.ps1"
	script := fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$backup = '%s'
$script = '%s'
try {
  while (Get-Process -Id %d -ErrorAction SilentlyContinue) {
    Start-Sleep -Milliseconds 250
  }
  Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
} finally {
  Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $script -Force -ErrorAction SilentlyContinue
}
`, psSingleQuote(backup), psSingleQuote(scriptPath), parentPID)
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		return fmt.Errorf("write cleanup helper: %w", err)
	}

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", scriptPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | detachedProcess,
	}
	if err := cmd.Start(); err != nil {
		os.Remove(scriptPath)
		return fmt.Errorf("start cleanup helper: %w", err)
	}
	return cmd.Process.Release()
}

func psSingleQuote(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}
