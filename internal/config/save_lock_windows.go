//go:build windows

package config

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func lockSaveFile(path string) (func() error, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("config: open save lock %q: %w", path, err)
	}
	overlapped := &windows.Overlapped{}
	handle := windows.Handle(file.Fd())
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, overlapped); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("config: lock save file %q: %w", path, err)
	}
	return func() error {
		unlockErr := windows.UnlockFileEx(handle, 0, 1, 0, overlapped)
		closeErr := file.Close()
		return errors.Join(unlockErr, closeErr)
	}, nil
}
