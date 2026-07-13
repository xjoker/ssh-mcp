//go:build !darwin && !linux && !windows

package config

import "fmt"

func lockSaveFile(path string) (func() error, error) {
	return nil, fmt.Errorf("config: atomic save locking is unsupported on this platform for %q", path)
}
