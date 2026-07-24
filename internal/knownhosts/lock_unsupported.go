//go:build !darwin && !linux && !windows

package knownhosts

import "fmt"

func lockKnownHostsFile(path string) (func() error, error) {
	return nil, fmt.Errorf("known_hosts locking is unsupported on this platform for %q", path)
}
