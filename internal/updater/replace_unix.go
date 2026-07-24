//go:build !windows

package updater

import "os"

func replaceDownloadedBinary(source, destination string) error {
	return os.Rename(source, destination)
}
