//go:build !darwin

package updater

import "context"

func prepareDownloadedBinary(context.Context, string) error {
	return nil
}
