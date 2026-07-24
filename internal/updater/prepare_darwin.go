//go:build darwin

package updater

import (
	"context"
	"fmt"
	"os/exec"
)

func prepareDownloadedBinary(ctx context.Context, path string) error {
	for _, command := range [][]string{
		{"xattr", "-cr", path},
		{"codesign", "--force", "--sign", "-", path},
		{"codesign", "--verify", "--strict", path},
	} {
		if output, err := exec.CommandContext(ctx, command[0], command[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %w: %s", command[0], err, output)
		}
	}
	return nil
}
