// Package version defines the release version contract shared by local builds
// and CI.
package version

import (
	"fmt"
	"regexp"
	"time"
)

var basePattern = regexp.MustCompile(`^([0-9]{8})\.([1-9][0-9]*)$`)

// ValidateBase accepts the root VERSION format YYYYMMDD.V. The suffix is
// deliberately excluded because VERSION is the stable base for both channels.
func ValidateBase(base string) error {
	match := basePattern.FindStringSubmatch(base)
	if match == nil {
		return fmt.Errorf("version %q must match YYYYMMDD.V with V >= 1 and no leading zero", base)
	}
	if _, err := time.Parse("20060102", match[1]); err != nil {
		return fmt.Errorf("version %q contains an invalid calendar date: %w", base, err)
	}
	return nil
}

// ResolveRelease verifies that tag exactly matches VERSION for the selected
// channel and returns the version string to inject into release binaries.
func ResolveRelease(base, channel, tag string) (string, error) {
	if err := ValidateBase(base); err != nil {
		return "", err
	}

	var expectedTag, releaseVersion string
	switch channel {
	case "stable":
		expectedTag = "v" + base
		releaseVersion = base
	case "dev":
		expectedTag = "v" + base + "-dev"
		releaseVersion = base + "-dev"
	default:
		return "", fmt.Errorf("unknown release channel %q: want stable or dev", channel)
	}
	if tag != expectedTag {
		return "", fmt.Errorf("%s release tag %q must exactly equal %q from VERSION", channel, tag, expectedTag)
	}
	return releaseVersion, nil
}
