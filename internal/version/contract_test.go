package version

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateBase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		version string
		wantErr bool
	}{
		{name: "valid date and first revision", version: "20260724.1"},
		{name: "valid leap day", version: "20240229.9"},
		{name: "zero revision", version: "20260724.0", wantErr: true},
		{name: "leading zero revision", version: "20260724.01", wantErr: true},
		{name: "invalid calendar date", version: "20260229.1", wantErr: true},
		{name: "development suffix belongs to tags and builds", version: "20260724.1-dev", wantErr: true},
		{name: "legacy semver", version: "0.0.7", wantErr: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateBase(tt.version)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateBase(%q) error = %v, wantErr %v", tt.version, err, tt.wantErr)
			}
		})
	}
}

func TestResolveReleaseRequiresExactTag(t *testing.T) {
	t.Parallel()

	const base = "20260724.1"
	tests := []struct {
		name    string
		channel string
		tag     string
		want    string
		wantErr bool
	}{
		{name: "stable", channel: "stable", tag: "v20260724.1", want: base},
		{name: "development", channel: "dev", tag: "v20260724.1-dev", want: base + "-dev"},
		{name: "stable rejects development tag", channel: "stable", tag: "v20260724.1-dev", wantErr: true},
		{name: "development rejects numbered suffix", channel: "dev", tag: "v20260724.1-dev.2", wantErr: true},
		{name: "development rejects different VERSION", channel: "dev", tag: "v20260724.2-dev", wantErr: true},
		{name: "unknown channel", channel: "nightly", tag: "v20260724.1", wantErr: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ResolveRelease(base, tt.channel, tt.tag)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ResolveRelease(%q, %q, %q) error = %v, wantErr %v", base, tt.channel, tt.tag, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("ResolveRelease(%q, %q, %q) = %q, want %q", base, tt.channel, tt.tag, got, tt.want)
			}
		})
	}
}

func TestWorkflowsUseSharedVersionContract(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", ".github", "workflows")
	tests := []struct {
		file     string
		required []string
	}{
		{file: "ci.yml", required: []string{
			"go run ./cmd/version-check",
			`version | head -n 1`,
		}},
		{file: "release.yml", required: []string{
			"go run ./cmd/version-check",
			"--channel stable",
			"fetch-depth: 0",
			`git merge-base --is-ancestor "$GITHUB_SHA" origin/main`,
			`version | head -n 1`,
		}},
		{file: "release-dev.yml", required: []string{
			"go run ./cmd/version-check",
			"--channel dev",
			"fetch-depth: 0",
			`git merge-base --is-ancestor "$GITHUB_SHA" origin/dev`,
			`version | head -n 1`,
		}},
	}

	for _, tt := range tests {
		content, err := os.ReadFile(filepath.Join(root, tt.file))
		if err != nil {
			t.Fatal(err)
		}
		for _, required := range tt.required {
			if !strings.Contains(string(content), required) {
				t.Errorf("%s does not use shared version contract %q", tt.file, required)
			}
		}
	}
}

func TestMakeReleaseUsesValidatedTagAndCleanTree(t *testing.T) {
	t.Parallel()

	content, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	makefile := string(content)
	for _, required := range []string{
		"git status --porcelain",
		"git describe --tags --exact-match HEAD",
		"go run ./cmd/version-check --channel stable --tag",
		"version | head -n 1",
		"set -e;",
	} {
		if !strings.Contains(makefile, required) {
			t.Errorf("Makefile release target missing %q", required)
		}
	}
	if strings.Contains(makefile, "VERSION ?=") {
		t.Error("Makefile must not allow callers to override the VERSION single source of truth")
	}
}
