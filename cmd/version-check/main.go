package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	versioncontract "github.com/xjoker/ssh-mcp/internal/version"
)

func main() {
	versionFile := flag.String("file", "VERSION", "path to the base VERSION file")
	channel := flag.String("channel", "", "release channel: stable or dev")
	tag := flag.String("tag", "", "release tag to verify")
	flag.Parse()

	raw, err := os.ReadFile(*versionFile)
	if err != nil {
		fail("read %s: %v", *versionFile, err)
	}
	base := strings.TrimSpace(string(raw))
	if err := versioncontract.ValidateBase(base); err != nil {
		fail("%v", err)
	}

	if *channel == "" && *tag == "" {
		fmt.Println(base)
		return
	}
	if *channel == "" || *tag == "" {
		fail("--channel and --tag must be provided together")
	}

	releaseVersion, err := versioncontract.ResolveRelease(base, *channel, *tag)
	if err != nil {
		fail("%v", err)
	}
	fmt.Println(releaseVersion)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "version-check: "+format+"\n", args...)
	os.Exit(1)
}
