// Package version holds build metadata injected at link time via -ldflags.
//
// The Makefile sets these with, e.g.:
//
//	-X github.com/jfigge/keephippo/internal/version.Version=v0.1.0
package version

import (
	"fmt"
	"runtime"
)

// Build metadata. Defaults apply to `go run`/`go build` without ldflags;
// the Makefile overrides them for real builds. See the Makefile's LDFLAGS.
var (
	Version   = "dev"
	Commit    = "none"
	Branch    = "none"
	BuildTime = "unknown"
)

// Short returns just the version string (a git tag like "v0.1.0", or a commit
// hash when no tag is reachable).
func Short() string {
	return Version
}

// Info returns a multi-line, human-readable build summary: version, branch,
// commit, build time, the Go toolchain version, and the target platform.
func Info() string {
	return fmt.Sprintf(
		"version:    %s\nbranch:     %s\ncommit:     %s\nbuild time: %s\ngo:         %s\nplatform:   %s/%s",
		Version, Branch, Commit, BuildTime, runtime.Version(), runtime.GOOS, runtime.GOARCH,
	)
}
