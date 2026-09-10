// Package version reports which webhog build produced a result, so a finding
// can be traced back to the exact code that found it.
package version

import (
	"runtime/debug"
	"strings"
)

// Version and Commit are stamped at build time:
//
//	go build -ldflags "-X github.com/emancipat3r/webhog/internal/version.Version=v1.2.3 \
//	                   -X github.com/emancipat3r/webhog/internal/version.Commit=abc1234"
//
// (the Makefile does this from git). When not stamped, they fall back to the
// module version and VCS revision Go embeds, so a `go install ...@vX.Y.Z`
// build still identifies itself without any flags.
var (
	Version = ""
	Commit  = ""
)

func init() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	if Version == "" && info.Main.Version != "" && info.Main.Version != "(devel)" {
		Version = info.Main.Version
	}
	var rev string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if Commit == "" && rev != "" {
		if len(rev) > 12 {
			rev = rev[:12]
		}
		if dirty {
			rev += "-dirty"
		}
		Commit = rev
	}
	if Version == "" {
		Version = "dev"
	}
}

// String returns "vX.Y.Z (commit)" or whichever parts are known.
func String() string {
	var b strings.Builder
	b.WriteString(Version)
	if Commit != "" {
		b.WriteString(" (")
		b.WriteString(Commit)
		b.WriteString(")")
	}
	return b.String()
}

// UserAgent returns the default User-Agent webhog sends, carrying the version
// so a target's logs can identify which build made a request.
func UserAgent() string {
	return "webhog/" + Version + " (https://github.com/emancipat3r/webhog)"
}
