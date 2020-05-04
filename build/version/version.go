package version

import (
	"encoding/json"
	"fmt"

	"github.com/dchest/uniuri"
)

// Build information. Populated at build-time.
var (
	Version   = "unknown"
	Revision  = "unknown"
	Branch    = "unknown"
	BuildUser = "unknown"
	BuildDate = "unknown"
	GoVersion = "unknown"
)

// Map provides the iterable version information.
var Map = map[string]string{
	"version":   Version,
	"revision":  Revision,
	"branch":    Branch,
	"buildUser": BuildUser,
	"buildDate": BuildDate,
	"goVersion": GoVersion,
}

// Full returns full composed version string
func Full() string {
	return fmt.Sprintf("%s [%s] (Go: %s, User: %s, Date: %s)", Version, Branch, GoVersion, BuildUser, BuildDate)
}

// JSON returns json representation of build info
func JSON() string {
	payload, err := json.Marshal(Map)
	if err != nil {
		panic(err)
	}

	return string(payload)
}

// ID returns an instance id
func ID() string {
	return uniuri.NewLen(64)
}
