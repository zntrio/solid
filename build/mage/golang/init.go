package golang

import (
	"os"
	"runtime"
	"strings"

	"github.com/fatih/color"
)

const (
	goVersion = "go1.14"
)

func init() {
	if !strings.HasPrefix(runtime.Version(), goVersion) {
		color.HiRed("#############################################################################################")
		color.HiRed("")
		color.HiRed("Your golang compiler (%s) must be updated to %s to successfully compile all tools.", runtime.Version, goVersion)
		color.HiRed("")
		color.HiRed("#############################################################################################")
		os.Exit(-1)
	}
}
