package golang

import (
	"github.com/fatih/color"
	"github.com/magefile/mage/sh"
)

// License checks allowed license of vendored dependencies.
func License() error {
	color.Cyan("## Check license")
	return sh.RunV("wwhrd", "check", "-f", "../../.wwhrd.yml")
}
