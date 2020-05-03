package golang

import (
	"github.com/fatih/color"
	"github.com/magefile/mage/sh"
)

// Vendor locks all dependencies.
func Vendor() error {
	color.Cyan("## Vendoring dependencies")
	return sh.RunV("go", "mod", "vendor")
}
