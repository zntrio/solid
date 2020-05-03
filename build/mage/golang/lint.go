package golang

import (
	"path/filepath"

	"github.com/fatih/color"
	"github.com/magefile/mage/sh"
)

// Lint all source code.
func Lint(basePath string) func() error {
	return func() error {
		color.Cyan("## Lint go code")
		return sh.RunV("golangci-lint", "run", "-c", filepath.Clean(filepath.Join(basePath, ".golangci.yml")))
	}
}
