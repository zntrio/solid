package golang

import (
	"github.com/fatih/color"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

// Import fix all source code imports.
func Import() error {
	mg.Deps(CollectGoFiles)

	color.Cyan("## Process imports")

	for pth := range CollectedGoFiles {
		args := []string{"-w", "-local", "go.zenithar.org/solid"}
		args = append(args, pth)

		if err := sh.RunV("gofumports", args...); err != nil {
			return err
		}
	}

	return nil
}
