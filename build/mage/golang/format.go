package golang

import (
	"github.com/fatih/color"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

// Format all source code.
func Format() error {
	mg.Deps(CollectGoFiles)

	color.Cyan("## Format everything")

	for pth := range CollectedGoFiles {
		args := []string{"-s", "-w"}
		args = append(args, pth)

		if err := sh.RunV("gofumpt", args...); err != nil {
			return err
		}
	}

	return nil
}
