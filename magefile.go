//+build mage

package main

import (
	"go.zenithar.org/solid/build/mage/golang"

	"github.com/fatih/color"
	"github.com/magefile/mage/mg"
)

type Code mg.Namespace

func (Code) Lint() {
	mg.Deps(Code.Format)

	color.Red("## Lint source")
	mg.Deps(golang.Lint("."))
}

func (Code) Format() {
	color.Red("## Formatting all sources")
	mg.SerialDeps(golang.Format, golang.Import)
}
