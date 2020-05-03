//+build mage

package main

import (
	"go.zenithar.org/solid/build/mage/golang"

	"github.com/fatih/color"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
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

// -----------------------------------------------------------------------------

type API mg.Namespace

func (API) Generate() error {
	color.Blue("### Regenerate API")
	return sh.RunV("protoc", "--go_out=api/gen/go", "-Iapi/proto", "-Itools/vendor", "proto/**/*.proto")
}
