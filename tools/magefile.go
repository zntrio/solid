// +build mage

package main

import (
	"github.com/fatih/color"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

var Default = Build

func Build() {
	color.Red("# Installing tools ---------------------------------------------------------")
	mg.SerialDeps(Go.Vendor, Go.Tools)
}

type Go mg.Namespace

var deps = []string{
	"github.com/izumin5210/gex/cmd/gex",
}

// Vendor create tools vendors
func (Go) Vendor() error {
	color.Blue("## Vendoring dependencies")
	return sh.RunV("go", "mod", "vendor")
}

// Tools updates tools from package
func (Go) Tools() error {
	color.Blue("## Installing tools")
	return sh.RunV("go", "run", "github.com/izumin5210/gex/cmd/gex", "--build")
}
