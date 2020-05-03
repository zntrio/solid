package golang

import (
	"fmt"

	"github.com/magefile/mage/sh"
)

// Generate invoke the go:generate task on given package
func Generate(name, packageName string) func() error {
	return func() error {
		fmt.Printf(" > %s [%s]\n", name, packageName)
		return sh.RunV("go", "generate", packageName)
	}
}
