// +build ignore

package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/magefile/mage/mage"
)

func init() {
	// Get current working directory
	name, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	// Get absolute path
	p, err := filepath.Abs(path.Join(name, "tools", "bin"))
	if err != nil {
		panic(err)
	}

	// Add local bin in PATH
	err = os.Setenv("PATH", fmt.Sprintf("%s:%s", p, os.Getenv("PATH")))
	if err != nil {
		panic(err)
	}
}

func main() { os.Exit(mage.Main()) }
