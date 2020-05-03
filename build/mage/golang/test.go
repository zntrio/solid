package golang

import (
	"crypto/sha256"
	"fmt"

	"github.com/fatih/color"
	"github.com/magefile/mage/sh"
)

// UnitTest run go test
func UnitTest(packageName string) func() error {
	return func() error {
		color.Yellow("> Unit testing [%s]", packageName)
		if err := sh.Run("mkdir", "-p", "test-results/junit"); err != nil {
			return err
		}

		return sh.RunV("gotestsum", "--junitfile", fmt.Sprintf("test-results/junit/unit-%x.xml", sha256.Sum256([]byte(packageName))), "--", "-short", "-race", "-cover", packageName)
	}
}

// IntegrationTest run go test
func IntegrationTest(packageName string) func() error {
	return func() error {
		color.Yellow("> Integration testing [%s]", packageName)
		if err := sh.Run("mkdir", "-p", "test-results/junit"); err != nil {
			return err
		}

		return sh.RunV("gotestsum", "--junitfile", fmt.Sprintf("test-results/junit/integration-%x.xml", sha256.Sum256([]byte(packageName))), "--", "-tags=integration", "-short", "-race", "-cover", packageName)
	}
}
