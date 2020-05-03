package golang

import (
	"fmt"
	"os"
	"path"

	"github.com/magefile/mage/sh"
)

// -----------------------------------------------------------------------------

var fuzzDir = "../test-results/fuzz"

// FuzzBuild instrument the given package name for fuzzing tests.
func FuzzBuild(name, packageName string) func() error {
	return func() error {
		// Prepare output path
		outputPath := path.Join(fuzzDir, name)

		// Check output directory existence
		if !existDir(outputPath) {
			// Create output directory
			if err := os.MkdirAll(outputPath, 0777); err != nil {
				return fmt.Errorf("unable to create fuzz output directory: %w", err)
			}
		}

		fmt.Printf(" > Instrumenting %s [%s]\n", name, packageName)
		return sh.Run("go-fuzz-build", "-o", fmt.Sprintf("%s.zip", outputPath), packageName)
	}
}

// FuzzRun starts a fuzzing process
func FuzzRun(name string) func() error {
	return func() error {
		// Prepare output path
		outputPath := path.Join(fuzzDir, name)

		fmt.Printf(" > Fuzzing %s\n", name)
		return sh.Run("go-fuzz", "-bin", fmt.Sprintf("%s.zip", outputPath), "-workdir", outputPath)
	}
}

func existDir(fpath string) bool {
	st, err := os.Stat(fpath)
	if err != nil {
		return false
	}
	return st.IsDir()
}
