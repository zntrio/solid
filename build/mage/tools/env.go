package tools

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
)

// Env sets the environment for tools
func Env() error {
	// Get current working directory
	name, err := os.Getwd()
	if err != nil {
		return err
	}

	// Get absolute path
	p, err := filepath.Abs(path.Join(name, "tools", "bin"))
	if err != nil {
		return err
	}

	// Add local bin in PATH
	return os.Setenv("PATH", fmt.Sprintf("%s:%s", p, os.Getenv("PATH")))
}
