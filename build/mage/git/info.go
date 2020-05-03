package git

import (
	"github.com/magefile/mage/sh"
)

var (
	// Revision contains git commit hash
	Revision string

	// Tag contains git tag description
	Tag string

	// Branch used to build
	Branch string
)

// CollectInfo is used to populate package properties.
func CollectInfo() error {
	var err error

	Revision, err = hash()
	if err != nil {
		return err
	}

	Tag, err = tag()
	if err != nil {
		return err
	}

	Branch, err = branch()
	return err
}

// tag returns the git tag for the current branch or "" if none.
func tag() (string, error) {
	return sh.Output("git", "describe", "--always")
}

// TagMatch returns the git tag for the current branch or "" if none.
func TagMatch(match string) (string, error) {
	tag, err := sh.Output("git", "describe", "--match", match)
	if err != nil {
		return "", nil
	}

	// No error
	return tag, nil
}

// hash returns the git hash for the current repo or "" if none.
func hash() (string, error) {
	return sh.Output("git", "rev-parse", "--short", "HEAD")
}

// branch returns the git branch for current repo
func branch() (string, error) {
	return sh.Output("git", "rev-parse", "--abbrev-ref", "HEAD")
}
