package golang

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"go.zenithar.org/solid/build/mage/git"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

type buildOpts struct {
	binaryName  string
	packageName string
	cgoEnabled  bool
	goOS        string
	goArch      string
}

// BuildOption is used to define function option pattern.
type BuildOption func(*buildOpts)

// -----------------------------------------------------------------------------

// WithCGO enbales CGO compilation
func WithCGO() BuildOption {
	return func(opts *buildOpts) {
		opts.cgoEnabled = true
	}
}

// GOOS sets the GOOS value during build
func GOOS(value string) BuildOption {
	return func(opts *buildOpts) {
		opts.goOS = value
	}
}

// GOARCH sets the GOARCH value during build
func GOARCH(value string) BuildOption {
	return func(opts *buildOpts) {
		opts.goArch = value
	}
}

// -----------------------------------------------------------------------------

// Build the given binary usign the given package.
func Build(name, packageName string, opts ...BuildOption) func() error {
	const (
		defaultCgoEnabled = false
		defaultGoOs       = runtime.GOOS
		defaultGoArch     = runtime.GOARCH
	)

	// Default build options
	defaultOpts := &buildOpts{
		binaryName:  name,
		packageName: packageName,
		cgoEnabled:  defaultCgoEnabled,
		goOS:        defaultGoOs,
		goArch:      defaultGoArch,
	}

	// Apply options
	for _, o := range opts {
		o(defaultOpts)
	}

	return func() error {
		mg.SerialDeps(git.CollectInfo)

		fmt.Printf(" > Building %s [%s] [os:%s arch:%s cgo:%v]\n", defaultOpts.binaryName, defaultOpts.packageName, defaultOpts.goOS, defaultOpts.goArch, defaultOpts.cgoEnabled)

		// Generate artifact name
		artifactName := fmt.Sprintf("%s-%s-%s", name, defaultOpts.goOS, defaultOpts.goArch)

		// Check if CGO is enabled
		if defaultOpts.cgoEnabled {
			artifactName = fmt.Sprintf("%s-cgo", artifactName)
		}

		// Prepare build flags
		version, err := git.TagMatch(fmt.Sprintf("cmd/%s*", name))
		if err != nil {
			return err
		}

		// Inject version information
		varsSetByLinker := map[string]string{
			"go.zenithar.org/solid/build/version.Version":   version,
			"go.zenithar.org/solid/build/version.Revision":  git.Revision,
			"go.zenithar.org/solid/build/version.Branch":    git.Branch,
			"go.zenithar.org/solid/build/version.BuildUser": os.Getenv("USER"),
			"go.zenithar.org/solid/build/version.BuildDate": time.Now().Format(time.RFC3339),
			"go.zenithar.org/solid/build/version.GoVersion": runtime.Version(),
		}
		var linkerArgs []string
		for name, value := range varsSetByLinker {
			linkerArgs = append(linkerArgs, "-X", fmt.Sprintf("'%s=%s'", name, value))
		}

		// Strip and remove DWARF
		linkerArgs = append(linkerArgs, "-s", "-w")

		// Assemble ldflags
		ldflagsValue := strings.Join(linkerArgs, " ")

		// Build environment
		env := map[string]string{
			"GOOS":        defaultOpts.goOS,
			"GOARCH":      defaultOpts.goArch,
			"CGO_ENABLED": "0",
		}
		if defaultOpts.cgoEnabled {
			env["CGO_ENABLED"] = "1"
		}

		// Generate output filename
		filename := fmt.Sprintf("../../bin/%s", artifactName)
		if defaultOpts.goOS == "windows" {
			filename = fmt.Sprintf("%s.exe", filename)
		}

		return sh.RunWith(env, "go", "build", "-mod=readonly", "-ldflags", ldflagsValue, "-o", filename, packageName)
	}
}
