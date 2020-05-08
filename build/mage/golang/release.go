// Licensed to SolID under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. SolID licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package golang

import (
	"fmt"
	"os"
	"runtime"

	"github.com/fatih/color"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"

	"go.zenithar.org/solid/build/mage/git"
)

// -----------------------------------------------------------------------------

// Release build and generate a final release artifact.
func Release(name, packageName string, opts ...BuildOption) func() error {
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

		// Generate artifact name
		artifactName := fmt.Sprintf("%s-%s-%s", name, defaultOpts.goOS, defaultOpts.goArch)

		// Retrieve release from ENV
		releaseVersion := os.Getenv("RELEASE")
		if releaseVersion == "" {
			return fmt.Errorf("RELEASE environment variable is missing")
		}

		// Check if CGO is enabled
		if defaultOpts.cgoEnabled {
			artifactName = fmt.Sprintf("%s-cgo", artifactName)
		}

		// If windows target append ".exe"
		if defaultOpts.goOS == "windows" {
			artifactName = fmt.Sprintf("%s.exe", artifactName)
		}

		// Build the artifact
		if err := Build(
			name,
			packageName,
			opts...,
		)(); err != nil {
			return err
		}

		// Pack it
		if err := pack(artifactName); err != nil {
			return err
		}

		// Archive it
		if err := archive(artifactName, releaseVersion); err != nil {
			return err
		}

		// No error
		return nil
	}
}

// Pack the given artifact using upx
func pack(name string) error {
	color.Blue(" + Packing artifact")
	return sh.Run("upx", "-9", fmt.Sprintf("../../bin/%s", name))
}

// Archive as XZ archive
func archive(name, version string) error {
	color.Blue(" + Archive artifact")
	return sh.Run("tar", "Jcvf", fmt.Sprintf("../../dist/%s-%s.tar.xz", name, version), fmt.Sprintf("../../bin/%s", name))
}
