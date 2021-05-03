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

//+build mage

package main

import (
	"github.com/fatih/color"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"

	"zntr.io/solid/build/mage/docker"
	"zntr.io/solid/build/mage/golang"
)

// -----------------------------------------------------------------------------

type Code mg.Namespace

// Lint code using golangci-lint.
func (Code) Lint() {
	mg.Deps(Code.Format)

	color.Red("## Lint source")
	mg.Deps(golang.Lint("."))
}

// Format source code and process imports.
func (Code) Format() {
	color.Red("## Formatting all sources")
	mg.SerialDeps(golang.Format, golang.Import)
}

// Licenser apply copyright banner to source code.
func (Code) Licenser() error {
	mg.SerialDeps(golang.Format, golang.Import)

	color.Red("## Add license banner")
	return sh.RunV("go-licenser", "-licensor", "SolID", "-license", "ASL2")
}

// Generate SDK code (mocks, tests, etc.)
func (Code) Generate() {
	color.Cyan("## Generate code")
	mg.SerialDeps(
		func() error {
			return golang.Generate("SDK", "zntr.io/solid/pkg/...")()
		},
	)
}

// -----------------------------------------------------------------------------

type API mg.Namespace

// Generate protobuf objects from proto definitions.
func (API) Generate() error {
	color.Blue("### Regenerate API")
	if err := sh.RunV("task", "-d", "api"); err != nil {
		return err
	}

	mg.SerialDeps(Code.Licenser)
	return nil
}

// -----------------------------------------------------------------------------

type Test mg.Namespace

// Test harp application.
func (Test) Unit() {
	color.Cyan("## Unit Tests")
	mg.SerialDeps(
		func() error {
			return golang.UnitTest("zntr.io/solid/...")()
		},
	)
}

// -----------------------------------------------------------------------------

type Docker mg.Namespace

// Tools prepares docker images with go toolchain and project tools.
func (Docker) Tools() error {
	return docker.Tools()
}
