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
