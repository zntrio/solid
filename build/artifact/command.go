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

package artifact

import (
	"github.com/iancoleman/strcase"
)

// Command specification
type Command struct {
	Name        string
	Description string
	Package     string
	Module      string
	UseBoring   bool
}

// Kebab returns the kebab-case artifact name.
func (c Command) Kebab() string {
	return strcase.ToKebab(c.Name)
}

// Camel returns the CamelCase artifact name.
func (c Command) Camel() string {
	return strcase.ToCamel(c.Name)
}

// HasModule returns trus if artifact as a dedicated module.
func (c Command) HasModule() bool {
	return c.Module != ""
}
