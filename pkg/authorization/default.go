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

package authorization

import (
	"context"

	"github.com/dchest/uniuri"
)

const (
	// DefaultAuthorizationCodeLen defines default auhtorization code length.
	DefaultAuthorizationCodeLen = 16
)

// Default returns the default authorization code generator.
func Default() CodeGenerator {
	return &codeGenerator{}
}

// -----------------------------------------------------------------------------

type codeGenerator struct {
}

func (c *codeGenerator) Generate(_ context.Context) (string, error) {
	code := uniuri.NewLen(DefaultAuthorizationCodeLen)
	return code, nil
}
