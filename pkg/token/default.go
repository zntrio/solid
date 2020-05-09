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

package token

import (
	"context"
	"fmt"

	"github.com/dchest/uniuri"
)

const (
	// DefaultAccessTokenLen defines default authorization code length.
	DefaultAccessTokenLen = 60
)

// DefaultAccessTokenGenerator returns the default authorization code generator.
func DefaultAccessTokenGenerator() AccessTokenGenerator {
	return &accessTokenGenerator{}
}

// -----------------------------------------------------------------------------

type accessTokenGenerator struct {
}

func (c *accessTokenGenerator) Generate(_ context.Context) (string, error) {
	code := fmt.Sprintf("%s.%s", uniuri.NewLen(3), uniuri.NewLen(DefaultAccessTokenLen))
	return code, nil
}
