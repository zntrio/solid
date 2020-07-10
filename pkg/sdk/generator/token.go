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

package generator

import (
	"context"
	"fmt"

	"github.com/dchest/uniuri"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
)

const (
	// DefaultAccessTokenLen defines default token code length.
	DefaultAccessTokenLen = 28
)

// DefaultToken returns the default token generator.
func DefaultToken() Token {
	return &tokenGenerator{}
}

// -----------------------------------------------------------------------------

type tokenGenerator struct {
}

func (c *tokenGenerator) Generate(_ context.Context, _ string, _ *corev1.TokenMeta, _ *corev1.TokenConfirmation) (string, error) {
	code := fmt.Sprintf("%s.%s", uniuri.NewLen(3), uniuri.NewLen(DefaultAccessTokenLen))
	return code, nil
}
