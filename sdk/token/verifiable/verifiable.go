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

package verifiable

import (
	"context"
	"errors"
	"fmt"

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/sdk/token"
)

func Token(source UUIDGeneratorFunc, secretKey []byte) token.Generator {
	return &tokenGenerator{
		generator: UUIDGenerator(source, secretKey),
	}
}

type tokenGenerator struct {
	generator Generator
}

func (c *tokenGenerator) Generate(_ context.Context, t *tokenv1.Token) (string, error) {
	// Check arguments
	switch {
	case c.generator == nil:
		return "", errors.New("the generator instance is nil")
	case t == nil:
		return "", errors.New("token must not be nil")
	}

	// Prepare token generation options
	opts := []GenerateOption{}
	switch t.TokenType {
	case tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN:
		opts = append(opts, WithTokenPrefix("sldat"))
	case tokenv1.TokenType_TOKEN_TYPE_REFRESH_TOKEN:
		opts = append(opts, WithTokenPrefix("sldrt"))
	case tokenv1.TokenType_TOKEN_TYPE_PHANTOM_TOKEN:
		opts = append(opts, WithTokenPrefix("sldpt"))
	case tokenv1.TokenType_TOKEN_TYPE_UNSPECIFIED, tokenv1.TokenType_TOKEN_TYPE_UNKNOWN, tokenv1.TokenType_TOKEN_TYPE_ID_TOKEN:
		return "", errors.New("unsupported token type")
	default:
		return "", errors.New("unsupported token type")
	}

	// Generate token
	out, err := c.generator.Generate(opts...)
	if err != nil {
		return "", fmt.Errorf("unable to generate the token value: %w", err)
	}

	return out, nil
}
