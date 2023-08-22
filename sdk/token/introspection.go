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
	"time"

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/sdk/types"
)

// -----------------------------------------------------------------------------

// Introspection instantiate an introspection assertion generator.
func Introspection(signer Serializer) Generator {
	return &introspectionAssertionGenerator{
		signer: signer,
	}
}

// -----------------------------------------------------------------------------

type introspectionAssertionGenerator struct {
	signer Serializer
}

func (c *introspectionAssertionGenerator) Generate(ctx context.Context, t *tokenv1.Token) (string, error) {
	// Check arguments
	if types.IsNil(c.signer) {
		return "", fmt.Errorf("unable to use nil signer")
	}
	if t == nil {
		return "", fmt.Errorf("unable to sign nil token")
	}
	if t.Metadata == nil {
		return "", fmt.Errorf("token meta must not be nil")
	}

	// Prepare claims
	active := (t.Status == tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE) && IsUsable(t)
	tokenIntrospection := map[string]any{
		"active": active,
	}
	if active {
		tokenIntrospection["iss"] = t.Metadata.Issuer
		tokenIntrospection["aud"] = t.Metadata.Audience
		tokenIntrospection["iat"] = t.Metadata.IssuedAt
		tokenIntrospection["exp"] = t.Metadata.ExpiresAt
		tokenIntrospection["client_id"] = t.Metadata.ClientId
		tokenIntrospection["scope"] = t.Metadata.Scope
		tokenIntrospection["sub"] = t.Metadata.Subject
		tokenIntrospection["jti"] = t.TokenId
	}

	claims := map[string]any{
		"iss":                 t.Metadata.Issuer,
		"iat":                 time.Now().Unix(),
		"token_introspection": tokenIntrospection,
	}

	// Sign the assertion
	raw, err := c.signer.Serialize(ctx, claims)
	if err != nil {
		return "", fmt.Errorf("unable to sign client assertion: %w", err)
	}

	// No error
	return raw, nil
}
