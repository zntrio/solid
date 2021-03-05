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

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/pkg/sdk/types"
)

// -----------------------------------------------------------------------------

// Introspection instantiate an introspection assertion generator.
func Introspection(serializer Serializer) Generator {
	return &introspectionAssertionGenerator{
		serializer: serializer,
	}
}

// -----------------------------------------------------------------------------

type introspectionAssertionGenerator struct {
	serializer Serializer
}

func (c *introspectionAssertionGenerator) Generate(ctx context.Context, t *corev1.Token) (string, error) {
	// Check arguments
	if types.IsNil(c.serializer) {
		return "", fmt.Errorf("unable to use nil serializer")
	}
	if t == nil {
		return "", fmt.Errorf("unable to serialize nil token")
	}
	if t.Metadata == nil {
		return "", fmt.Errorf("token meta must not be nil")
	}

	// Prepare claims
	active := (t.Status == corev1.TokenStatus_TOKEN_STATUS_ACTIVE) && IsUsable(t)
	tokenIntrospection := map[string]interface{}{
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

	claims := map[string]interface{}{
		"iss":                 t.Metadata.Issuer,
		"iat":                 time.Now().Unix(),
		"token_introspection": tokenIntrospection,
	}

	// Serialize the assertion
	raw, err := c.serializer.Serialize(ctx, claims)
	if err != nil {
		return "", fmt.Errorf("unable to serialize client assertion: %w", err)
	}

	// No error
	return raw, nil
}
