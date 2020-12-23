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

package jwt

import (
	"context"
	"fmt"

	"github.com/square/go-jose/v3/jwt"

	"zntr.io/solid/pkg/sdk/jwk"
	"zntr.io/solid/pkg/sdk/token"
	"zntr.io/solid/pkg/sdk/types"
)

// DefaultVerifier declare a default JWT verifier.
func DefaultVerifier(keySetProvider jwk.KeySetProviderFunc, supportedAlgorithms []string) token.Verifier {
	return &defaultVerifier{
		keySetProvider:      keySetProvider,
		supportedAlgorithms: types.StringArray(supportedAlgorithms),
	}
}

// -----------------------------------------------------------------------------

type defaultVerifier struct {
	keySetProvider      jwk.KeySetProviderFunc
	supportedAlgorithms types.StringArray
}

func (v *defaultVerifier) Parse(token string) (token.Token, error) {
	// Parse JWT token
	t, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, fmt.Errorf("unable to parse signed token: %w", err)
	}

	// Wrap token instance
	return &tokenWrapper{
		token: t,
	}, nil
}

func (v *defaultVerifier) Verify(token string) error {
	// Parse JWT token
	t, err := jwt.ParseSigned(token)
	if err != nil {
		return fmt.Errorf("unable to parse signed token: %w", err)
	}

	// Check token header
	if len(t.Headers) == 0 {
		return fmt.Errorf("unable to process token without header")
	}

	// Validate algorithm
	alg := t.Headers[0].Algorithm
	if !v.supportedAlgorithms.Contains(alg) {
		return fmt.Errorf("token uses an invalid or not supported algorithm `%s`", alg)
	}

	// No error
	return nil
}

func (v *defaultVerifier) Claims(raw string, claims interface{}) error {
	// Parse JWT token
	t, err := jwt.ParseSigned(raw)
	if err != nil {
		return fmt.Errorf("unable to parse signed token: %w", err)
	}

	// Retrieve KeySet
	jwks, err := v.keySetProvider(context.Background())
	if err != nil {
		return fmt.Errorf("unable to retrieve KeySet: %w", err)
	}

	// Set all keys by default
	keys := jwks.Keys

	// Check if token refer to a key
	kid := t.Headers[0].KeyID
	if kid != "" {
		keys = jwks.Key(kid)
	}

	// Iterate on all keys to find a matching one.
	valid := false
	// For each key in keyset
	for i := range keys {
		// Extract key
		k := keys[i]

		// Check key type
		if k.Use == "enc" {
			// Ignore encryption key
			continue
		}

		// Try to verify with current key
		if err := t.Claims(k, claims); err != nil {
			continue
		}

		// Found a valid key
		valid = true
		break
	}
	if !valid {
		return token.ErrInvalidTokenSignature
	}

	// No error
	return nil
}
