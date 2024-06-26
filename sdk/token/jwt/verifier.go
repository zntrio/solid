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
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token"
)

// DefaultVerifier declare a default JWT verifier.
func DefaultVerifier(keySetProvider jwk.KeySetProviderFunc, supportedAlgorithms []jose.SignatureAlgorithm) token.Verifier {
	return &defaultVerifier{
		keySetProvider:      keySetProvider,
		supportedAlgorithms: supportedAlgorithms,
	}
}

// -----------------------------------------------------------------------------

type defaultVerifier struct {
	keySetProvider      jwk.KeySetProviderFunc
	supportedAlgorithms []jose.SignatureAlgorithm
}

func (v *defaultVerifier) Parse(token string) (token.Token, error) {
	// Parse JWT token
	t, err := jwt.ParseSigned(token, v.supportedAlgorithms)
	if err != nil {
		return nil, errors.New("unable to parse signed token")
	}

	// Wrap token instance
	return &tokenAdapter{
		token: t,
	}, nil
}

func (v *defaultVerifier) Verify(token string) error {
	// Parse JWT token
	t, err := jwt.ParseSigned(token, v.supportedAlgorithms)
	if err != nil {
		return fmt.Errorf("unable to parse signed token: %w", err)
	}

	// Check token header
	if len(t.Headers) == 0 {
		return fmt.Errorf("unable to process token without header")
	}

	// No error
	return nil
}

// Claims extracts claims from given raw token with verifier keyset provider.
func (v *defaultVerifier) Claims(ctx context.Context, raw string, claims any) error {
	// Parse JWT token
	t, err := jwt.ParseSigned(raw, v.supportedAlgorithms)
	if err != nil {
		return fmt.Errorf("unable to parse signed token: %w", err)
	}

	// Retrieve KeySet
	jwks, err := v.keySetProvider(ctx)
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
