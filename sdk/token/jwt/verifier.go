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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	gojwt "github.com/golang-jwt/jwt/v5"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token"
)

// parseUnverified syntactically parses raw, resolves the signing method,
// enforces the algorithm allowlist, and returns the token plus raw segments.
func parseUnverified(raw string, supportedAlgorithms []string) (*gojwt.Token, []string, error) {
	t, parts, err := gojwt.NewParser().ParseUnverified(raw, gojwt.MapClaims{})
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse signed token: %w", err)
	}

	// Enforce the algorithm allowlist: ParseUnverified does not apply
	// WithValidMethods, so the check is done manually here.
	alg := t.Method.Alg()
	supported := false
	for _, a := range supportedAlgorithms {
		if a == alg {
			supported = true
			break
		}
	}
	if !supported {
		return nil, nil, fmt.Errorf("token signed with unsupported algorithm %q", alg)
	}

	// No error
	return t, parts, nil
}

// decodeClaims base64-decodes parts[1] and unmarshals into claims.
func decodeClaims(parts []string, claims any) error {
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("unable to decode token claims: %w", err)
	}
	if err := json.Unmarshal(payload, claims); err != nil {
		return fmt.Errorf("unable to unmarshal token claims: %w", err)
	}
	return nil
}

// verifyWithKey cryptographically verifies token (from parseUnverified)
// against a materialized public key.
func verifyWithKey(t *gojwt.Token, parts []string, publicKey any) error {
	if err := t.Method.Verify(parts[0]+"."+parts[1], t.Signature, publicKey); err != nil {
		return fmt.Errorf("unable to verify token signature: %w", err)
	}
	return nil
}

// DefaultVerifier declare a default JWT verifier.
func DefaultVerifier(keySetProvider jwk.KeySetProviderFunc, supportedAlgorithms []string) token.Verifier {
	return &defaultVerifier{
		keySetProvider:      keySetProvider,
		supportedAlgorithms: supportedAlgorithms,
	}
}

// -----------------------------------------------------------------------------

type defaultVerifier struct {
	keySetProvider      jwk.KeySetProviderFunc
	supportedAlgorithms []string
}

func (v *defaultVerifier) Parse(raw string) (token.Token, error) {
	// Parse JWT token
	t, parts, err := parseUnverified(raw, v.supportedAlgorithms)
	if err != nil {
		return nil, errors.New("unable to parse signed token")
	}

	// Wrap token instance
	return &tokenAdapter{
		token: t,
		parts: parts,
	}, nil
}

func (v *defaultVerifier) Verify(raw string) error {
	// Parse JWT token
	if _, _, err := parseUnverified(raw, v.supportedAlgorithms); err != nil {
		return fmt.Errorf("unable to parse signed token: %w", err)
	}

	// No error
	return nil
}

// Claims extracts claims from given raw token with verifier keyset provider.
func (v *defaultVerifier) Claims(ctx context.Context, raw string, claims any) error {
	// Parse JWT token
	t, parts, err := parseUnverified(raw, v.supportedAlgorithms)
	if err != nil {
		return fmt.Errorf("unable to parse signed token: %w", err)
	}

	// Retrieve KeySet
	jwks, err := v.keySetProvider(ctx)
	if err != nil {
		return fmt.Errorf("unable to retrieve KeySet: %w", err)
	}
	// Set all keys by default
	var keys []jwk.Key
	for i := 0; i < jwks.Len(); i++ {
		k, ok := jwks.Key(i)
		if !ok {
			continue
		}
		keys = append(keys, k)
	}

	// Check if token refer to a key
	if kid, ok := t.Header["kid"]; ok {
		if k, found := jwks.LookupKeyID(fmt.Sprintf("%v", kid)); found {
			keys = []jwk.Key{k}
		}
	}
	// Iterate on all keys to find a matching one.
	valid := false
	// For each key in keyset
	for i := range keys {
		// Extract key
		k := keys[i]

		// Check key type
		if use, ok := k.KeyUsage(); ok && use == "enc" {
			// Ignore encryption key
			continue
		}

		// Materialize public key
		publicKey, err := MaterializeSigningKey(k)
		if err != nil {
			continue
		}

		// Try to verify with current key
		if err := verifyWithKey(t, parts, publicKey); err != nil {
			continue
		}

		// Decode claims into the target object
		if err := decodeClaims(parts, claims); err != nil {
			return err
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
