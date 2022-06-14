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

	"gopkg.in/square/go-jose.v2/jwt"

	"zntr.io/solid/sdk/token"
	"zntr.io/solid/sdk/types"
)

// EmbeddedKeyVerifier declare an embedded Key JWT verifier.
func EmbeddedKeyVerifier(supportedAlgorithms []string) token.Verifier {
	return &embeddedKeyVerifier{
		supportedAlgorithms: types.StringArray(supportedAlgorithms),
	}
}

// -----------------------------------------------------------------------------

type embeddedKeyVerifier struct {
	supportedAlgorithms types.StringArray
}

func (v *embeddedKeyVerifier) Parse(token string) (token.Token, error) {
	// Parse JWT token
	t, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, errors.New("unable to parse signed token")
	}

	// Wrap token instance
	return &tokenAdapter{
		token: t,
	}, nil
}

func (v *embeddedKeyVerifier) Verify(token string) error {
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

	// Validate embedded key existence
	k := t.Headers[0].JSONWebKey
	if k == nil {
		return errors.New("token has no embedded public key")
	}

	// Ensure key algorithm alignment
	if k.Algorithm != alg {
		return errors.New("token has an invalid key for given algorithm")
	}

	// No error
	return nil
}

// Claims extracts claims from given raw token with verifier keyset provider.
func (v *embeddedKeyVerifier) Claims(ctx context.Context, raw string, claims any) error {
	// Parse JWT token
	t, err := jwt.ParseSigned(raw)
	if err != nil {
		return fmt.Errorf("unable to parse signed token: %w", err)
	}

	// Get embedded key.
	embeddedJwk := t.Headers[0].JSONWebKey

	// Try to verify with current key
	if err := t.Claims(embeddedJwk, claims); err != nil {
		return token.ErrInvalidTokenSignature
	}

	// No error
	return nil
}
