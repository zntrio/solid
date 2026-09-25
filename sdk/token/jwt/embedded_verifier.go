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
	"encoding/json"
	"errors"
	"fmt"

	gojwt "github.com/golang-jwt/jwt/v5"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token"
)

// EmbeddedKeyVerifier declare an embedded Key JWT verifier.
func EmbeddedKeyVerifier(supportedAlgorithms []string) token.Verifier {
	return &embeddedKeyVerifier{
		supportedAlgorithms: supportedAlgorithms,
	}
}

// -----------------------------------------------------------------------------

type embeddedKeyVerifier struct {
	supportedAlgorithms []string
}

// embeddedKey extracts the JWK embedded in the token header.
func embeddedKey(t *gojwt.Token) (jwxjwk.Key, error) {
	raw, ok := t.Header["jwk"]
	if !ok {
		return nil, errors.New("token has no embedded public key")
	}

	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("unable to serialize embedded public key: %w", err)
	}

	// AKP (ML-DSA) keys are not supported by jwx: decode through the
	// tolerant parser.
	kset, err := jwk.Parse(encoded)
	if err != nil {
		return nil, fmt.Errorf("unable to parse embedded public key: %w", err)
	}
	k, ok := kset.Key(0)
	if !ok {
		return nil, errors.New("token has no embedded public key")
	}

	// No error
	return k, nil
}

func (v *embeddedKeyVerifier) Parse(raw string) (token.Token, error) {
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

func (v *embeddedKeyVerifier) Verify(raw string) error {
	// Parse JWT token
	t, _, err := parseUnverified(raw, v.supportedAlgorithms)
	if err != nil {
		return fmt.Errorf("unable to parse signed token: %w", err)
	}

	// Validate algorithm
	alg, _ := t.Header["alg"].(string)

	// Validate embedded key existence
	k, err := embeddedKey(t)
	if err != nil {
		return err
	}

	// Ensure key algorithm alignment
	keyAlg, ok := k.Algorithm()
	if !ok || keyAlg.String() != alg {
		return errors.New("token has an invalid key for given algorithm")
	}

	// No error
	return nil
}

// Claims extracts claims from given raw token with verifier keyset provider.
func (v *embeddedKeyVerifier) Claims(ctx context.Context, raw string, claims any) error {
	// Parse JWT token
	t, parts, err := parseUnverified(raw, v.supportedAlgorithms)
	if err != nil {
		return fmt.Errorf("unable to parse signed token: %w", err)
	}

	// Get embedded key.
	k, err := embeddedKey(t)
	if err != nil {
		return token.ErrInvalidTokenSignature
	}

	// Materialize public key
	publicKey, err := MaterializeSigningKey(k)
	if err != nil {
		return token.ErrInvalidTokenSignature
	}

	if err := verifyWithKey(t, parts, publicKey); err != nil {
		return token.ErrInvalidTokenSignature
	}

	// Decode claims into target object
	if err := decodeClaims(parts, claims); err != nil {
		return token.ErrInvalidTokenSignature
	}

	// No error
	return nil
}
