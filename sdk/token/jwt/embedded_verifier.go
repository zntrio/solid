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
	t, parts, err := decodeHeader(raw, v.supportedAlgorithms)
	if err != nil {
		return nil, errors.New("unable to parse signed token")
	}

	// Wrap token instance
	return &tokenAdapter{
		token: t,
		parts: parts,
	}, nil
}

// Verify checks the token signature against the key embedded in the
// token header.
func (v *embeddedKeyVerifier) Verify(raw string) error {
	return v.Claims(context.Background(), raw, &struct{}{})
}

// Claims verifies the token signature against the key embedded in the
// token header and extracts the verified claims.
func (v *embeddedKeyVerifier) Claims(ctx context.Context, raw string, claims any) error {
	_ = ctx

	// Parse and verify through the standard parser: the signature is
	// checked against the public key embedded in the token header.
	// WithValidMethods enforces the algorithm allowlist; the keyfunc
	// additionally requires the embedded key alg to match the token alg.
	parsed, err := gojwt.NewParser(
		gojwt.WithValidMethods(v.supportedAlgorithms),
		gojwt.WithoutClaimsValidation(),
	).Parse(raw, func(t *gojwt.Token) (any, error) {
		// The embedded key is the only trust anchor of this verifier
		// (self-asserted proofs, e.g. DPoP: RFC 9449 §4.2).
		k, errKey := embeddedKey(t)
		if errKey != nil {
			return nil, errKey
		}
		// Key algorithm must match the token alg.
		keyAlg, hasAlg := k.Algorithm()
		alg, _ := t.Header["alg"].(string)
		if !hasAlg || keyAlg.String() != alg {
			return nil, errors.New("token has an invalid key for given algorithm")
		}
		return MaterializeSigningKey(k)
	})
	if err != nil || parsed == nil || !parsed.Valid {
		return token.ErrInvalidTokenSignature
	}

	// Decode the verified claims into the target object.
	if errDecode := decodeVerifiedClaims(parsed, claims); errDecode != nil {
		return token.ErrInvalidTokenSignature
	}

	// No error
	return nil
}

func (v *embeddedKeyVerifier) ContentType() string {
	return contentTypeJWT
}
