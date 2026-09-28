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
	"crypto"
	"encoding/base64"
	"fmt"
	"strings"

	gojwt "github.com/golang-jwt/jwt/v5"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
)

type tokenAdapter struct {
	token *gojwt.Token
	parts []string
}

func (tw *tokenAdapter) Type() (string, error) {
	if v, ok := tw.token.Header["typ"]; ok {
		return fmt.Sprintf("%v", v), nil
	}

	return "", fmt.Errorf("unable to retrieve token type")
}

func (tw *tokenAdapter) KeyID() (string, error) {
	if v, ok := tw.token.Header["kid"]; ok {
		if s, ok := v.(string); ok {
			return s, nil
		}
	}

	return "", fmt.Errorf("unable to retrieve kid claim from header")
}

func (tw *tokenAdapter) PublicKey() (any, error) {
	k, err := embeddedKey(tw.token)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve embededded jwk from header: %w", err)
	}

	return k, nil
}

func (tw *tokenAdapter) PublicKeyThumbPrint() (string, error) {
	k, err := embeddedKey(tw.token)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve embededded jwk from header: %w", err)
	}

	// Generate thumbprint (RFC 7638)
	h, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("unable to generate embedded jwk thumbprint: %w", err)
	}

	// No error
	return base64.RawURLEncoding.EncodeToString(h), nil
}

func (tw *tokenAdapter) Algorithm() (string, error) {
	if v, ok := tw.token.Header["alg"]; ok {
		if s, ok := v.(string); ok {
			return s, nil
		}
	}

	return "", fmt.Errorf("unable to retrieve `alg` claim from header")
}

// Claims verifies the token signature against the given key and decodes
// the verified claims. Verification goes through the standard parser so
// the signature check is enforced by golang-jwt itself.
func (tw *tokenAdapter) Claims(publicKey, claims any) error {
	// Materialize the public key (a jwk.Key from PublicKey()).
	k, ok := publicKey.(jwxjwk.Key)
	if !ok {
		return fmt.Errorf("invalid public key type")
	}
	rawKey, err := MaterializeSigningKey(k)
	if err != nil {
		return fmt.Errorf("unable to materialize public key: %w", err)
	}

	// Verify through the standard parser: the signature is checked by
	// the library; claims validation (exp/nbf) stays with the caller,
	// which owns the clock (e.g. the ID-JAG verifier injects its now).
	parsed, err := gojwt.NewParser(
		gojwt.WithoutClaimsValidation(),
	).Parse(strings.Join(tw.parts, "."), func(*gojwt.Token) (any, error) {
		return rawKey, nil
	})
	if err != nil || parsed == nil || !parsed.Valid {
		return fmt.Errorf("unable to verify token signature: %w", err)
	}

	// Decode the verified claims into the target object.
	return decodeVerifiedClaims(parsed, claims)
}

// UnverifiedClaims decodes the payload without signature verification:
// the values are attacker-controlled and only usable to route key
// resolution before Claims performs the verification.
func (tw *tokenAdapter) UnverifiedClaims(claims any) error {
	return decodeClaims(tw.parts, claims)
}
