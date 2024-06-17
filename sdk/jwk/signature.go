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

package jwk

import (
	"errors"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// ErrInvalidTokenSignature is raised when token is signed with a private key
// where the public key is not known by the keyset.
var ErrInvalidTokenSignature = errors.New("invalid token signature")

// ValidateToken validates given token using given JWKS.
func ValidateToken(jwks *jose.JSONWebKeySet, token *jwt.JSONWebToken, claims any) error {
	// Check parameters
	if jwks == nil {
		return errors.New("can't process nil jwks")
	}
	if len(jwks.Keys) == 0 {
		return errors.New("can't process empty jwks")
	}
	if token == nil {
		return errors.New("can't process nil token")
	}

	valid := false
	// For each key in keyset
	for i := range jwks.Keys {
		// Extract key
		k := jwks.Keys[i]

		// Check key type
		if k.Use == "enc" {
			// Ignore encryption key
			continue
		}

		// Try to verify with current key
		if err := token.Claims(k, claims); err != nil {
			continue
		}

		// Found a valid key
		valid = true
		break
	}
	if !valid {
		return ErrInvalidTokenSignature
	}

	// No error
	return nil
}

// ValidateSignature validates given token using given JWKS.
func ValidateSignature(jwks *jose.JSONWebKeySet, signature *jose.JSONWebSignature) error {
	// Check parameters
	if jwks == nil {
		return errors.New("can't process nil jwks")
	}
	if len(jwks.Keys) == 0 {
		return errors.New("can't process empty jwks")
	}
	if signature == nil {
		return errors.New("can't process nil signature")
	}

	valid := false
	// For each key in keyset
	for i := range jwks.Keys {
		// Extract key
		k := jwks.Keys[i]

		// Check key type
		if k.Use == "enc" {
			// Ignore encryption key
			continue
		}

		// Try to verify with current key
		if _, err := signature.Verify(k); err != nil {
			continue
		}

		// Found a valid key
		valid = true
		break
	}
	if !valid {
		return ErrInvalidTokenSignature
	}

	// No error
	return nil
}
