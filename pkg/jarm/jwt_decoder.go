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

package jarm

import (
	"context"
	"fmt"
	"time"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/pkg/jwk"
	"zntr.io/solid/pkg/rfcerrors"

	"github.com/square/go-jose/v3/jwt"
)

// -----------------------------------------------------------------------------

type jwtResponseClaims struct {
	Issuer           string `json:"iss,omitempty"`
	Audience         string `json:"aud,omitempty"`
	ExpiresAt        uint64 `json:"exp,omitempty"`
	Code             string `json:"code,omitempty"`
	State            string `json:"state,omitempty"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

func (r *jwtResponseClaims) HasError() bool {
	return r.Error != ""
}

// -----------------------------------------------------------------------------

// JWTDecoder builds a JWT Response deocer instance.
func JWTDecoder(issuer string, keySetProvider jwk.KeySetProviderFunc) ResponseDecoder {
	return &jwtDecoder{
		issuer:         issuer,
		keySetProvider: keySetProvider,
	}
}

type jwtDecoder struct {
	keySetProvider jwk.KeySetProviderFunc
	issuer         string
}

func (d *jwtDecoder) Decode(ctx context.Context, audience, response string) (*corev1.AuthorizationCodeResponse, error) {
	// Retrieve key from provider
	jwks, err := d.keySetProvider(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve key from provider: %w", err)
	}
	if jwks == nil {
		return nil, fmt.Errorf("key set privoder returned nil key set")
	}
	if len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("key set provider returned an empty key list")
	}

	// Validate value
	token, err := jwt.ParseSigned(response)
	if err != nil {
		return nil, fmt.Errorf("unable to decode response value as a valid JWT: %w", err)
	}

	// Claims
	var claims jwtResponseClaims
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
		if err := token.Claims(k, &claims); err != nil {
			continue
		}

		// Found a valid key
		valid = true
		break
	}
	if !valid {
		return nil, fmt.Errorf("unable to validate response token, no valid public key found")
	}

	// Decode claims
	if claims.HasError() {
		return &corev1.AuthorizationCodeResponse{
			Error: &corev1.Error{
				Err:              claims.Error,
				ErrorDescription: claims.ErrorDescription,
				ErrorUri:         claims.ErrorURI,
			},
		}, nil
	}

	// Check claims
	if claims.Issuer != d.issuer {
		return &corev1.AuthorizationCodeResponse{
			Error: rfcerrors.InvalidToken(),
		}, fmt.Errorf("invalid response token, '%s' does not match expected issuer", claims.Issuer)
	}

	if claims.Audience != audience {
		return &corev1.AuthorizationCodeResponse{
			Error: rfcerrors.InvalidToken(),
		}, fmt.Errorf("invalid response token, '%s' does not match expected audience", claims.Audience)
	}

	if claims.ExpiresAt < uint64(time.Now().Unix()) {
		return &corev1.AuthorizationCodeResponse{
			Error: rfcerrors.InvalidToken(),
		}, fmt.Errorf("invalid response, response token is expired")
	}

	// No error
	return &corev1.AuthorizationCodeResponse{
		Code:  claims.Code,
		State: claims.State,
	}, nil
}
