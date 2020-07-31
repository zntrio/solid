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
	"zntr.io/solid/pkg/sdk/jwt"
	"zntr.io/solid/pkg/sdk/rfcerrors"
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
func JWTDecoder(issuer string, verifier jwt.Verifier) ResponseDecoder {
	return &jwtDecoder{
		issuer:   issuer,
		verifier: verifier,
	}
}

type jwtDecoder struct {
	issuer   string
	verifier jwt.Verifier
}

func (d *jwtDecoder) Decode(ctx context.Context, audience, response string) (*corev1.AuthorizationCodeResponse, error) {
	// Check arguments
	if audience == "" {
		return nil, fmt.Errorf("audience must not be blank")
	}
	if response == "" {
		return nil, fmt.Errorf("response must not be blank")
	}

	// Parse response
	t, err := d.verifier.Parse(response)
	if err != nil {
		return nil, fmt.Errorf("unable to parse JARM response: %w", err)
	}

	// Check token type
	typ, err := t.Type()
	if err != nil {
		return nil, fmt.Errorf("jarm response has not a valid jwt syntax, valid 'typ' header is mandatory")
	}
	if typ != HeaderType {
		return nil, fmt.Errorf("jarm response  has not a valid jwt syntax, 'typ' header value must be '%s'", HeaderType)
	}

	// Claims
	var claims jwtResponseClaims

	// Extract claims
	if err := d.verifier.Claims(response, &claims); err != nil {
		return nil, fmt.Errorf("unable to extract claims from JARM response : %w", err)
	}

	// Decode claims
	if claims.HasError() {
		return &corev1.AuthorizationCodeResponse{
			Error: &corev1.Error{
				Err:              claims.Error,
				ErrorDescription: claims.ErrorDescription,
			},
		}, nil
	}

	// Check claims
	if claims.Issuer != d.issuer {
		return &corev1.AuthorizationCodeResponse{
			Error: rfcerrors.InvalidToken().Build(),
		}, fmt.Errorf("invalid response token, '%s' does not match expected issuer", claims.Issuer)
	}

	if claims.Audience != audience {
		return &corev1.AuthorizationCodeResponse{
			Error: rfcerrors.InvalidToken().Build(),
		}, fmt.Errorf("invalid response token, '%s' does not match expected audience", claims.Audience)
	}

	if claims.ExpiresAt < uint64(time.Now().Unix()) {
		return &corev1.AuthorizationCodeResponse{
			Error: rfcerrors.InvalidToken().Build(),
		}, fmt.Errorf("invalid response, response token is expired")
	}

	// No error
	return &corev1.AuthorizationCodeResponse{
		Code:  claims.Code,
		State: claims.State,
	}, nil
}
