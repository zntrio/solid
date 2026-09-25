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

package jwsreq

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	"zntr.io/solid/sdk/token"
)

// -----------------------------------------------------------------------------

// AuthorizationRequestDecoder returns an authorization request decoder
// instance. The expectedIssuer value identifies this authorization server:
// per RFC 9101 section 5, the request object aud claim MUST match it and
// the exp claim MUST be present.
func AuthorizationRequestDecoder(verifier token.Verifier, expectedIssuer string) AuthorizationDecoder {
	return &tokenDecoder{
		verifier:       verifier,
		expectedIssuer: expectedIssuer,
	}
}

type tokenDecoder struct {
	verifier       token.Verifier
	expectedIssuer string
}

func (d *tokenDecoder) Decode(ctx context.Context, value string) (*flowv1.AuthorizationRequest, error) {
	// Check arguments
	if value == "" {
		return nil, fmt.Errorf("value must not be blank")
	}

	// Extract claims
	var claims map[string]any
	if err := d.verifier.Claims(ctx, value, &claims); err != nil {
		return nil, fmt.Errorf("unable to decode request claims: %w", err)
	}

	// RFC 9101 section 5: the exp claim is REQUIRED in a request object.
	if _, ok := claims["exp"]; !ok {
		return nil, fmt.Errorf("request object 'exp' claim is mandatory")
	}

	// RFC 9101 section 5: the request object MUST NOT contain nested
	// request or request_uri parameters.
	if _, ok := claims["request"]; ok {
		return nil, fmt.Errorf("request object must not contain request or request_uri claims")
	}
	if _, ok := claims["request_uri"]; ok {
		return nil, fmt.Errorf("request object must not contain request or request_uri claims")
	}

	// RFC 9101 section 5: the exp claim MUST be in the future at decode
	// time; the nbf claim, when present, must have elapsed.
	now := time.Now()
	if exp, ok := claims["exp"].(float64); !ok || exp <= float64(now.Unix()) {
		return nil, fmt.Errorf("request object is expired")
	}
	if nbf, ok := claims["nbf"].(float64); ok && nbf > float64(now.Unix()) {
		return nil, fmt.Errorf("request object not yet valid")
	}

	// RFC 9101 section 5: the aud claim MUST identify the authorization
	// server as the intended audience of the request object; the JSON Web
	// Token profile permits the array form.
	if !audClaimContains(claims["aud"], d.expectedIssuer) {
		return nil, fmt.Errorf("request object 'aud' claim must equal '%s'", d.expectedIssuer)
	}

	// Re-encode to json, dropping the JOSE envelope claims that have no
	// AuthorizationRequest representation (validated above).
	claims = stripEnvelopeClaims(claims)
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(claims); err != nil {
		return nil, fmt.Errorf("unable to reencode request claims as json : %w", err)
	}

	// Verify token claims
	var req flowv1.AuthorizationRequest
	if err := protojson.Unmarshal(buf.Bytes(), &req); err != nil {
		return nil, fmt.Errorf("unable to decode request payload: %w", err)
	}

	// No error
	return &req, nil
}

// stripEnvelopeClaims removes the JOSE envelope claims that have no
// AuthorizationRequest representation (validated by the caller).
func stripEnvelopeClaims(claims map[string]any) map[string]any {
	for _, claim := range []string{"aud", "exp", "nbf", "iat", "jti", "iss"} {
		delete(claims, claim)
	}
	return claims
}

// audClaimContains reports whether the aud claim value — a string or, per
// the JSON Web Token profile, an array of strings — contains the expected
// issuer (RFC 9101 section 5).
func audClaimContains(aud any, expected string) bool {
	switch v := aud.(type) {
	case string:
		return v == expected
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}
