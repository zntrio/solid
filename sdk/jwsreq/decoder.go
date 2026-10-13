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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	"zntr.io/solid/sdk/token"
	"zntr.io/solid/sdk/types"
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

	// RFC 9101 section 5: the request object JOSE header MUST use the
	// typ value for its serialization format, i.e. 'oauth-authz-req+jwt'
	// for the JWT profile (section 2.2 of the OAuth JWT profile).
	if err := d.checkTyp(value); err != nil {
		return nil, err
	}

	// Extract claims
	var claims map[string]any
	if err := d.verifier.Claims(ctx, value, &claims); err != nil {
		return nil, fmt.Errorf("unable to decode request claims: %w", err)
	}

	if err := d.validateEnvelopeClaims(claims); err != nil {
		return nil, err
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

// validateEnvelopeClaims enforces the RFC 9101 section 5 request-object
// envelope semantics on the decoded claims: REQUIRED exp (in the future),
// nbf elapsed when present (numeric, fail closed), no nested
// request/request_uri, single-valued aud equal to the issuer, and iss —
// when present — equal to the request's client_id.
func (d *tokenDecoder) validateEnvelopeClaims(claims map[string]any) error {
	// RFC 9101 section 5: the exp claim is REQUIRED in a request object.
	if _, ok := claims["exp"]; !ok {
		return fmt.Errorf("request object 'exp' claim is mandatory")
	}

	// RFC 9101 section 5: the request object MUST NOT contain nested
	// request or request_uri parameters.
	if _, ok := claims["request"]; ok {
		return fmt.Errorf("request object must not contain request or request_uri claims")
	}
	if _, ok := claims["request_uri"]; ok {
		return fmt.Errorf("request object must not contain request or request_uri claims")
	}

	// RFC 9101 section 5: the exp claim MUST be in the future at decode
	// time; the nbf claim, when present, must have elapsed.
	now := time.Now()
	if exp, ok := claims["exp"].(float64); !ok || exp <= float64(now.Unix()) {
		return fmt.Errorf("request object is expired")
	}
	if nbfRaw, ok := claims["nbf"]; ok {
		nbf, isNumber := nbfRaw.(float64)
		if !isNumber {
			// Fail closed: a non-numeric nbf claim is malformed and
			// MUST NOT be silently ignored.
			return fmt.Errorf("request object 'nbf' claim must be a numeric date")
		}
		if nbf > float64(now.Unix()) {
			return fmt.Errorf("request object not yet valid")
		}
	}

	// RFC 9101 section 5: the aud claim MUST identify the authorization
	// server as the intended audience of the request object; the JSON Web
	// Token profile permits the array form. Solid stricter posture
	// (security-topics 2.1.2 parity with client assertions): a
	// multi-valued aud array is rejected — exactly-one audience, matching
	// the issuer.
	if !audClaimIsSingle(claims["aud"], d.expectedIssuer) {
		return fmt.Errorf("request object 'aud' claim must equal '%s'", d.expectedIssuer)
	}

	// RFC 9101 section 5: the iss claim identifies the client that
	// presented the request object. When present it MUST match the
	// request's client_id (the caller resolves and re-checks the client
	// binding; this gate closes the claim-level mismatch).
	if issRaw, ok := claims["iss"]; ok {
		iss, isStr := issRaw.(string)
		if !isStr {
			return fmt.Errorf("request object 'iss' claim must be a string")
		}
		if cid, ok := claims["client_id"].(string); ok && cid != "" && !types.SecureCompareString(iss, cid) {
			return fmt.Errorf("request object 'iss' claim must equal 'client_id'")
		}
	}
	return nil
}

// checkTyp verifies the JOSE header 'typ' of the compact-encoded request
// object without trusting its signature: the header selects the profile the
// verifier should apply, so a mismatched typ is rejected before any claim
// processing (RFC 9101 section 5, JWT profile section 2.2).
func (d *tokenDecoder) checkTyp(raw string) error {
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return fmt.Errorf("request object is not a valid compact JWS")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("unable to decode request object JOSE header: %w", err)
	}
	var header struct {
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return fmt.Errorf("unable to parse request object JOSE header: %w", err)
	}
	expected := token.HeaderType(token.TypeAuthzRequest, d.verifier.ContentType())
	if header.Typ != expected {
		return fmt.Errorf("request object 'typ' header value must be '%s'", expected)
	}
	return nil
}

// stripEnvelopeClaims removes the JOSE envelope claims that have no
// AuthorizationRequest representation (validated by the caller).
func stripEnvelopeClaims(claims map[string]any) map[string]any {
	for _, claim := range []string{"aud", "exp", "nbf", "iat", "jti", "iss"} {
		delete(claims, claim)
	}
	return claims
}

// audClaimIsSingle reports whether the aud claim — a string, or per the
// JSON Web Token profile an array of strings — is exactly the expected
// issuer (RFC 9101 section 5; multi-valued audiences are rejected).
func audClaimIsSingle(aud any, expected string) bool {
	switch v := aud.(type) {
	case string:
		return types.SecureCompareString(v, expected)
	case []any:
		// Single-element array form is accepted; a multi-valued aud is
		// rejected (the request object is addressed to exactly one
		// authorization server).
		if len(v) == 1 {
			if s, ok := v[0].(string); ok {
				return types.SecureCompareString(s, expected)
			}
		}
	}
	return false
}
