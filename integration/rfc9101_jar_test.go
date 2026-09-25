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

package integration

import (
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"

	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	"zntr.io/solid/oidc"
)

// RFC 9101 (JWT-Secured Authorization Requests, JAR) adversarial coverage.

// jarClaims assembles a base claim set for request objects.
func jarClaims(overrides map[string]any) map[string]any {
	now := time.Now().Unix()
	claims := map[string]any{
		"aud":   testIssuer,
		"exp":   now + 3600,
		"state": "af0ifjsldkjoijaoijoijaoidja3456789012",
		// Minimal authorization request payload.
		"scope":                 "openid profile",
		"response_type":         oidc.ResponseTypeCode,
		"client_id":             "jar-client-id",
		"redirect_uri":          testRedirectURI,
		"nonce":                 "n-0S6_WzA2Mj",
		"audience":              "urn:example:cooperation-context",
		"code_challenge":        "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
		"code_challenge_method": "S256",
		"prompt":                "consent",
	}
	for k, v := range overrides {
		claims[k] = v
	}
	return claims
}

// TestRFC9101_ExpiredRequestObject asserts a request object with a past exp
// is rejected (RFC 9101 section 5: exp is REQUIRED and bounds validity).
func TestRFC9101_ExpiredRequestObject(t *testing.T) {
	raw := signedRequestObject(t, jarClaims(map[string]any{
		"exp": time.Now().Add(-time.Hour).Unix(),
	}))
	_, err := jarDecoder().Decode(t.Context(), raw)
	require.Error(t, err, "expired request object must be rejected")
}

// TestRFC9101_NbfFuture asserts a request object with a future nbf is
// rejected (RFC 9101 section 5 / RFC 7519 nbf semantics).
func TestRFC9101_NbfFuture(t *testing.T) {
	raw := signedRequestObject(t, jarClaims(map[string]any{
		"nbf": time.Now().Add(time.Hour).Unix(),
	}))
	_, err := jarDecoder().Decode(t.Context(), raw)
	require.Error(t, err, "not-yet-valid request object must be rejected")
}

// TestRFC9101_NestedRequestUri asserts request objects carrying a nested
// request or request_uri claim are rejected (RFC 9101 section 2: MUST NOT
// be used together).
func TestRFC9101_NestedRequestUri(t *testing.T) {
	for _, claim := range []string{"request", "request_uri"} {
		t.Run("nested "+claim, func(t *testing.T) {
			raw := signedRequestObject(t, jarClaims(map[string]any{
				claim: "urn:example:nested-value",
			}))
			_, err := jarDecoder().Decode(t.Context(), raw)
			require.Error(t, err, "nested %s must be rejected", claim)
		})
	}
}

// TestRFC9101_AudArrayAccepted asserts the array form of the aud claim is
// accepted when it contains the AS issuer (RFC 9101 section 5 with RFC 7519
// aud array semantics).
func TestRFC9101_AudArrayAccepted(t *testing.T) {
	raw := signedRequestObject(t, jarClaims(map[string]any{
		"aud": []any{testIssuer, "https://other.example"},
	}))
	req, err := jarDecoder().Decode(t.Context(), raw)
	require.NoError(t, err, "array aud containing the issuer must decode")
	require.NotNil(t, req)
}

func TestRFC9101_AlgConfusion(t *testing.T) {
	// Sign with the ES256 client fixture key while the JAR verifier only
	// accepts ES384.
	privateKey, err := jwxjwk.ParseKey(clientPrivateKey)
	require.NoError(t, err)
	var rawKey any
	require.NoError(t, jwxjwk.Export(privateKey, &rawKey))

	tok := gojwt.NewWithClaims(gojwt.SigningMethodES256, gojwt.MapClaims(jarClaims(nil)))
	tok.Header["typ"] = "JWT"
	raw, err := tok.SignedString(rawKey)
	require.NoError(t, err)

	_, err = jarDecoder().Decode(t.Context(), raw)
	require.Error(t, err, "ES256-signed request object must not verify against the ES384-only allowlist")
}

// TestRFC9101_AuthorizationDetailsDecoded asserts request objects carrying
// authorization_details (RFC 9396) decode into the AuthorizationRequest:
// the parameter is carried as a request-object claim and preserved rather
// than dropped.
func TestRFC9101_AuthorizationDetailsDecoded(t *testing.T) {
	raw := signedRequestObject(t, jarClaims(map[string]any{
		"authorization_details": []any{
			map[string]any{"type": "payment_initiation", "actions": []any{"initiate"}},
		},
	}))
	req, err := jarDecoder().Decode(t.Context(), raw)
	require.NoError(t, err, "authorization_details must decode")
	require.NotNil(t, req)
	require.Len(t, req.AuthorizationDetails, 1)
	require.Equal(t, "payment_initiation", req.AuthorizationDetails[0].Type)
	require.Equal(t, []string{"initiate"}, req.AuthorizationDetails[0].Actions)
}

// TestRFC9101_ClientIdMismatch asserts the service-level invariant: the
// authenticated front-channel client must match the client_id of the
// authorization request (RFC 9101 section 5: the request object's client
// identity binds to the request).
func TestRFC9101_ClientIdMismatch(t *testing.T) {
	h := newHarness(t)
	clientA := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode})
	clientB := h.registerConfidentialClient(t, []string{testRedirectURI, "https://client-b.example.org/cb"}, []string{oidc.GrantTypeAuthorizationCode})

	verifier, _ := newPKCEPair(t)
	// The authorization request claims client A, but client B drives the
	// authorize call with its own credentials and redirect URI.
	req := validAuthorizationRequest(clientA.ClientId, verifier, testRedirectURI)
	req.RedirectUri = "https://client-b.example.org/cb"

	res, err := h.authz.Authorize(t.Context(), &flowv1.AuthorizeRequest{
		Issuer:  h.issuer,
		Client:  clientB,
		Subject: "attacker",
		Request: req,
	})
	require.Error(t, err, "request bound to another client must be rejected")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_request", res.Error.Err)
	require.NotEmpty(t, clientA.ClientId)
}
