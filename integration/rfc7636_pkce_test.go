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
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	"zntr.io/solid/oidc"
)

// RFC 7636 (PKCE) adversarial coverage.

// TestRFC7636_VerifierCharset_4_1 asserts code verifiers containing
// characters outside the unreserved set are rejected even when their length
// is within bounds and the challenge matches (RFC 7636 section 4.1:
// verifiers use only unreserved characters).
func TestRFC7636_VerifierCharset_4_1(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	// CJK padding: 22 CJK chars (66 bytes) + ASCII padding to reach the
	// 43-byte floor — passes the byte-length bound, fails rune counting.
	cjk := strings.Repeat("世", 22)
	cases := map[string]string{
		"plus signs":    strings.Repeat("+", 43),
		"slash":         strings.Repeat("/", 43),
		"equal signs":   strings.Repeat("=", 43),
		"cjk multibyte": cjk + strings.Repeat("a", 43-utf8.RuneCountInString(cjk)),
	}

	for name, verifier := range cases {
		t.Run(name, func(t *testing.T) {
			// The attacker registers the S256 challenge OF THEIR OWN
			// malformed verifier, then redeems it.
			req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
			req.CodeChallenge = s256Challenge(verifier)
			code := h.seedAuthorization(t, client, req)

			res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
			require.Error(t, err, "malformed code_verifier must be rejected")
			require.NotNil(t, res.Error)
			// Rejected either by the protovalidate syntax layer
			// (invalid_request) or by the service-level PKCE checks
			// (invalid_grant): both are RFC 7636 conformant rejections.
			require.Contains(t, []string{"invalid_request", "invalid_grant"}, res.Error.Err)
		})
	}
}

// TestRFC7636_ChallengeCharset asserts an authorization request whose
// code_challenge contains non-unreserved characters is rejected upfront with
// invalid_request (RFC 7636 section 4.2: challenges are base64url-encoded
// values of the unreserved alphabet).
func TestRFC7636_ChallengeCharset(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	// 43 characters, but with a forbidden character.
	req.CodeChallenge = strings.Repeat("a", 21) + "=" + strings.Repeat("b", 21)

	res, err := h.authz.Authorize(t.Context(), &flowv1.AuthorizeRequest{
		Issuer:  h.issuer,
		Client:  client,
		Subject: "user-1",
		Request: req,
	})
	require.Error(t, err)
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_request", res.Error.Err)
}

// TestRFC7636_VerifierBoundary asserts the verifier length bounds are
// enforced in characters: 42 runes fails, 43 and 128 succeed, 129 fails
// (RFC 7636 section 4.1: 43 <= code_verifier <= 128).
func TestRFC7636_VerifierBoundary(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	upper := strings.Repeat("A", 64) + strings.Repeat("b", 64)

	t.Run("42 runes fails", func(t *testing.T) {
		verifier := strings.Repeat("a", 42)
		req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
		req.CodeChallenge = s256Challenge(verifier)
		code := h.seedAuthorization(t, client, req)
		res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
		require.Error(t, err)
		// Rejected either by the protovalidate syntax layer or the
		// service-level bound; both conform to RFC 7636.
		require.Contains(t, []string{"invalid_request", "invalid_grant"}, res.Error.Err)
	})

	t.Run("43 runes succeeds", func(t *testing.T) {
		verifier := strings.Repeat("a", 43)
		req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
		req.CodeChallenge = s256Challenge(verifier)
		code := h.seedAuthorization(t, client, req)
		res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
		require.NoError(t, err)
		require.NotNil(t, res.AccessToken)
	})

	t.Run("128 runes succeeds", func(t *testing.T) {
		verifier := upper
		req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
		req.CodeChallenge = s256Challenge(verifier)
		code := h.seedAuthorization(t, client, req)
		res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
		require.NoError(t, err)
		require.NotNil(t, res.AccessToken)
	})

	t.Run("129 runes fails", func(t *testing.T) {
		verifier := strings.Repeat("a", 129)
		req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
		req.CodeChallenge = s256Challenge(verifier)
		code := h.seedAuthorization(t, client, req)
		res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
		require.Error(t, err)
		require.Contains(t, []string{"invalid_request", "invalid_grant"}, res.Error.Err)
	})
}
