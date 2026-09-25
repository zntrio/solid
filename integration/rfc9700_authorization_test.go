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

	"github.com/stretchr/testify/require"

	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	"zntr.io/solid/oidc"
)

// Attacker model A1 (web attacker, RFC 9700 section 3): controls malicious
// websites and can get the resource owner to visit them.

// TestRFC9700_RedirectUriAttacks_4_1 asserts the authorization endpoint only
// accepts the exact registered redirect_uri (RFC 9700 section 4.1.3: exact
// string matching; no pattern, suffix, or substring matching).
func TestRFC9700_RedirectUriAttacks_4_1(t *testing.T) {
	attackerVariants := map[string]string{
		"prefix of registered uri pointing at attacker host": "https://client.example.org/cb.attacker.example",
		"attacker host embedding client domain":              "https://attacker.example/.somesite.example",
		"attacker subdomain lookalike":                       "https://client.example.org.attacker.example/cb",
		"trailing slash evasion":                             "https://client.example.org/cb/",
		"extra path evasion":                                 "https://client.example.org/cb/extra",
		"appended query parameter":                           "https://client.example.org/cb?redirect_to=https://attacker.example",
		"userinfo trick":                                     "https://client.example.org@attacker.example/cb",
		"different scheme":                                   "http://client.example.org/cb",
		"percent-encoded path":                               "https://client.example.org/%63b",
	}

	t.Run("rejects attacker-controlled variants", func(t *testing.T) {
		for name, attackerURI := range attackerVariants {
			t.Run(name, func(t *testing.T) {
				h := newHarness(t)
				client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})
				verifier, _ := newPKCEPair(t)

				req := validAuthorizationRequest(client.ClientId, verifier, attackerURI)
				res, err := h.authz.Authorize(t.Context(), &flowv1.AuthorizeRequest{
					Issuer:  h.issuer,
					Client:  client,
					Subject: "user-1",
					Request: req,
				})
				require.Error(t, err, "attacker redirect_uri must be rejected")
				require.NotNil(t, res.Error, "an RFC 6749 error must be surfaced")
				require.Equal(t, "invalid_request", res.Error.Err)
				require.Empty(t, res.Code, "no code must be issued to an attacker redirect_uri")
			})
		}
	})

	t.Run("accepts the exact registered uri", func(t *testing.T) {
		h := newHarness(t)
		client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})
		verifier, _ := newPKCEPair(t)

		code := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, verifier, testRedirectURI))
		require.NotEmpty(t, code)
	})
}

// TestRFC9700_ResponseTypeCodeOnly_2_1_2 asserts the implicit flow is not
// offered: response_type=token and hybrid variants are refused (RFC 9700
// section 2.1.1: authorization servers MUST NOT offer the implicit flow).
// Attacker model A1: tries to obtain tokens via front-channel response_type.
func TestRFC9700_ResponseTypeCodeOnly_2_1_2(t *testing.T) {
	for _, responseType := range []string{oidc.ResponseTypeToken, "code token", "code id_token", "id_token token"} {
		t.Run("response_type="+responseType, func(t *testing.T) {
			h := newHarness(t)
			client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})
			verifier, _ := newPKCEPair(t)

			req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
			req.ResponseType = responseType
			res, err := h.authz.Authorize(t.Context(), &flowv1.AuthorizeRequest{
				Issuer:  h.issuer,
				Client:  client,
				Subject: "user-1",
				Request: req,
			})
			require.Error(t, err, "implicit and hybrid response types must not be offered")
			require.NotNil(t, res.Error)
			require.Equal(t, "unsupported_response_type", res.Error.Err)
			require.Empty(t, res.Code)
		})
	}
}

// TestRFC9700_PkceNotOptional_2_1_1 asserts PKCE is mandatory and limited to
// S256 (RFC 9700 section 2.1.1: AS MUST support PKCE with S256; plain is not
// allowed; the challenge must be present and of sufficient length).
// Attacker model A4 (request observer) relies on weak or absent challenges.
func TestRFC9700_PkceNotOptional_2_1_1(t *testing.T) {
	authorize := func(t *testing.T, mutate func(req *flowv1.AuthorizationRequest)) (*flowv1.AuthorizeResponse, error) {
		h := newHarness(t)
		client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})
		verifier, _ := newPKCEPair(t)

		req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
		mutate(req)
		return h.authz.Authorize(t.Context(), &flowv1.AuthorizeRequest{
			Issuer: h.issuer, Client: client, Subject: "user-1", Request: req,
		})
	}

	t.Run("missing code_challenge", func(t *testing.T) {
		res, err := authorize(t, func(req *flowv1.AuthorizationRequest) { req.CodeChallenge = "" })
		require.Error(t, err)
		require.NotNil(t, res.Error)
		require.Equal(t, "invalid_request", res.Error.Err)
	})

	t.Run("plain method refused", func(t *testing.T) {
		res, err := authorize(t, func(req *flowv1.AuthorizationRequest) { req.CodeChallengeMethod = "plain" })
		require.Error(t, err)
		require.NotNil(t, res.Error)
		require.Equal(t, "invalid_request", res.Error.Err)
	})

	t.Run("challenge shorter than 43 chars", func(t *testing.T) {
		res, err := authorize(t, func(req *flowv1.AuthorizationRequest) { req.CodeChallenge = "short-challenge" })
		require.Error(t, err)
		require.NotNil(t, res.Error)
		require.Equal(t, "invalid_request", res.Error.Err)
	})
}

// TestRFC9700_PkceVerifierMismatch_4_5_3_1 plays an A3 attacker (code
// thief) who steals the authorization code but cannot guess the PKCE
// verifier: the code redemption must fail (RFC 9700 section 4.5.3.1).
func TestRFC9700_PkceVerifierMismatch_4_5_3_1(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	honestVerifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, honestVerifier, testRedirectURI))

	// Attacker redeems with a different (valid-length) verifier.
	attackerVerifier, _ := newPKCEPair(t)
	res, err := h.redeemCode(t, client.ClientId, code, attackerVerifier, testRedirectURI)
	require.Error(t, err, "PKCE verifier mismatch must fail the grant")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_grant", res.Error.Err)
	require.Nil(t, res.AccessToken, "no tokens must be issued on verifier mismatch")
	require.Nil(t, res.RefreshToken)
}

// TestRFC9700_DowngradeVerifiers_4_8_2 asserts that a session stored with
// S256 cannot be satisfied by presenting the raw challenge as a verifier
// (a plain-PKCE downgrade attempt, RFC 9700 section 4.8.2).
func TestRFC9700_DowngradeVerifiers_4_8_2(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, challenge := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	require.Equal(t, challenge, req.CodeChallenge)
	code := h.seedAuthorization(t, client, req)

	// Downgrade: present the challenge itself as the verifier.
	res, err := h.redeemCode(t, client.ClientId, code, req.CodeChallenge, testRedirectURI)
	require.Error(t, err, "raw challenge presented as verifier must fail S256 comparison")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_grant", res.Error.Err)
	require.Nil(t, res.AccessToken)
}
