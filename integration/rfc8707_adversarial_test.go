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

	"zntr.io/solid/oidc"
)

// RFC 8707 (Resource Indicators for OAuth 2.0) adversarial coverage. The
// attacker (A3 authorization code attacker / confused deputy) controls
// resource and audience request parameters; the countermeasures under test:
//
//   - section 2: unknown resource/audience values are rejected
//     (invalid_target) before any token is minted;
//   - section 2 ("The authorization server SHOULD audience-restrict issued
//     access tokens to the resource(s) indicated by the resource
//     parameter"): the validated resource indicator — not the verbatim
//     request parameter — becomes the minted token's audience;
//   - section 2.2: refresh-request resources are limited to those
//     originally granted (subset rule);
//   - section 3 (solid stronger posture): multiple resource parameters are
//     rejected outright — the RFC only "encourages" a single resource, but a
//     multi-audience bearer token is valid at every listed resource.

// TestRFC8707_UnknownResourceAtAuthorization_2_1 asserts section 2.1: an
// authorization request carrying a resource indicator unknown to the
// registry must not yield a redeemable code — redemption fails with
// invalid_target (the attacker's URI never reaches a minted token).
func TestRFC8707_UnknownResourceAtAuthorization_2_1(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	req.Resource = []string{"https://attacker.example/"}

	code := h.seedAuthorization(t, client, req)
	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.Error(t, err, "an unknown resource indicator must fail redemption")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_target", res.Error.Error)
}

// TestRFC8707_ResourceBindsTokenAudience_2 asserts section 2: the minted
// access token's audience is the validated resource indicator, not the
// request's audience parameter — a code captured for resource A cannot be
// minted with an arbitrary aud (confused-deputy escalation).
func TestRFC8707_ResourceBindsTokenAudience_2(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	// The attacker-influencable audience parameter is ignored when a
	// resource indicator is present.
	req.Audience = "urn:example:cooperation-context"
	req.Resource = []string{"urn:example:backend-api"}

	code := h.seedAuthorization(t, client, req)
	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.Nil(t, res.Error)
	require.NotNil(t, res.AccessToken)
	require.Equal(t, "urn:example:backend-api", res.AccessToken.Metadata.Audience,
		"the aud claim must equal the validated resource indicator, not the request audience parameter")
}

// TestRFC8707_TokenRequestResourceMismatch_2_2 asserts section 2.2: on a
// token request, the acceptable resources are limited to those originally
// granted (or a subset thereof) — a registered-but-different resource B is a
// subset violation of the single-resource grant and must fail closed.
func TestRFC8707_TokenRequestResourceMismatch_2_2(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	// Grant with the cooperation-context audience.
	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	code := h.seedAuthorization(t, client, req)

	// Token request replaying the grant while requesting a different,
	// registered resource: the refresh-grant subset rule (RFC 8707
	// section 2.2) rejects it via the refresh grant after a first
	// redemption.
	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, res.RefreshToken, "offline_access with consent must mint a refresh token")

	// Refresh with a registered-but-different resource: subset violation.
	refreshReq := refreshGrantRequest(h.issuer, client.ClientId, res.RefreshToken.Value)
	refreshReq.Resource = []string{"urn:example:backend-api"}
	h.authenticateClient(t, client.ClientId)
	refreshRes, err := h.tokenz.Token(t.Context(), refreshReq)
	require.Error(t, err)
	require.NotNil(t, refreshRes.Error)
	require.Equal(t, "invalid_target", refreshRes.Error.Error,
		"a registered-but-different resource is not a subset of the granted audience")
}

// TestRFC8707_MultiResourceRejected_3 asserts section 3 (solid stronger
// posture): token and authorization requests carrying two resource
// parameters are rejected with invalid_target. RFC 8707 section 3 only
// "encourages" a single resource; solid refuses the multi-audience
// expansion because a bearer token valid at multiple resources can be used
// by any of them to access all the others.
func TestRFC8707_MultiResourceRejected_3(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	req.Resource = []string{"urn:example:backend-api", "urn:example:cooperation-context"}

	code := h.seedAuthorization(t, client, req)
	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.Error(t, err, "multiple resource indicators must be rejected")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_target", res.Error.Error)
}

// TestRFC8707_UnknownAudienceRejected_2 asserts section 2: the audience
// parameter is validated against the resource registry exactly like a
// resource indicator — an attacker-controlled audience string never lands
// verbatim in the minted token's aud claim. The positive control guards the
// registered harness fixture audience.
func TestRFC8707_UnknownAudienceRejected_2(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	// Attacker audience: unknown to the registry.
	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	req.Audience = "https://attacker.example/"
	code := h.seedAuthorization(t, client, req)
	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.Error(t, err, "an unknown audience must fail redemption")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_target", res.Error.Error)

	// Positive control: the registered fixture audience still succeeds
	// and binds the minted aud.
	verifier2, _ := newPKCEPair(t)
	code2 := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, verifier2, testRedirectURI))
	res2, err := h.redeemCode(t, client.ClientId, code2, verifier2, testRedirectURI)
	require.NoError(t, err)
	require.Nil(t, res2.Error)
	require.Equal(t, "urn:example:cooperation-context", res2.AccessToken.Metadata.Audience)
}

// TestRFC8707_RefreshAudienceInvariant_2_2 asserts section 2.2: the refresh
// grant keeps the grant-level audience — the refreshed access token
// carries the same aud, a refresh request naming the granted resource
// succeeds (subset of one), and one naming a different resource fails with
// invalid_target.
func TestRFC8707_RefreshAudienceInvariant_2_2(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	// Grant for the backend-api resource.
	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	req.Resource = []string{"urn:example:backend-api"}
	code := h.seedAuthorization(t, client, req)

	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, res.RefreshToken)
	require.Equal(t, "urn:example:backend-api", res.AccessToken.Metadata.Audience)

	// Refresh without resource: keeps the grant-level audience.
	refreshed, err := h.refresh(t, client.ClientId, res.RefreshToken.Value)
	require.NoError(t, err)
	require.Nil(t, refreshed.Error)
	require.Equal(t, "urn:example:backend-api", refreshed.AccessToken.Metadata.Audience,
		"the refreshed token must keep the grant-level audience")

	// Refresh with the granted resource: subset of one, succeeds.
	sameRes := refreshGrantRequest(h.issuer, client.ClientId, refreshed.RefreshToken.Value)
	sameRes.Resource = []string{"urn:example:backend-api"}
	h.authenticateClient(t, client.ClientId)
	sameOut, err := h.tokenz.Token(t.Context(), sameRes)
	require.NoError(t, err)
	require.Nil(t, sameOut.Error)

	// Refresh with a different registered resource: invalid_target.
	otherRes := refreshGrantRequest(h.issuer, client.ClientId, sameOut.RefreshToken.Value)
	otherRes.Resource = []string{"urn:example:cooperation-context"}
	h.authenticateClient(t, client.ClientId)
	otherOut, err := h.tokenz.Token(t.Context(), otherRes)
	require.Error(t, err)
	require.NotNil(t, otherOut.Error)
	require.Equal(t, "invalid_target", otherOut.Error.Error)
}

// TestRFC8707_ClientCredentialsAudienceValidated_2_2 asserts section 2.2 on
// the client_credentials grant: the audience parameter must resolve in the
// resource registry — an unknown audience is an invalid_target, a
// registered one is minted verbatim into aud.
func TestRFC8707_ClientCredentialsAudienceValidated_2_2(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeClientCredentials, oidc.GrantTypeAuthorizationCode})

	h.authenticateClient(t, client.ClientId)

	// Registered audience: minted.
	good := clientCredentialsRequest(h.issuer, client.ClientId, "urn:example:backend-api")
	goodRes, err := h.tokenz.Token(t.Context(), good)
	require.NoError(t, err)
	require.Nil(t, goodRes.Error)
	require.NotNil(t, goodRes.AccessToken)
	require.Equal(t, "urn:example:backend-api", goodRes.AccessToken.Metadata.Audience)

	// Unknown audience: invalid_target.
	bad := clientCredentialsRequest(h.issuer, client.ClientId, "https://attacker.example/")
	badRes, err := h.tokenz.Token(t.Context(), bad)
	require.Error(t, err)
	require.NotNil(t, badRes.Error)
	require.Equal(t, "invalid_target", badRes.Error.Error)
}
