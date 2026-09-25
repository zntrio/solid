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

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
)

// Attacker model A5 (token attacker, RFC 9700 section 3): steals refresh
// tokens and replays them.

// TestRFC9700_Rotation_4_14_2 asserts baseline refresh token rotation:
// each use mints a new refresh token and invalidates the presented one
// (RFC 9700 section 4.14.2).
func TestRFC9700_Rotation_4_14_2(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, verifier, testRedirectURI))
	res1, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, res1.RefreshToken)

	// Rotate once.
	res2, err := h.refresh(t, client.ClientId, res1.RefreshToken.Value)
	require.NoError(t, err)
	require.NotNil(t, res2.RefreshToken)
	require.NotEqual(t, res1.RefreshToken.Value, res2.RefreshToken.Value, "rotation must mint a fresh refresh token")

	// Replaying the rotated (now revoked) token fails.
	resReplay, err := h.refresh(t, client.ClientId, res1.RefreshToken.Value)
	require.Error(t, err, "a rotated refresh token must be refused")
	require.NotNil(t, resReplay.Error)
	require.Equal(t, "invalid_grant", resReplay.Error.Err)
}

// TestRFC9700_FamilyRevocationOnReplay_4_14_2 plays the A5 attacker who
// replays a stolen, already-rotated refresh token while the honest client
// continues with the descendant token. Per RFC 9700 section 4.14.2, reuse of
// an invalidated refresh token MUST revoke the entire grant family: the
// still-valid descendant refresh tokens and access tokens die too.
func TestRFC9700_FamilyRevocationOnReplay_4_14_2(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, verifier, testRedirectURI))
	res1, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, res1.RefreshToken)
	require.NotNil(t, res1.AccessToken)

	// Honest client rotates: RT1 -> RT2, then RT2 -> RT3.
	res2, err := h.refresh(t, client.ClientId, res1.RefreshToken.Value)
	require.NoError(t, err)
	res3, err := h.refresh(t, client.ClientId, res2.RefreshToken.Value)
	require.NoError(t, err)
	require.NotNil(t, res3.RefreshToken)

	// Attacker replays the stale RT1.
	resReplay, err := h.refresh(t, client.ClientId, res1.RefreshToken.Value)
	require.Error(t, err, "stale refresh token must be refused")
	require.NotNil(t, resReplay.Error)
	require.Equal(t, "invalid_grant", resReplay.Error.Err)

	// Family revocation: the honest client's current token (RT3 family
	// descendant) is now dead too.
	resAfter, err := h.refresh(t, client.ClientId, res3.RefreshToken.Value)
	require.Error(t, err, "family revocation must kill the descendant refresh token")
	require.NotNil(t, resAfter.Error)
	require.Equal(t, "invalid_grant", resAfter.Error.Err)

	// The access token minted from the same grant family is revoked as well.
	atRecord, err := h.tokens.GetByValue(t.Context(), h.issuer, res1.AccessToken.Value)
	require.NoError(t, err)
	require.Equal(t, tokenv1.TokenStatus_TOKEN_STATUS_REVOKED, atRecord.Status, "access tokens of the grant family must be revoked")
}

// TestRFC9700_RefreshTokenBoundToClient_2_2_2 asserts a refresh token
// minted for client A cannot be used by client B (RFC 9700 section 2.2.2:
// refresh tokens are bound to a single client).
func TestRFC9700_RefreshTokenBoundToClient_2_2_2(t *testing.T) {
	h := newHarness(t)
	clientA := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})
	clientB := h.registerConfidentialClient(t, []string{"https://client-b.example.org/cb"}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, clientA, validAuthorizationRequest(clientA.ClientId, verifier, testRedirectURI))
	res1, err := h.redeemCode(t, clientA.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, res1.RefreshToken)

	// Attacker client B replays client A's refresh token.
	res, err := h.refresh(t, clientB.ClientId, res1.RefreshToken.Value)
	require.Error(t, err, "refresh token must be bound to its issuing client")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_grant", res.Error.Err)
}

// TestRFC9700_RefreshTokenNotAnAccessToken_4_14 asserts an access token value
// cannot be redeemed through the refresh grant (prevents token-type
// confusion).
func TestRFC9700_RefreshTokenNotAnAccessToken_4_14(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, verifier, testRedirectURI))
	res1, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, res1.AccessToken)

	// Attacker presents the access token value as a refresh token.
	res, err := h.refresh(t, client.ClientId, res1.AccessToken.Value)
	require.Error(t, err, "access tokens must not be redeemable as refresh tokens")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_grant", res.Error.Err)
}
