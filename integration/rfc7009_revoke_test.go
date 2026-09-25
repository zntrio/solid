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

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
)

// RFC 7009 (OAuth 2.0 Token Revocation) adversarial coverage, section
// references per RFC 7009.

// TestRFC7009_RevokeUnknownToken_2_2 asserts an unknown token is revoked
// silently: the client must not learn whether the token ever existed (RFC
// 7009 section 2.2).
func TestRFC7009_RevokeUnknownToken_2_2(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	res, err := h.revoke(t, client.ClientId, "totally-unknown-token-value")
	require.NoError(t, err, "revocation of an unknown token must be a silent success")
	require.NotNil(t, res)
	require.Nil(t, res.Error)
}

// TestRFC7009_RevokeCascadesToGrantFamily_2_1 asserts revoking a refresh
// token revokes the whole grant family: the sibling access token becomes
// inactive and the refresh token cannot be rotated (RFC 7009 section 2.1:
// the server MAY revoke related tokens; RFC 9700 section 4.14.2 mandates it
// for refresh tokens).
func TestRFC7009_RevokeCascadesToGrantFamily_2_1(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	req.Prompt = new(oidc.PromptConsent)
	code := h.seedAuthorization(t, client, req)
	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, res.RefreshToken)

	// Revoke the refresh token.
	rres, rerr := h.revoke(t, client.ClientId, res.RefreshToken.Value)
	require.NoError(t, rerr)
	require.Nil(t, rres.Error)

	// The sibling access token is now inactive.
	ires, ierr := h.introspect(t, client.ClientId, res.AccessToken.Value)
	require.NoError(t, ierr)
	require.NotEqual(t, tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE, ires.Token.Status, "access token of the revoked grant must be inactive")

	// The revoked refresh token cannot be used.
	fres, ferr := h.refresh(t, client.ClientId, res.RefreshToken.Value)
	require.Error(t, ferr, "revoked refresh token must not rotate")
	require.NotNil(t, fres.Error)
	require.Equal(t, "invalid_grant", fres.Error.Err)
}

// TestRFC7009_RevokeHintDoesNotBlock_2_1 asserts token_type_hint never
// restricts the search: revoking a refresh token with an access_token hint
// (or a garbage hint) still revokes the presented token (RFC 7009 section
// 2.1: the hint is advisory; the server MUST find the token).
func TestRFC7009_RevokeHintDoesNotBlock_2_1(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	for name, hint := range map[string]string{
		"access_token hint": "access_token",
		"garbage hint":      "jwt-and-a-kitten",
	} {
		t.Run(name, func(t *testing.T) {
			verifier, _ := newPKCEPair(t)
			req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
			req.Prompt = new(oidc.PromptConsent)
			code := h.seedAuthorization(t, client, req)
			res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
			require.NoError(t, err)
			require.NotNil(t, res.RefreshToken)

			// Revoke the refresh token with a misleading hint.
			h.authenticateClient(t, client.ClientId)
			rres, rerr := h.tokenz.Revoke(t.Context(), revokeRequestWithHint(h.issuer, client.ClientId, res.RefreshToken.Value, hint))
			require.NoError(t, rerr)
			require.Nil(t, rres.Error)

			// The refresh token was still revoked.
			_, ferr := h.refresh(t, client.ClientId, res.RefreshToken.Value)
			require.Error(t, ferr, "refresh token revoked under a misleading hint must not rotate")
		})
	}
}

// TestRFC7009_RevokeOtherClientToken_2_1 asserts a client cannot revoke
// another client's token: the request fails with invalid_client and the
// target token stays active (RFC 7009 section 2.1 ownership rule).
func TestRFC7009_RevokeOtherClientToken_2_1(t *testing.T) {
	h := newHarness(t)
	clientA := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})
	clientB := h.registerConfidentialClient(t, []string{"https://client-b.example.org/cb"}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, clientA, validAuthorizationRequest(clientA.ClientId, verifier, testRedirectURI))
	res, err := h.redeemCode(t, clientA.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, res.AccessToken)

	// Attacker (client B) tries to revoke client A's token.
	rres, rerr := h.revoke(t, clientB.ClientId, res.AccessToken.Value)
	require.Error(t, rerr, "revoking another client's token must fail")
	require.NotNil(t, rres.Error)
	require.Equal(t, "invalid_client", rres.Error.Err)

	// The token is still active for its owner.
	ires, ierr := h.introspect(t, clientA.ClientId, res.AccessToken.Value)
	require.NoError(t, ierr)
	require.Equal(t, tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE, ires.Token.Status, "target token must remain active after the failed revocation")
}

// TestRFC7009_RevokeIsSingleToken_Only asserts revoking the access token
// alone does NOT revoke the sibling refresh token: over-cascading would
// log the user out on every access-token revocation (RFC 7009 section 2.1
// permits cascade only for refresh tokens).
func TestRFC7009_RevokeIsSingleToken_Only(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	req.Prompt = new(oidc.PromptConsent)
	code := h.seedAuthorization(t, client, req)
	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, res.RefreshToken)

	// Revoke only the access token.
	rres, rerr := h.revoke(t, client.ClientId, res.AccessToken.Value)
	require.NoError(t, rerr)
	require.Nil(t, rres.Error)

	// The refresh token still rotates.
	fres, ferr := h.refresh(t, client.ClientId, res.RefreshToken.Value)
	require.NoError(t, ferr, "refresh token must survive an access-token-only revocation")
	require.NotNil(t, fres.AccessToken)
}

// revokeRequestWithHint builds a RevokeRequest carrying a token_type_hint.
func revokeRequestWithHint(issuer, clientID, tokenValue, hint string) *tokenv1.RevokeRequest {
	return &tokenv1.RevokeRequest{
		Issuer:        issuer,
		Client:        &clientv1.Client{ClientId: clientID},
		Token:         tokenValue,
		TokenTypeHint: &hint,
	}
}
