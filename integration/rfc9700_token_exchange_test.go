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
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	"zntr.io/solid/oidc"
)

// Attacker model A1/A5 (RFC 9700 section 3) targeting token exchange
// (RFC 8693) audience restrictions (RFC 9700 section 4.10.2: audience
// restricted tokens).

// exchangeRequest builds a TokenRequest for the token exchange grant.
func exchangeRequest(issuer, clientID, subjectToken, audience string) *flowv1.TokenRequest {
	return &flowv1.TokenRequest{
		Issuer:    issuer,
		GrantType: oidc.GrantTypeTokenExchange,
		Client:    &clientv1.Client{ClientId: clientID},
		Audience:  &audience,
		Grant: &flowv1.TokenRequest_TokenExchange{
			TokenExchange: &flowv1.GrantTokenExchange{
				SubjectToken:     subjectToken,
				SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
			},
		},
	}
}

// TestRFC9700_TokenExchangeAudienceRestriction_4_10_2 asserts the exchanged
// token's audience is restricted to the requested resource and differs from
// tokens minted for other audiences (RFC 9700 section 4.10.2).
func TestRFC9700_TokenExchangeAudienceRestriction_4_10_2(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken, oidc.GrantTypeTokenExchange})

	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, verifier, testRedirectURI))
	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, res.AccessToken)

	// Exchange for the first audience.
	h.authenticateClient(t, client.ClientId)
	exResA, err := h.tokenz.Token(t.Context(), exchangeRequest(h.issuer, client.ClientId, res.AccessToken.Value, "urn:example:cooperation-context"))
	require.NoError(t, err)
	require.NotNil(t, exResA.AccessToken)
	require.Equal(t, "urn:example:cooperation-context", exResA.AccessToken.Metadata.Audience)

	// Exchange for the second audience.
	exResB, err := h.tokenz.Token(t.Context(), exchangeRequest(h.issuer, client.ClientId, res.AccessToken.Value, "urn:example:backend-api"))
	require.NoError(t, err)
	require.NotNil(t, exResB.AccessToken)
	require.Equal(t, "urn:example:backend-api", exResB.AccessToken.Metadata.Audience)

	// The two minted tokens are audience-distinct: a token for audience A
	// must not carry audience B (the resource server for B can distinguish
	// and refuse it).
	require.NotEqual(t, exResA.AccessToken.Metadata.Audience, exResB.AccessToken.Metadata.Audience)
}

// TestRFC9700_TokenExchangeUnknownAudience_4_10_2 asserts an exchange
// request for an unregistered audience is rejected.
func TestRFC9700_TokenExchangeUnknownAudience_4_10_2(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken, oidc.GrantTypeTokenExchange})

	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, verifier, testRedirectURI))
	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)

	h.authenticateClient(t, client.ClientId)
	exRes, err := h.tokenz.Token(t.Context(), exchangeRequest(h.issuer, client.ClientId, res.AccessToken.Value, "urn:attacker:fake-resource"))
	require.Error(t, err, "unknown audience must be rejected")
	require.NotNil(t, exRes.Error)
}

// TestRFC9700_TokenExchangeSubjectTokenTypeEnforced asserts a refresh token
// cannot be smuggled through token exchange as a subject_token (token-type
// confusion).
func TestRFC9700_TokenExchangeSubjectTokenTypeEnforced(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken, oidc.GrantTypeTokenExchange})

	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, verifier, testRedirectURI))
	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, res.RefreshToken)

	// Attacker presents the refresh token as subject_token.
	h.authenticateClient(t, client.ClientId)
	exRes, err := h.tokenz.Token(t.Context(), exchangeRequest(h.issuer, client.ClientId, res.RefreshToken.Value, "urn:example:cooperation-context"))
	require.Error(t, err, "refresh tokens must not be exchangable as access tokens")
	require.NotNil(t, exRes.Error)
}
