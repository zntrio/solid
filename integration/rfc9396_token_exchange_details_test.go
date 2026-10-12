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
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
)

// TestRFC9396_TokenExchangeDetailsCarriedVerbatim asserts the token exchange
// grant (RFC 8693) accepts an authorization_details request parameter and
// carries it verbatim into the minted token and the token response
// (RFC 9396 sections 6 and 7). The AS applies mocked processing: no consent
// narrowing is enforced — the target resource server evaluates the entries.
func TestRFC9396_TokenExchangeDetailsCarriedVerbatim(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeTokenExchange})

	verifier, _ := newPKCEPair(t)
	seed := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	seed.AuthorizationDetails = []*tokenv1.AuthorizationDetail{
		{
			Type:      "payment_initiation",
			Locations: []string{"http://127.0.0.1:8085"},
			Actions:   []string{"timestamp:read"},
		},
	}
	code := h.seedAuthorization(t, client, seed)
	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, res.AccessToken)

	details := []*tokenv1.AuthorizationDetail{
		{
			Type:      "payment_initiation",
			Locations: []string{"http://127.0.0.1:8085"},
			Actions:   []string{"timestamp:read"},
		},
	}

	req := &flowv1.TokenRequest{
		Issuer:               h.issuer,
		GrantType:            oidc.GrantTypeTokenExchange,
		Client:               &clientv1.Client{ClientId: client.ClientId},
		Audience:             new("urn:example:cooperation-context"),
		AuthorizationDetails: details,
		Grant: &flowv1.TokenRequest_TokenExchange{
			TokenExchange: &flowv1.GrantTokenExchange{
				SubjectToken:     res.AccessToken.Value,
				SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
			},
		},
		// The subject token is DPoP-bound (minted through the enforced code
		// flow); the exchange presents the matching confirmation.
		TokenConfirmation: &tokenv1.TokenConfirmation{Jkt: integrationDPoPJkt},
	}

	h.authenticateClient(t, client.ClientId)
	exRes, err := h.tokenz.Token(t.Context(), req)
	require.NoError(t, err)
	require.NotNil(t, exRes.AccessToken)

	// The minted token carries the requested entries verbatim.
	require.Len(t, exRes.AccessToken.Metadata.AuthorizationDetails, 1)
	d := exRes.AccessToken.Metadata.AuthorizationDetails[0]
	require.Equal(t, "payment_initiation", d.Type)
	require.Equal(t, []string{"http://127.0.0.1:8085"}, d.Locations)
	require.Equal(t, []string{"timestamp:read"}, d.Actions)

	// RFC 9396 section 7: the token response echoes the granted entries.
	require.Len(t, exRes.AuthorizationDetails, 1)
	require.Equal(t, "payment_initiation", exRes.AuthorizationDetails[0].Type)

	// Introspection exposes the carried entries to the resource server.
	inRes, err := h.introspect(t, client.ClientId, exRes.AccessToken.Value)
	require.NoError(t, err)
	require.Equal(t, tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE, inRes.Token.Status)
	require.Len(t, inRes.Token.Metadata.AuthorizationDetails, 1)
	require.Equal(t, "payment_initiation", inRes.Token.Metadata.AuthorizationDetails[0].Type)
	require.Equal(t, []string{"timestamp:read"}, inRes.Token.Metadata.AuthorizationDetails[0].Actions)
}
