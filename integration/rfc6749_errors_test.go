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

// RFC 6749 (OAuth 2.0 Core) error-code adversarial coverage, section 5.2.

// TestRFC6749_UnsupportedGrantType_5_2 asserts an unknown grant_type string
// yields unsupported_grant_type — the RFC-correct code — not invalid_grant
// (RFC 6749 section 5.2).
func TestRFC6749_UnsupportedGrantType_5_2(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	for _, grantType := range []string{"password", "client_credentials_mtls", "garbage"} {
		t.Run("grant_type="+grantType, func(t *testing.T) {
			h.authenticateClient(t, client.ClientId)
			res, err := h.tokenz.Token(t.Context(), &flowv1.TokenRequest{
				Issuer:    h.issuer,
				GrantType: grantType,
				Client:    &clientv1.Client{ClientId: client.ClientId},
				Grant: &flowv1.TokenRequest_ClientCredentials{
					ClientCredentials: &flowv1.GrantClientCredentials{},
				},
			})
			require.Error(t, err)
			require.NotNil(t, res.Error)
			require.Equal(t, "unsupported_grant_type", res.Error.Err)
		})
	}
}

// TestRFC6749_UnauthorizedClient_5_2 asserts a client registered without a
// grant type gets unauthorized_client when using it (RFC 6749 section 5.2).
func TestRFC6749_UnauthorizedClient_5_2(t *testing.T) {
	h := newHarness(t)
	// Registered for authorization_code only.
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode})

	h.authenticateClient(t, client.ClientId)
	res, err := h.tokenz.Token(t.Context(), &flowv1.TokenRequest{
		Issuer:    h.issuer,
		GrantType: oidc.GrantTypeRefreshToken,
		Client:    &clientv1.Client{ClientId: client.ClientId},
		Grant: &flowv1.TokenRequest_RefreshToken{
			RefreshToken: &flowv1.GrantRefreshToken{RefreshToken: "some-refresh-token"},
		},
	})
	require.Error(t, err)
	require.NotNil(t, res.Error)
	require.Equal(t, "unauthorized_client", res.Error.Err)
}

// TestRFC6749_BlankIssuer_InvalidRequest asserts a blank or malformed issuer
// is a client-input problem (invalid_request), not a server fault
// (RFC 6749 section 5.2 / 5.1: server_error is reserved for AS faults).
func TestRFC6749_BlankIssuer_InvalidRequest(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode})

	cases := map[string]string{
		"blank issuer":  "",
		"malformed uri": "not a uri at all",
	}
	for name, issuer := range cases {
		t.Run(name, func(t *testing.T) {
			h.authenticateClient(t, client.ClientId)
			res, err := h.tokenz.Token(t.Context(), &flowv1.TokenRequest{
				Issuer:    issuer,
				GrantType: oidc.GrantTypeAuthorizationCode,
				Client:    &clientv1.Client{ClientId: client.ClientId},
				Grant: &flowv1.TokenRequest_AuthorizationCode{
					AuthorizationCode: &flowv1.GrantAuthorizationCode{
						Code:         "some-code",
						CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
						RedirectUri:  testRedirectURI,
					},
				},
			})
			require.Error(t, err)
			require.NotNil(t, res.Error)
			require.Equal(t, "invalid_request", res.Error.Err)
		})
	}
}
