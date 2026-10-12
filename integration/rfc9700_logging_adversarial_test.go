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

	"github.com/stretchr/testify/require"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	"zntr.io/solid/oidc"
)

// RFC 9700 section 4.15.2 (logging): the authorization server MUST NOT
// include token or credential values in logs or error chains. The solid
// posture: grant services return sanitized error chains — the internal
// error that the presentation layer logs carries the failure cause, never
// the submitted token, device code or subject token value. These tests
// drive every grant failure path that receives a secret-bearing parameter
// and assert the returned error chain is value-free.

// TestRFC9700_NoTokenValuesInErrorChains_4_15 asserts each grant failure
// path that receives a token/code value: the returned internal error
// never contains that value (the error chains feed the server logs).
func TestRFC9700_NoTokenValuesInErrorChains_4_15(t *testing.T) {
	t.Run("refresh grant unknown token", func(t *testing.T) {
		h := newHarness(t)
		client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeRefreshToken})

		const attackerToken = "attacker-probed-refresh-token-value-9700"
		h.authenticateClient(t, client.ClientId)
		_, err := h.tokenz.Token(t.Context(), refreshGrantRequest(h.issuer, client.ClientId, attackerToken))
		require.Error(t, err)
		require.False(t, strings.Contains(err.Error(), attackerToken),
			"the refresh-grant error chain must not leak the submitted token value (RFC 9700 section 4.15.2)")
	})

	t.Run("device grant expired code", func(t *testing.T) {
		h := newHarness(t)
		client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeDeviceCode})

		deviceCode, userCode := h.startDeviceAuthorization(t, client, []string{"openid"})
		h.approveDevice(t, userCode, "user-1")

		// Poll with the device code: the granted session is consumed on
		// first poll; a replay of the same code exercises the
		// unknown-code error path with the code value in hand.
		h.authenticateClient(t, client.ClientId)
		_, firstErr := h.tokenz.Token(t.Context(), deviceTokenRequest(h.issuer, client.ClientId, deviceCode))
		require.NoError(t, firstErr)

		_, replayErr := h.tokenz.Token(t.Context(), deviceTokenRequest(h.issuer, client.ClientId, deviceCode))
		require.Error(t, replayErr)
		require.False(t, strings.Contains(replayErr.Error(), deviceCode),
			"the device-grant error chain must not leak the device code value (RFC 9700 section 4.15.2)")
	})

	t.Run("token exchange unknown subject token", func(t *testing.T) {
		h := newHarness(t)
		client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeTokenExchange})

		const attackerSubjectToken = "attacker-probed-subject-token-value-9700"
		tokenType := oidc.TokenExchangeAccessTokenType
		h.authenticateClient(t, client.ClientId)
		_, err := h.tokenz.Token(t.Context(), &flowv1.TokenRequest{
			Issuer:    h.issuer,
			GrantType: oidc.GrantTypeTokenExchange,
			Client:    &clientv1.Client{ClientId: client.ClientId},
			Grant: &flowv1.TokenRequest_TokenExchange{
				TokenExchange: &flowv1.GrantTokenExchange{
					SubjectTokenType: tokenType,
					SubjectToken:     attackerSubjectToken,
				},
			},
		})
		require.Error(t, err)
		require.False(t, strings.Contains(err.Error(), attackerSubjectToken),
			"the token-exchange error chain must not leak the subject token value (RFC 9700 section 4.15.2)")
	})
}
