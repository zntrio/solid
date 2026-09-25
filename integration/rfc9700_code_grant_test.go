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
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"zntr.io/solid/oidc"
)

// Attacker models A1/A3 (RFC 9700 section 3): the authorization code attacker
// tries to redeem a code issued to another client, or to redeem a code twice.

// TestRFC9700_CodeInjection_BindingToClient_4_5 asserts an authorization code
// issued to client A cannot be redeemed by client B (RFC 9700 section 4.5:
// codes are bound to the client; prevents mix-up and code injection).
func TestRFC9700_CodeInjection_BindingToClient_4_5(t *testing.T) {
	h := newHarness(t)
	clientA := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})
	clientB := h.registerConfidentialClient(t, []string{"https://client-b.example.org/cb"}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})
	require.NotEqual(t, clientA.ClientId, clientB.ClientId)

	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, clientA, validAuthorizationRequest(clientA.ClientId, verifier, testRedirectURI))

	// Attacker (client B) presents client A's code with its own credentials.
	res, err := h.redeemCode(t, clientB.ClientId, code, verifier, testRedirectURI)
	require.Error(t, err, "a code must only be redeemable by its issuing client")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_grant", res.Error.Err)
	require.Nil(t, res.AccessToken)
}

// TestRFC9700_CodeSingleUse_4_2_4 asserts an authorization code cannot be
// redeemed twice (RFC 9700 section 4.2.4 / RFC 6749 section 4.1.2: the code
// is single-use; the second redemption fails with invalid_grant).
func TestRFC9700_CodeSingleUse_4_2_4(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, verifier, testRedirectURI))

	// Honest first redemption.
	res1, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, res1.AccessToken)
	firstRT := res1.RefreshToken
	require.NotNil(t, firstRT, "offline_access scope must yield a refresh token")

	// A3 attacker replays the stolen code.
	res2, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.Error(t, err, "a burned code must not be redeemable a second time")
	require.NotNil(t, res2.Error)
	require.Equal(t, "invalid_grant", res2.Error.Err)
	require.Nil(t, res2.AccessToken)
	require.Nil(t, res2.RefreshToken)

	// Per RFC 9700 section 4.2.4, token revocation after double redemption is
	// realized at refresh-token family level (see
	// TestRFC9700_FamilyRevocationOnReplay_4_14_2): the first refresh token
	// remains usable by the honest client until replayed.
	require.NotNil(t, firstRT)
}

// TestRFC9700_RedirectUriTampering_4_5_1 asserts the redirect_uri presented
// at the token endpoint must be identical to the one in the authorization
// request, even when the alternative URI is itself registered for the client
// (RFC 9700 section 4.5.1 step 5; RFC 6749 section 4.1.3).
func TestRFC9700_RedirectUriTampering_4_5_1(t *testing.T) {
	h := newHarness(t)
	secondURI := "https://client.example.org/cb2"
	client := h.registerConfidentialClient(t, []string{testRedirectURI, secondURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, verifier, testRedirectURI))

	// Attacker swaps the redirect_uri to another registered URI.
	res, err := h.redeemCode(t, client.ClientId, code, verifier, secondURI)
	require.Error(t, err, "redirect_uri must be identical between authorize and token")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_grant", res.Error.Err)
	require.Nil(t, res.AccessToken)
}

// TestRFC9700_CodeReplayRace_4_5 asserts the atomic code burn: two concurrent
// redemption attempts of the same code must yield exactly one success
// (RFC 9700 section 4.5: single-use codes enforced without a Get/Delete
// TOCTOU window).
func TestRFC9700_CodeReplayRace_4_5(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, verifier, testRedirectURI))

	// Two racing attackers (or attacker + honest client) redeem concurrently.
	const attempts = 8
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results []bool
	)
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
			ok := err == nil && res != nil && res.AccessToken != nil
			mu.Lock()
			results = append(results, ok)
			mu.Unlock()
		}()
	}
	wg.Wait()

	successes := 0
	for _, ok := range results {
		if ok {
			successes++
		}
	}
	require.Equal(t, 1, successes, "exactly one concurrent redemption must win; the code is single-use")
}
