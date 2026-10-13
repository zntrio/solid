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
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/server/storage/inmemory"
)

// TestAdversarial_ConcurrentRefreshRotationSingleWinner pins the atomic
// ConsumeIfActive rotation (RFC 9700 section 4.14.2): the same refresh
// token presented CONCURRENTLY redeems exactly once — the losers observe
// the CONSUMED state and trigger grant-family revocation, so a racing
// thief cannot keep a live descendant family.
func TestAdversarial_ConcurrentRefreshRotationSingleWinner(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, verifier, testRedirectURI))
	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, res.RefreshToken)

	// Fire N concurrent refreshes with the SAME token: exactly one must
	// succeed (the atomic consume), every other must observe CONSUMED.
	const racers = 8
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		wins    int
		replays int
	)
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, errR := h.tokenz.Token(context.Background(), refreshGrantRequest(h.issuer, client.ClientId, res.RefreshToken.Value))
			mu.Lock()
			defer mu.Unlock()
			if errR == nil && r != nil && r.Error == nil {
				wins++
			} else if r != nil && r.Error != nil {
				replays++
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, 1, wins, "exactly one racer must win the rotation (atomic consume)")
	assert.Equal(t, racers-1, replays, "every other racer must observe the consumed (replayed) token")
}

// TestAdversarial_ExchangeGrantFamilyRevocation pins the GrantId
// inheritance on exchanged tokens (RFC 9700 section 4.14.2 family scope):
// revoking the subject token's grant family reaches the exchange
// derivative.
func TestAdversarial_ExchangeGrantFamilyRevocation(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken, oidc.GrantTypeTokenExchange})

	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, verifier, testRedirectURI))
	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, res.AccessToken)
	require.NotEmpty(t, res.AccessToken.Metadata.GrantId)

	// Exchange the subject token (same audience, delegated flow not needed).
	h.authenticateClient(t, client.ClientId)
	exRes, err := h.tokenz.Token(context.Background(), exchangeRequest(h.issuer, client.ClientId, res.AccessToken.Value, "urn:example:cooperation-context"))
	require.NoError(t, err)
	require.NotNil(t, exRes.AccessToken)
	require.Equal(t, res.AccessToken.Metadata.GrantId, exRes.AccessToken.Metadata.GrantId,
		"the exchanged token must inherit the subject token's grant id")

	// Revoke the subject refresh token: family revocation must cascade to
	// the exchanged derivative.
	revRes, err := h.tokenz.Revoke(context.Background(), &tokenv1.RevokeRequest{
		Issuer: h.issuer,
		Client: &clientv1.Client{ClientId: client.ClientId},
		Token:  res.RefreshToken.Value,
	})
	require.NoError(t, err)
	require.Nil(t, revRes.Error)

	inRes, err := h.introspect(t, client.ClientId, exRes.AccessToken.Value)
	require.NoError(t, err)
	require.NotEqual(t, tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE, inRes.Token.Status,
		"family revocation must reach the exchanged derivative")
}

// TestAdversarial_RefreshTokenStatusConsumed pins the new CONSUMED status
// semantics directly at the storage layer: ConsumeIfActive is a single
// compare-and-set, concurrent claims win exactly once, and a consumed
// token keeps its pre-transition metadata (grant id) for the replay
// cascade.
func TestAdversarial_RefreshTokenStatusConsumed(t *testing.T) {
	tokens := inmemory.Tokens([]byte("consumed-test-key"))

	seed := &tokenv1.Token{
		Value:     "rt-consume-value",
		TokenId:   "rt-consume-id",
		TokenType: tokenv1.TokenType_TOKEN_TYPE_REFRESH_TOKEN,
		Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
		Metadata: &tokenv1.TokenMeta{
			GrantId: "grant-1",
			Scope:   "openid",
		},
	}
	require.NoError(t, tokens.Create(context.Background(), "http://issuer.example", seed))

	// First consume: wins, pre-transition state is ACTIVE.
	first, err := tokens.ConsumeIfActive(context.Background(), "http://issuer.example", "rt-consume-value")
	require.NoError(t, err)
	require.Equal(t, tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE, first.Status)
	require.Equal(t, "grant-1", first.Metadata.GrantId)

	// Second consume (sequential replay): loses, pre-transition state is
	// CONSUMED with intact metadata for the family cascade.
	second, err := tokens.ConsumeIfActive(context.Background(), "http://issuer.example", "rt-consume-value")
	require.NoError(t, err)
	require.Equal(t, tokenv1.TokenStatus_TOKEN_STATUS_CONSUMED, second.Status)
	require.Equal(t, "grant-1", second.Metadata.GrantId)

	// Concurrent claims on a fresh token: exactly one winner.
	seed2 := &tokenv1.Token{
		Value:     "rt-race-value",
		TokenId:   "rt-race-id",
		TokenType: tokenv1.TokenType_TOKEN_TYPE_REFRESH_TOKEN,
		Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
	}
	require.NoError(t, tokens.Create(context.Background(), "http://issuer.example", seed2))

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners int
	)
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, errR := tokens.ConsumeIfActive(context.Background(), "http://issuer.example", "rt-race-value")
			if errR == nil && got.Status == tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, 1, winners, "exactly one concurrent consumer must win")
}
