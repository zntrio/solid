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
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/server/storage/inmemory"
)

// TestAdversarial_ConcurrentProofBurn pins the atomic jti single-use burn:
// the same DPoP proof (identical jti) presented concurrently must succeed
// exactly once across all racing verifications (RFC 9449 section 4.3).
func TestAdversarial_ConcurrentProofBurn(t *testing.T) {
	proofs := inmemory.DPoPProofs()
	cleanupStores(t, proofs)
	key := "concurrent-burn-jti"

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		successes int
	)
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := proofs.RegisterIfAbsent(context.Background(), key)
			assert.NoError(t, err)
			if ok {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, 1, successes, "atomic claim: exactly one racing presentation must win the jti burn")
}

// TestAdversarial_SequentialProofBurnReplay pins that a burned jti stays
// burned for the retention window: the second sequential presentation of
// the same proof is a replay.
func TestAdversarial_SequentialProofBurnReplay(t *testing.T) {
	proofs := inmemory.DPoPProofs()
	cleanupStores(t, proofs)

	first, err := proofs.RegisterIfAbsent(context.Background(), "sequential-burn-jti")
	require.NoError(t, err)
	require.True(t, first, "first presentation must claim the jti")

	second, err := proofs.RegisterIfAbsent(context.Background(), "sequential-burn-jti")
	require.NoError(t, err)
	require.False(t, second, "second presentation of the same jti is a replay")
}

// TestAdversarial_RefreshDPoPKeyContinuity pins RFC 9449 section 8: a
// DPoP-bound refresh token must be refreshed under the same key. Presenting
// no confirmation, or a foreign one, is a proof-of-possession failure.
func TestAdversarial_RefreshDPoPKeyContinuity(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, verifier, testRedirectURI))
	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, res.RefreshToken, "code grant with offline_access must mint a refresh token")

	// No confirmation at all.
	none := refreshGrantRequest(h.issuer, client.ClientId, res.RefreshToken.Value)
	none.TokenConfirmation = nil
	h.authenticateClient(t, client.ClientId)
	noneRes, err := h.tokenz.Token(context.Background(), none)
	require.Error(t, err, "refresh of a DPoP-bound token without a confirmation must fail")
	require.NotNil(t, noneRes.Error)
	require.Equal(t, "invalid_grant", noneRes.Error.Error)

	// A fresh code so the RT is active again (the failed attempt above does
	// not consume it, but rotate state deterministically).
	verifier2, _ := newPKCEPair(t)
	code2 := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, verifier2, testRedirectURI))
	res2, err := h.redeemCode(t, client.ClientId, code2, verifier2, testRedirectURI)
	require.NoError(t, err)

	// Foreign key: a syntactically valid but different jkt.
	foreign := refreshGrantRequest(h.issuer, client.ClientId, res2.RefreshToken.Value)
	foreign.TokenConfirmation = &tokenv1.TokenConfirmation{Jkt: "1ZCat6lh5RWAddz9W0j43PFtzl6Ph2K54NfLxQXT2M9"}
	h.authenticateClient(t, client.ClientId)
	foreignRes, err := h.tokenz.Token(context.Background(), foreign)
	require.Error(t, err, "refresh under a different DPoP key must fail (key continuity)")
	require.NotNil(t, foreignRes.Error)
	require.Equal(t, "invalid_grant", foreignRes.Error.Error)
}

// TestAdversarial_TokenExchangeDetailsEscalation pins RFC 9396 section 6 on
// the exchange grant: authorization_details requested at exchange time
// must be a subset of the subject token's consented set — arbitrary
// privilege escalation through exchange is rejected.
func TestAdversarial_TokenExchangeDetailsEscalation(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeTokenExchange})

	// Subject token consented to payment_initiation only.
	verifier, _ := newPKCEPair(t)
	seed := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	seed.AuthorizationDetails = []*tokenv1.AuthorizationDetail{
		{Type: "payment_initiation", Actions: []string{"read"}, Datatypes: []string{"transaction"}},
	}
	code := h.seedAuthorization(t, client, seed)
	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, res.AccessToken)

	// Exchange requesting an entry the subject never consented to.
	escalation := &flowv1.TokenRequest{
		Issuer:    h.issuer,
		GrantType: oidc.GrantTypeTokenExchange,
		Client:    &clientv1.Client{ClientId: client.ClientId},
		Audience:  new("urn:example:cooperation-context"),
		AuthorizationDetails: []*tokenv1.AuthorizationDetail{
			{Type: "payment_initiation", Actions: []string{"read", "write"}, Datatypes: []string{"transaction"}},
		},
		Grant: &flowv1.TokenRequest_TokenExchange{
			TokenExchange: &flowv1.GrantTokenExchange{
				SubjectToken:     res.AccessToken.Value,
				SubjectTokenType: oidc.TokenExchangeAccessTokenType,
			},
		},
		TokenConfirmation: &tokenv1.TokenConfirmation{Jkt: integrationDPoPJkt},
	}
	h.authenticateClient(t, client.ClientId)
	escRes, err := h.tokenz.Token(context.Background(), escalation)
	require.Error(t, err, "exchange requesting beyond the consented details must fail")
	require.NotNil(t, escRes.Error)
	require.Equal(t, "invalid_authorization_details", escRes.Error.Error)
}
