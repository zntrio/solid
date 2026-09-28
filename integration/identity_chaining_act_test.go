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
// specific language governing permissions and
// limitations under the License.

package integration

import (
	"testing"

	"github.com/stretchr/testify/require"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
)

// Identity chaining act/may_act coverage (draft-ietf-oauth-identity-
// chaining-17 section 2.5 / RFC 8693 sections 4.4 and 5): the act claim
// chain must survive delegation across token exchange, and may_act on the
// subject token must gate every actor in the chain.

// exchangeWithActor drives a token-exchange request with the given subject
// and actor tokens.
func exchangeWithActor(t *testing.T, h *harness, client *clientv1.Client, subject, actor string) (*flowv1.TokenResponse, error) {
	t.Helper()

	actorType := oidc.TokenExchangeAccessTokenType
	audience := "urn:example:cooperation-context"

	h.authenticateClient(t, client.ClientId)
	return h.tokenz.Token(t.Context(), &flowv1.TokenRequest{
		Issuer:    h.issuer,
		GrantType: oidc.GrantTypeTokenExchange,
		Client:    &clientv1.Client{ClientId: client.ClientId},
		Audience:  &audience,
		Grant: &flowv1.TokenRequest_TokenExchange{
			TokenExchange: &flowv1.GrantTokenExchange{
				SubjectToken:     subject,
				SubjectTokenType: oidc.TokenExchangeAccessTokenType,
				ActorToken:       &actor,
				ActorTokenType:   &actorType,
			},
		},
	})
}

// TestIdentityChainingActChainPreserved_4_4 asserts RFC 8693 section 4.4
// through the identity-chaining lens: when the actor token itself carries a
// prior act chain (a delegation of a delegation), the exchanged token must
// record the full chain — the immediate actor first, then the preserved
// prior chain in order. Delegation depth must not be lost: the Resource
// Authorization Server resolving the chain relies on its completeness
// (identity-chaining-17 section 2.5 claims transcription).
func TestIdentityChainingActChainPreserved_4_4(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken, oidc.GrantTypeTokenExchange})

	subject, _ := mintTokens(t, h, client)

	// The actor token carries a prior chain: admin acted for alice.
	actor := craftStoredToken(t, h, func(tk *tokenv1.Token) {
		tk.Metadata.ClientId = client.ClientId
		tk.Metadata.Subject = "admin"
		tk.Metadata.Scope = "openid profile"
		tk.Actor = []*tokenv1.Actor{
			{Subject: "admin", Issuer: h.issuer},
			{Subject: "alice", Issuer: h.issuer},
		}
	})

	res, err := exchangeWithActor(t, h, client, subject.Value, actor.Value)
	require.NoError(t, err)
	require.NotNil(t, res.AccessToken)
	require.NotEmpty(t, res.AccessToken.Actor, "the exchanged token must record the act chain")

	// RFC 8693 section 4.4: the immediate actor comes first, followed by
	// the prior chain in order.
	require.Len(t, res.AccessToken.Actor, 3, "full delegation chain must be preserved: immediate actor + prior chain")
	require.Equal(t, "admin", res.AccessToken.Actor[0].Subject, "the immediate actor is recorded first")
	require.Equal(t, "admin", res.AccessToken.Actor[1].Subject, "prior chain entry 1 preserved")
	require.Equal(t, "alice", res.AccessToken.Actor[2].Subject, "prior chain entry 2 preserved")

	// The subject stays the delegating user, never the actor.
	require.Equal(t, subject.Metadata.Subject, res.AccessToken.Metadata.Subject, "subject must remain the delegating end-user")
}

// TestIdentityChainingMayActGatesChainedActor_5 asserts may_act applies to
// the presented actor token's subject (RFC 8693 section 5): a subject
// token with may_act = [admin] rejects a chained delegation where the
// immediate actor is not listed, even though the ultimate principal in the
// chain might be. Authorization is evaluated against the acting party.
func TestIdentityChainingMayActGatesChainedActor_5(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken, oidc.GrantTypeTokenExchange})

	// Subject token with may_act = [admin].
	subject := craftStoredToken(t, h, func(tk *tokenv1.Token) {
		tk.Metadata.ClientId = client.ClientId
		tk.Metadata.Scope = "openid profile"
		tk.MayAct = []*tokenv1.Actor{{Subject: "admin"}}
	})

	// The immediate actor is "service" (NOT in may_act); its prior chain
	// claims it was delegated by "admin" (which IS in may_act). The
	// immediate acting party is what may_act governs: the exchange must
	// be rejected — an attacker cannot smuggle authorization via a prior
	// chain entry.
	actor := craftStoredToken(t, h, func(tk *tokenv1.Token) {
		tk.Metadata.ClientId = client.ClientId
		tk.Metadata.Subject = "service"
		tk.Metadata.Scope = "openid profile"
		tk.Actor = []*tokenv1.Actor{
			{Subject: "service", Issuer: h.issuer},
			{Subject: "admin", Issuer: h.issuer},
		}
	})

	res, err := exchangeWithActor(t, h, client, subject.Value, actor.Value)
	require.Error(t, err, "an immediate actor absent from may_act must be rejected even if a prior chain entry is listed")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_request", res.Error.Err)
}

// TestIdentityChainingActChainDepthCapped asserts the deep-delegation
// security limit: an actor token whose prior chain would push the
// resulting act chain beyond maxActChainDepth (3) is rejected fail-closed.
// Silent truncation would misrepresent the authorization history, and
// unbounded chains are a privilege-laundering vector — every hop is
// another party that may have mis-delegated.
func TestIdentityChainingActChainDepthCapped(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken, oidc.GrantTypeTokenExchange})

	subject, _ := mintTokens(t, h, client)

	// The actor carries a 4-entry prior chain: exchanging it would mint a
	// 5-entry chain (immediate actor + 4), beyond the cap of 3.
	deepActor := craftStoredToken(t, h, func(tk *tokenv1.Token) {
		tk.Metadata.ClientId = client.ClientId
		tk.Metadata.Subject = "hop-1"
		tk.Metadata.Scope = "openid profile"
		tk.Actor = []*tokenv1.Actor{
			{Subject: "hop-1", Issuer: h.issuer},
			{Subject: "hop-2", Issuer: h.issuer},
			{Subject: "hop-3", Issuer: h.issuer},
			{Subject: "hop-4", Issuer: h.issuer},
		}
	})

	res, err := exchangeWithActor(t, h, client, subject.Value, deepActor.Value)
	require.Error(t, err, "a delegation chain deeper than the cap must be rejected, not minted")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_request", res.Error.Err)
	require.Nil(t, res.AccessToken, "no token may be issued for an over-deep chain")
}

// TestIdentityChainingMayActListedChainedActorSucceeds_5 is the positive
// control: the immediate actor IS the may_act-listed subject and carries a
// prior chain; the exchange succeeds and records the complete chain.
func TestIdentityChainingMayActListedChainedActorSucceeds_5(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken, oidc.GrantTypeTokenExchange})

	subject := craftStoredToken(t, h, func(tk *tokenv1.Token) {
		tk.Metadata.ClientId = client.ClientId
		tk.Metadata.Scope = "openid profile"
		tk.MayAct = []*tokenv1.Actor{{Subject: "admin"}}
	})

	// Immediate actor = admin (listed), prior chain: admin for alice.
	admin := craftStoredToken(t, h, func(tk *tokenv1.Token) {
		tk.Metadata.ClientId = client.ClientId
		tk.Metadata.Subject = "admin"
		tk.Metadata.Scope = "openid profile"
		tk.Actor = []*tokenv1.Actor{
			{Subject: "admin", Issuer: h.issuer},
			{Subject: "alice", Issuer: h.issuer},
		}
	})

	res, err := exchangeWithActor(t, h, client, subject.Value, admin.Value)
	require.NoError(t, err, "a may_act-listed immediate actor with a prior chain must succeed")
	require.NotNil(t, res.AccessToken)
	require.Len(t, res.AccessToken.Actor, 3, "complete chain: admin (immediate) + admin + alice (prior)")
	require.Equal(t, "admin", res.AccessToken.Actor[0].Subject)
}
