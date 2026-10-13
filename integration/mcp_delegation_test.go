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
	"testing"

	"github.com/stretchr/testify/require"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/token/verifiable"
	"zntr.io/solid/server/services/token"
)

// mcpToolResource matches the in-memory MCP tool server resource
// indicator (examples/mcpserver): the delegation policy's key.
const mcpToolResource = "http://127.0.0.1:8090"

// backendResource matches the in-memory backend resource indicator
// (examples/resourceserver): the second hop's audience.
const backendResource = "http://127.0.0.1:8085"

// Delegated re-delegation coverage (RFC 8693 may_act + the agentclient →
// mcpserver → resourceserver topology): the delegation policy mints
// may_act at issuance, a may_act-listed client re-binds the confirmation
// to its own proof key, and the two-hop act chain is preserved.

// delegatingHarness returns a harness whose token service wires the
// demo delegation policy: tokens minted for the MCP resource carry
// may_act = [the MCP client].
func delegatingHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t)
	accessTokens := verifiable.Token(verifiable.UUIDv7Source(), []byte("integration-at-mac-key"))
	refreshTokens := verifiable.Token(verifiable.UUIDv7Source(), []byte("integration-rt-mac-key"))
	h.tokenz = token.NewWithOptions(accessTokens, refreshTokens, h.clients, h.authSessions, h.deviceSessions, h.backchannelSessions, h.tokens, h.resources,
		token.WithDelegationPolicy(staticTestDelegationPolicy{
			mcpToolResource: {"mcp-delegation-client"},
		}),
	)
	return h
}

// staticTestDelegationPolicy is a fixed map-backed delegation policy.
type staticTestDelegationPolicy map[string][]string

func (p staticTestDelegationPolicy) MayRedelegate(_ context.Context, resourceURI string) ([]string, error) {
	return p[resourceURI], nil
}

// delegationExchange drives a token-exchange request with the given
// audience, subject and actor tokens and confirmation.
func delegationExchange(t *testing.T, h *harness, clientID, audience, subject, actor, jkt string) (*flowv1.TokenResponse, error) {
	t.Helper()

	actorType := oidc.TokenExchangeAccessTokenType
	h.authenticateClient(t, clientID)
	return h.tokenz.Token(t.Context(), &flowv1.TokenRequest{
		Issuer:    h.issuer,
		GrantType: oidc.GrantTypeTokenExchange,
		Client:    &clientv1.Client{ClientId: clientID},
		Audience:  new(audience),
		Grant: &flowv1.TokenRequest_TokenExchange{
			TokenExchange: &flowv1.GrantTokenExchange{
				SubjectToken:     subject,
				SubjectTokenType: oidc.TokenExchangeAccessTokenType,
				ActorToken:       new(actor),
				ActorTokenType:   &actorType,
			},
		},
		TokenConfirmation: &tokenv1.TokenConfirmation{Jkt: jkt},
	})
}

// TestMCPDelegation_PolicyMintsMayAct asserts hop 1: an exchange targeting
// the MCP resource under a delegation policy mints a token whose may_act
// lists the policy's re-delegator client.
func TestMCPDelegation_PolicyMintsMayAct(t *testing.T) {
	h := delegatingHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeTokenExchange})
	actorClientID := "actor-client"

	subject := craftStoredToken(t, h, func(tk *tokenv1.Token) {
		tk.Metadata.ClientId = client.ClientId
		tk.Metadata.Scope = "openid profile"
	})
	actor := craftStoredToken(t, h, func(tk *tokenv1.Token) {
		tk.Metadata.ClientId = actorClientID
		tk.Metadata.Subject = actorClientID
		tk.Metadata.Scope = "openid profile"
	})

	res, err := delegationExchange(t, h, client.ClientId, mcpToolResource, subject.Value, actor.Value, integrationDPoPJkt)
	require.NoError(t, err)
	require.NotNil(t, res.AccessToken)
	require.Len(t, res.AccessToken.MayAct, 1, "the delegation policy's re-delegator must be listed in may_act")
	require.Equal(t, "mcp-delegation-client", res.AccessToken.MayAct[0].Subject)
}

// TestMCPDelegation_TwoHopChainAndReBind asserts the full delegated
// re-delegation: the MCP client (listed in T3's may_act) re-binds the
// confirmation to its own proof key, and the issued token's act chain
// records [mcp, agent] — the immediate actor plus the subject token's
// chain, no dropped hops.
func TestMCPDelegation_TwoHopChainAndReBind(t *testing.T) {
	h := delegatingHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeTokenExchange})
	mcp := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeClientCredentials, oidc.GrantTypeTokenExchange})
	mcpClientID := mcp.ClientId

	// T3: delegated to the MCP resource, may_act = [mcp], act = [agent],
	// bound to the agent key.
	t3 := craftStoredToken(t, h, func(tk *tokenv1.Token) {
		tk.Metadata.ClientId = client.ClientId
		tk.Metadata.Scope = "openid timestamp:read"
		tk.Metadata.Audience = mcpToolResource
		tk.MayAct = []*tokenv1.Actor{{Subject: mcpClientID}}
		tk.Confirmation = &tokenv1.TokenConfirmation{Jkt: integrationDPoPJkt}
		tk.Actor = []*tokenv1.Actor{{Subject: client.ClientId}}
	})
	// The MCP client's own client_credentials token (sub = its client id).
	mcpActor := craftStoredToken(t, h, func(tk *tokenv1.Token) {
		tk.Metadata.ClientId = mcpClientID
		tk.Metadata.Subject = mcpClientID
		tk.Metadata.Scope = "openid"
	})

	// Hop 2: the MCP client re-delegates toward the backend resource,
	// proving possession with its own key.
	res, err := delegationExchange(t, h, mcpClientID, backendResource, t3.Value, mcpActor.Value, "mcpProofJktValue1234567890abcdefghijdDeFf12")
	require.NoError(t, err, "a may_act-listed client re-delegating with its own proof must succeed")
	require.NotNil(t, res.AccessToken)

	// The confirmation is re-bound to the MCP server's proof key, not
	// inherited from the subject token.
	require.NotNil(t, res.AccessToken.Confirmation)
	require.Equal(t, "mcpProofJktValue1234567890abcdefghijdDeFf12", res.AccessToken.Confirmation.Jkt, "the re-delegated token must carry the re-delegator's proof key")

	// The act chain records [mcp, agent] — immediate actor plus the
	// subject token's chain.
	require.Len(t, res.AccessToken.Actor, 2, "act chain = immediate actor + subject token's chain")
	require.Equal(t, mcpClientID, res.AccessToken.Actor[0].Subject)
	require.Equal(t, client.ClientId, res.AccessToken.Actor[1].Subject)

	// The subject stays the delegating user.
	require.Equal(t, t3.Metadata.Subject, res.AccessToken.Metadata.Subject)
}

// TestMCPDelegation_ThiefFailsClosed asserts the theft case: a client NOT
// listed in the subject token's may_act cannot re-delegate even with its
// own valid actor token and DPoP proof — the strict confirmation path
// rejects the proof-key mismatch.
func TestMCPDelegation_ThiefFailsClosed(t *testing.T) {
	h := delegatingHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeTokenExchange})
	thief := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeClientCredentials, oidc.GrantTypeTokenExchange})
	thiefClientID := thief.ClientId

	// A stolen T3 (bound to the agent key, may_act = [mcp]).
	t3 := craftStoredToken(t, h, func(tk *tokenv1.Token) {
		tk.Metadata.ClientId = client.ClientId
		tk.Metadata.Scope = "openid timestamp:read"
		tk.Metadata.Audience = mcpToolResource
		tk.MayAct = []*tokenv1.Actor{{Subject: "mcp-delegation-client"}}
		tk.Confirmation = &tokenv1.TokenConfirmation{Jkt: integrationDPoPJkt}
	})
	// The thief's own actor token.
	thiefActor := craftStoredToken(t, h, func(tk *tokenv1.Token) {
		tk.Metadata.ClientId = thiefClientID
		tk.Metadata.Subject = thiefClientID
		tk.Metadata.Scope = "openid"
	})

	// The thief is not in may_act: the presented actor is rejected before
	// any re-bind decision (may_act gates the acting party, RFC 8693
	// section 5).
	_, err := delegationExchange(t, h, thiefClientID, backendResource, t3.Value, thiefActor.Value, "attacker-proof-jkt")
	require.Error(t, err, "a non-may_act actor must not re-delegate a stolen token")
}

// TestMCPDelegation_ReDelegationWithoutProofFailsClosed asserts the
// fail-closed proof requirement: the may_act-listed client itself cannot
// re-delegate without presenting a DPoP proof — the re-bind path never
// mints an unbound token.
func TestMCPDelegation_ReDelegationWithoutProofFailsClosed(t *testing.T) {
	h := delegatingHarness(t)
	mcp := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeClientCredentials, oidc.GrantTypeTokenExchange})
	mcpClientID := mcp.ClientId

	// T3 with may_act = [mcp].
	t3 := craftStoredToken(t, h, func(tk *tokenv1.Token) {
		tk.Metadata.ClientId = mcpClientID
		tk.Metadata.Scope = "openid timestamp:read"
		tk.Metadata.Audience = mcpToolResource
		tk.MayAct = []*tokenv1.Actor{{Subject: mcpClientID}}
		tk.Confirmation = &tokenv1.TokenConfirmation{Jkt: integrationDPoPJkt}
		tk.Actor = []*tokenv1.Actor{{Subject: "agent-client"}}
	})
	mcpActor := craftStoredToken(t, h, func(tk *tokenv1.Token) {
		tk.Metadata.ClientId = mcpClientID
		tk.Metadata.Subject = mcpClientID
		tk.Metadata.Scope = "openid"
	})

	// No proof presented: the exchange must fail closed.
	actorType := oidc.TokenExchangeAccessTokenType
	h.authenticateClient(t, mcpClientID)
	res, err := h.tokenz.Token(t.Context(), &flowv1.TokenRequest{
		Issuer:    h.issuer,
		GrantType: oidc.GrantTypeTokenExchange,
		Client:    &clientv1.Client{ClientId: mcpClientID},
		Audience:  new(backendResource),
		Grant: &flowv1.TokenRequest_TokenExchange{
			TokenExchange: &flowv1.GrantTokenExchange{
				SubjectToken:     t3.Value,
				SubjectTokenType: oidc.TokenExchangeAccessTokenType,
				ActorToken:       new(mcpActor.Value),
				ActorTokenType:   &actorType,
			},
		},
	})
	require.Error(t, err, "may_act re-delegation without a DPoP proof must fail closed")
	require.Nil(t, res.AccessToken, "no token may be minted without proof of possession")
}

// TestMCPDelegation_NoPolicyNoMayAct asserts the default posture: without
// a wired delegation policy, exchanged tokens carry no may_act — no
// re-delegation is authorized anywhere.
func TestMCPDelegation_NoPolicyNoMayAct(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeTokenExchange})

	subject := craftStoredToken(t, h, func(tk *tokenv1.Token) {
		tk.Metadata.ClientId = client.ClientId
		tk.Metadata.Scope = "openid profile"
	})
	actor := craftStoredToken(t, h, func(tk *tokenv1.Token) {
		tk.Metadata.ClientId = client.ClientId
		tk.Metadata.Subject = client.ClientId
		tk.Metadata.Scope = "openid profile"
	})

	res, err := delegationExchange(t, h, client.ClientId, mcpToolResource, subject.Value, actor.Value, integrationDPoPJkt)
	require.NoError(t, err)
	require.NotNil(t, res.AccessToken)
	require.Empty(t, res.AccessToken.MayAct, "without a delegation policy no may_act is minted")
}
