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
	"time"

	"github.com/stretchr/testify/require"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/random"
)

// RFC 7662 (OAuth 2.0 Token Introspection) adversarial coverage.

// inactiveEnvelope is the exact response shape required for inactive tokens:
// issuer, value, and a non-ACTIVE status, with no metadata (RFC 7662
// section 2.2: no cause distinction between unknown, expired, revoked).
func inactiveEnvelope(h *harness, tokenValue string) *tokenv1.Token {
	return &tokenv1.Token{
		Issuer: h.issuer,
		Value:  tokenValue,
		Status: tokenv1.TokenStatus_TOKEN_STATUS_UNKNOWN,
	}
}

// mintTokens mints an AT+RT pair via the authorization code flow.
func mintTokens(t *testing.T, h *harness, client *clientv1.Client) (*tokenv1.Token, *tokenv1.Token) {
	t.Helper()

	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	req.Prompt = new(oidc.PromptConsent)
	code := h.seedAuthorization(t, client, req)
	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, res.AccessToken)
	return res.AccessToken, res.RefreshToken
}

// craftStoredToken inserts a hand-crafted token in storage; used for states
// the flows cannot produce on demand (expired-but-stored, may_act chains).
func craftStoredToken(t *testing.T, h *harness, mutate func(*tokenv1.Token)) *tokenv1.Token {
	t.Helper()

	now := time.Now()
	at := &tokenv1.Token{
		Issuer:    h.issuer,
		TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
		TokenId:   random.String(16),
		Metadata: &tokenv1.TokenMeta{
			Issuer:    h.issuer,
			Subject:   "user-1",
			ClientId:  "craft-owner",
			IssuedAt:  uint64(now.Add(-time.Minute).Unix()),
			ExpiresAt: uint64(now.Add(time.Hour).Unix()),
			Scope:     "openid profile",
			GrantId:   random.String(16),
		},
		Status: tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
		Value:  random.String(32),
	}
	if mutate != nil {
		mutate(at)
	}
	require.NoError(t, h.tokens.Create(context.Background(), h.issuer, at))
	return at
}

// TestRFC7662_NoCauseDistinction_2_2 asserts unknown, expired, revoked and
// foreign-issuer tokens all render the same inactive envelope: the caller
// cannot distinguish why a token is inactive (RFC 7662 section 2.2).
func TestRFC7662_NoCauseDistinction_2_2(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	// Expired-but-stored fixture (hand-crafted; the flow cannot produce
	// an expired token without waiting).
	expired := craftStoredToken(t, h, func(tk *tokenv1.Token) {
		tk.Metadata.ClientId = client.ClientId
		tk.Metadata.ExpiresAt = uint64(time.Now().Add(-time.Hour).Unix())
	})

	// Revoked fixture.
	at, _ := mintTokens(t, h, client)
	rres, rerr := h.revoke(t, client.ClientId, at.Value)
	require.NoError(t, rerr)
	require.Nil(t, rres.Error)

	cases := map[string]struct{ tokenValue string }{
		"unknown token":  {tokenValue: "unknown-token-value"},
		"expired token":  {tokenValue: expired.Value},
		"revoked token":  {tokenValue: at.Value},
		"foreign issuer": {tokenValue: "issuer-bound-miss"},
	}
	for name, tc := range cases {
		if name == "foreign issuer" {
			// A token stored under a different issuer string is by
			// definition unknown to this issuer's introspection.
			continue
		}
		t.Run(name, func(t *testing.T) {
			res, err := h.introspect(t, client.ClientId, tc.tokenValue)
			require.NoError(t, err)
			require.NotNil(t, res.Token)
			require.NotEqual(t, tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE, res.Token.Status, "inactive token must not report active")
			require.Nil(t, res.Token.Metadata, "inactive token must not disclose claims")
		})
	}

	// Foreign issuer: same storage, different issuer namespace.
	foreign := craftStoredToken(t, h, func(tk *tokenv1.Token) {
		tk.Issuer = "http://other.as.example"
		tk.Metadata.Issuer = "http://other.as.example"
	})
	require.NoError(t, h.tokens.Create(context.Background(), "http://other.as.example", foreign))
	t.Run("foreign issuer", func(t *testing.T) {
		res, err := h.introspect(t, client.ClientId, foreign.Value)
		require.NoError(t, err)
		require.NotNil(t, res.Token)
		require.Equal(t, inactiveEnvelope(h, foreign.Value).Status, res.Token.Status)
		require.Nil(t, res.Token.Metadata, "foreign token must not disclose claims")
	})
}

// TestRFC7662_OwnershipGate_2_1 asserts a client cannot introspect another
// client's active token: the response is the unknown envelope, not the token
// claims (RFC 7662 section 2.1: only tokens of the requesting client).
func TestRFC7662_OwnershipGate_2_1(t *testing.T) {
	h := newHarness(t)
	clientA := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})
	clientB := h.registerConfidentialClient(t, []string{"https://client-b.example.org/cb"}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	at, _ := mintTokens(t, h, clientA)
	require.Equal(t, tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE, at.Status)

	// Attacker (client B) introspects client A's active token.
	res, err := h.introspect(t, clientB.ClientId, at.Value)
	require.NoError(t, err)
	require.NotNil(t, res.Token)
	require.Equal(t, tokenv1.TokenStatus_TOKEN_STATUS_UNKNOWN, res.Token.Status, "another client's token must render as unknown")
	require.Nil(t, res.Token.Metadata, "no claims may leak to a non-owner")
}

// TestRFC7662_RevokedTokenInactive asserts the owner sees its revoked token
// as inactive (RFC 7662 section 2.2: revoked tokens are inactive).
func TestRFC7662_RevokedTokenInactive(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	at, _ := mintTokens(t, h, client)
	rres, rerr := h.revoke(t, client.ClientId, at.Value)
	require.NoError(t, rerr)
	require.Nil(t, rres.Error)

	res, err := h.introspect(t, client.ClientId, at.Value)
	require.NoError(t, err)
	require.NotEqual(t, tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE, res.Token.Status)
}
