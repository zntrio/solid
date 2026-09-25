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
	"zntr.io/solid/sdk/random"
)

// RFC 8693 (Token Exchange) adversarial coverage.

// TestRFC8693_RequestedTokenTypeUnsupported asserts an explicit
// requested_token_type other than access_token is rejected with
// invalid_request (RFC 8693 section 2.1: unsupported types).
func TestRFC8693_RequestedTokenTypeUnsupported(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken, oidc.GrantTypeTokenExchange})

	at, _ := mintTokens(t, h, client)
	saml2 := oidc.TokenExchangeSAML2Type

	h.authenticateClient(t, client.ClientId)
	res, err := h.tokenz.Token(t.Context(), &flowv1.TokenRequest{
		Issuer:    h.issuer,
		GrantType: oidc.GrantTypeTokenExchange,
		Client:    &clientv1.Client{ClientId: client.ClientId},
		Grant: &flowv1.TokenRequest_TokenExchange{
			TokenExchange: &flowv1.GrantTokenExchange{
				SubjectToken:       at.Value,
				SubjectTokenType:   oidc.TokenExchangeAccessTokenType,
				RequestedTokenType: &saml2,
			},
		},
	})
	require.Error(t, err, "saml2 requested_token_type must be rejected")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_request", res.Error.Err)
}

// TestRFC8693_ActorTokenInvalid asserts an actor_token that is unknown or
// not a valid access token is rejected (RFC 8693 section 2.2.2).
func TestRFC8693_ActorTokenInvalid(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken, oidc.GrantTypeTokenExchange})

	at, _ := mintTokens(t, h, client)
	actorType := oidc.TokenExchangeAccessTokenType

	for name, actor := range map[string]string{
		"garbage":       "not-a-token-at-all",
		"unknown token": random.String(32),
	} {
		t.Run(name, func(t *testing.T) {
			h.authenticateClient(t, client.ClientId)
			res, err := h.tokenz.Token(t.Context(), &flowv1.TokenRequest{
				Issuer:    h.issuer,
				GrantType: oidc.GrantTypeTokenExchange,
				Client:    &clientv1.Client{ClientId: client.ClientId},
				Grant: &flowv1.TokenRequest_TokenExchange{
					TokenExchange: &flowv1.GrantTokenExchange{
						SubjectToken:     at.Value,
						SubjectTokenType: oidc.TokenExchangeAccessTokenType,
						ActorToken:       &actor,
						ActorTokenType:   &actorType,
					},
				},
			})
			require.Error(t, err, "invalid actor_token must be rejected")
			require.NotNil(t, res.Error)
			require.Equal(t, "invalid_request", res.Error.Err)
		})
	}
}

// TestRFC8693_ActorTokenValid asserts a valid actor token produces an
// exchanged token carrying the actor chain (RFC 8693 section 4.4: act).
func TestRFC8693_ActorTokenValid(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken, oidc.GrantTypeTokenExchange})

	subjectAT, _ := mintTokens(t, h, client)
	actorAT, _ := mintTokens(t, h, client)
	actorType := oidc.TokenExchangeAccessTokenType
	audience := "urn:example:cooperation-context"

	h.authenticateClient(t, client.ClientId)
	res, err := h.tokenz.Token(t.Context(), &flowv1.TokenRequest{
		Issuer:    h.issuer,
		GrantType: oidc.GrantTypeTokenExchange,
		Client:    &clientv1.Client{ClientId: client.ClientId},
		Audience:  &audience,
		Grant: &flowv1.TokenRequest_TokenExchange{
			TokenExchange: &flowv1.GrantTokenExchange{
				SubjectToken:     subjectAT.Value,
				SubjectTokenType: oidc.TokenExchangeAccessTokenType,
				ActorToken:       &actorAT.Value,
				ActorTokenType:   &actorType,
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, res.AccessToken)
	require.Equal(t, subjectAT.Metadata.Subject, res.AccessToken.Metadata.Subject, "subject must be preserved")
	require.NotEmpty(t, res.AccessToken.Actor, "exchanged token must record the actor chain")
	require.Equal(t, actorAT.Metadata.Subject, res.AccessToken.Actor[0].Subject)
}

// TestRFC8693_MayActEnforced asserts a subject token carrying may_act
// restricts the actors: an actor whose subject is not listed is rejected,
// a listed one succeeds (RFC 8693 section 5).
func TestRFC8693_MayActEnforced(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken, oidc.GrantTypeTokenExchange})
	actorType := oidc.TokenExchangeAccessTokenType
	audience := "urn:example:cooperation-context"

	// Subject token with may_act = [admin].
	subject := craftStoredToken(t, h, func(tk *tokenv1.Token) {
		tk.Metadata.ClientId = client.ClientId
		tk.Metadata.Scope = "openid profile"
		tk.MayAct = []*tokenv1.Actor{{Subject: "admin"}}
	})

	// An actor whose subject is NOT admin (randomguy) must be rejected.
	actor := craftStoredToken(t, h, func(tk *tokenv1.Token) {
		tk.Metadata.ClientId = client.ClientId
		tk.Metadata.Subject = "randomguy"
		tk.Metadata.Scope = "openid profile"
	})

	t.Run("unlisted actor rejected", func(t *testing.T) {
		h.authenticateClient(t, client.ClientId)
		res, err := h.tokenz.Token(t.Context(), &flowv1.TokenRequest{
			Issuer:    h.issuer,
			GrantType: oidc.GrantTypeTokenExchange,
			Client:    &clientv1.Client{ClientId: client.ClientId},
			Audience:  &audience,
			Grant: &flowv1.TokenRequest_TokenExchange{
				TokenExchange: &flowv1.GrantTokenExchange{
					SubjectToken:     subject.Value,
					SubjectTokenType: oidc.TokenExchangeAccessTokenType,
					ActorToken:       &actor.Value,
					ActorTokenType:   &actorType,
				},
			},
		})
		require.Error(t, err, "unlisted actor must be rejected by may_act")
		require.NotNil(t, res.Error)
		require.Equal(t, "invalid_request", res.Error.Err)
	})

	t.Run("listed actor succeeds", func(t *testing.T) {
		admin := craftStoredToken(t, h, func(tk *tokenv1.Token) {
			tk.Metadata.ClientId = client.ClientId
			tk.Metadata.Subject = "admin"
			tk.Metadata.Scope = "openid profile"
		})
		h.authenticateClient(t, client.ClientId)
		res, err := h.tokenz.Token(t.Context(), &flowv1.TokenRequest{
			Issuer:    h.issuer,
			GrantType: oidc.GrantTypeTokenExchange,
			Client:    &clientv1.Client{ClientId: client.ClientId},
			Audience:  &audience,
			Grant: &flowv1.TokenRequest_TokenExchange{
				TokenExchange: &flowv1.GrantTokenExchange{
					SubjectToken:     subject.Value,
					SubjectTokenType: oidc.TokenExchangeAccessTokenType,
					ActorToken:       &admin.Value,
					ActorTokenType:   &actorType,
				},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, res.AccessToken)
		require.NotEmpty(t, res.AccessToken.Actor)
		require.Equal(t, "admin", res.AccessToken.Actor[0].Subject)
	})
}

// TestRFC8693_ConfirmationMismatch asserts a DPoP-bound subject token cannot
// be exchanged with a proof of a different key (RFC 9449 section 8 applied
// to RFC 8693: the cnf claim must carry over).
func TestRFC8693_ConfirmationMismatch(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeTokenExchange})

	// Compute a real proof-key thumbprint.
	prover := buildDPoPProver(t)
	htu := testIssuer + "/token"
	proof, err := prover.Prove("POST", htu)
	require.NoError(t, err)
	jkt, err := buildDPoPVerifier().Verify(t.Context(), "POST", htu, proof)
	require.NoError(t, err)

	// Mint a DPoP-bound access token.
	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	code := h.seedAuthorization(t, client, req)

	h.authenticateClient(t, client.ClientId)
	minted, err := h.tokenz.Token(t.Context(), &flowv1.TokenRequest{
		Issuer:    h.issuer,
		GrantType: oidc.GrantTypeAuthorizationCode,
		Client:    &clientv1.Client{ClientId: client.ClientId},
		Grant: &flowv1.TokenRequest_AuthorizationCode{
			AuthorizationCode: &flowv1.GrantAuthorizationCode{
				Code:         code,
				CodeVerifier: verifier,
				RedirectUri:  testRedirectURI,
			},
		},
		TokenConfirmation: &tokenv1.TokenConfirmation{Jkt: jkt},
	})
	require.NoError(t, err)
	require.NotNil(t, minted.AccessToken)
	require.NotNil(t, minted.AccessToken.Confirmation)

	// Exchange with a DIFFERENT proof key: must fail.
	audience := "urn:example:cooperation-context"
	h.authenticateClient(t, client.ClientId)
	res, err := h.tokenz.Token(t.Context(), &flowv1.TokenRequest{
		Issuer:    h.issuer,
		GrantType: oidc.GrantTypeTokenExchange,
		Client:    &clientv1.Client{ClientId: client.ClientId},
		Audience:  &audience,
		Grant: &flowv1.TokenRequest_TokenExchange{
			TokenExchange: &flowv1.GrantTokenExchange{
				SubjectToken:     minted.AccessToken.Value,
				SubjectTokenType: oidc.TokenExchangeAccessTokenType,
			},
		},
		TokenConfirmation: &tokenv1.TokenConfirmation{Jkt: "different-key-jkt"},
	})
	require.Error(t, err, "proof-key swap during exchange must fail")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_grant", res.Error.Err)

	// Exchange with the SAME key: must succeed.
	h.authenticateClient(t, client.ClientId)
	okRes, okErr := h.tokenz.Token(t.Context(), &flowv1.TokenRequest{
		Issuer:    h.issuer,
		GrantType: oidc.GrantTypeTokenExchange,
		Client:    &clientv1.Client{ClientId: client.ClientId},
		Audience:  &audience,
		Grant: &flowv1.TokenRequest_TokenExchange{
			TokenExchange: &flowv1.GrantTokenExchange{
				SubjectToken:     minted.AccessToken.Value,
				SubjectTokenType: oidc.TokenExchangeAccessTokenType,
			},
		},
		TokenConfirmation: &tokenv1.TokenConfirmation{Jkt: jkt},
	})
	require.NoError(t, okErr)
	require.NotNil(t, okRes.AccessToken)
	require.Equal(t, jkt, okRes.AccessToken.Confirmation.Jkt, "cnf must carry over to the exchanged token")
}
