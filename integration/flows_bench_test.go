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
	"fmt"
	"testing"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
)

// Service-level flow benchmarks: each benchmark drives the real service
// stack (authorization, token, device, backchannel, client authentication,
// registration) wired with in-memory storage, without any HTTP layer — the
// numbers isolate the protocol cost from presentation concerns.
//
// Storage growth during a run (token records, TTL cache entries) is
// by-design persistent state, not a leak: the token store keeps minted
// tokens and the TTL windows outlive a benchmark run.

// benchCtx is the shared context for service calls in benchmarks.
var benchCtx = context.Background()

// BenchmarkAuthorizationRequestFlow measures a full authorization request
// registration (PAR-style) followed by the Authorize service call.
func BenchmarkAuthorizationRequestFlow(b *testing.B) {
	h := newHarness(b)
	ctx := benchCtx
	client := h.registerConfidentialClient(b, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	b.ResetTimer()
	for b.Loop() {
		verifier, _ := newPKCEPair(b)
		req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
		requestURI := "urn:solid:" + randomString(32)
		if _, err := h.authRequests.Register(ctx, h.issuer, requestURI, req); err != nil {
			b.Fatalf("unable to register authorization request: %v", err)
		}
		req.RequestUri = new(string)
		*req.RequestUri = requestURI
		res, err := h.authz.Authorize(ctx, &flowv1.AuthorizeRequest{
			Issuer:  h.issuer,
			Client:  client,
			Subject: "bench-user-1",
			Request: req,
		})
		if err != nil {
			b.Fatalf("unable to authorize: %v", err)
		}
		if res.Error != nil {
			b.Fatalf("authorization failed: %s", res.Error.Error)
		}
		if res.Code == "" {
			b.Fatal("authorization response has no code")
		}
	}
}

// BenchmarkAuthorizationCodeGrantFlow measures the complete authorization
// code grant: authorize (code issuance) + client authentication + code
// redemption (access & refresh token mint).
func BenchmarkAuthorizationCodeGrantFlow(b *testing.B) {
	h := newHarness(b)
	client := h.registerConfidentialClient(b, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	b.ResetTimer()
	for b.Loop() {
		verifier, _ := newPKCEPair(b)
		code := h.seedAuthorization(b, client, validAuthorizationRequest(client.ClientId, verifier, testRedirectURI))
		res, err := h.redeemCode(b, client.ClientId, code, verifier, testRedirectURI)
		if err != nil {
			b.Fatalf("code redemption failed: %v", err)
		}
		if res.Error != nil {
			b.Fatalf("code redemption error: %s", res.Error.Error)
		}
		if res.AccessToken == nil {
			b.Fatal("code grant must mint an access token")
		}
	}
}

// BenchmarkClientCredentialsGrantFlow measures private_key_jwt
// authentication followed by a client_credentials token issuance.
func BenchmarkClientCredentialsGrantFlow(b *testing.B) {
	h := newHarness(b)
	ctx := benchCtx
	client := h.registerConfidentialClient(b, []string{testRedirectURI}, []string{oidc.GrantTypeClientCredentials})

	b.ResetTimer()
	for b.Loop() {
		h.authenticateClient(b, client.ClientId)
		res, err := h.tokenz.Token(ctx, clientCredentialsRequest(h.issuer, client.ClientId, "urn:example:cooperation-context"))
		if err != nil {
			b.Fatalf("client_credentials grant failed: %v", err)
		}
		if res.Error != nil {
			b.Fatalf("client_credentials grant error: %s", res.Error.Error)
		}
		if res.AccessToken == nil {
			b.Fatal("client_credentials grant must mint an access token")
		}
	}
}

// BenchmarkRefreshTokenGrantFlow measures the refresh grant. The store
// rotates the refresh token on every use (RFC 9700 section 4.14.2), so the
// benchmark chains the rotated refresh token from one iteration to the
// next; only the first mint (before ResetTimer) is excluded from the
// measurement.
func BenchmarkRefreshTokenGrantFlow(b *testing.B) {
	h := newHarness(b)
	client := h.registerConfidentialClient(b, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	_, rt := mintTokens(b, h, client)
	refreshToken := rt.Value

	b.ResetTimer()
	for b.Loop() {
		res, err := h.refresh(b, client.ClientId, refreshToken)
		if err != nil {
			b.Fatalf("refresh grant failed: %v", err)
		}
		if res.Error != nil {
			b.Fatalf("refresh grant error: %s", res.Error.Error)
		}
		if res.RefreshToken == nil {
			b.Fatal("refresh grant must rotate the refresh token")
		}
		refreshToken = res.RefreshToken.Value
	}
}

// BenchmarkDeviceCodeGrantFlow measures the device authorization grant:
// device authorization + user approval + DPoP-confirmed token poll.
func BenchmarkDeviceCodeGrantFlow(b *testing.B) {
	h := newHarness(b)
	client := h.registerDeviceDPoPClient(b)

	b.ResetTimer()
	for b.Loop() {
		deviceCode, userCode := h.startDeviceAuthorization(b, client, []string{"openid"})
		h.approveDevice(b, userCode, "bench-device-user-1")
		res, err := h.pollDeviceTokenWithConfirmation(b, client.ClientId, deviceCode, &tokenv1.TokenConfirmation{Jkt: integrationDPoPJkt})
		if err != nil {
			b.Fatalf("device code grant failed: %v", err)
		}
		if res.Error != nil {
			b.Fatalf("device code grant error: %s", res.Error.Error)
		}
		if res.AccessToken == nil {
			b.Fatal("device code grant must mint an access token")
		}
	}
}

// BenchmarkCIBAGrantFlow measures the CIBA grant: backchannel
// authentication start + end-user approval + token poll.
func BenchmarkCIBAGrantFlow(b *testing.B) {
	h := newHarness(b)
	client := h.registerCIBAClient(b)

	b.ResetTimer()
	for b.Loop() {
		authReqID := h.startBackchannelAuth(b, client)
		h.approveBackchannel(b, authReqID, "hello")
		res, err := h.pollCIBAToken(b, client.ClientId, authReqID)
		if err != nil {
			b.Fatalf("CIBA grant failed: %v", err)
		}
		if res.Error != nil {
			b.Fatalf("CIBA grant error: %s", res.Error.Error)
		}
		if res.AccessToken == nil {
			b.Fatal("CIBA grant must mint an access token")
		}
	}
}

// BenchmarkTokenExchangeGrantFlow measures the RFC 8693 token exchange
// grant: client authentication + subject-token exchange without an actor
// token.
func BenchmarkTokenExchangeGrantFlow(b *testing.B) {
	h := newHarness(b)
	ctx := benchCtx
	client := h.registerConfidentialClient(b, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken, oidc.GrantTypeTokenExchange})

	subjectAT, _ := mintTokens(b, h, client)
	audience := "urn:example:cooperation-context"

	b.ResetTimer()
	for b.Loop() {
		h.authenticateClient(b, client.ClientId)
		res, err := h.tokenz.Token(ctx, &flowv1.TokenRequest{
			Issuer:    h.issuer,
			GrantType: oidc.GrantTypeTokenExchange,
			Client:    &clientv1.Client{ClientId: client.ClientId},
			Audience:  &audience,
			Grant: &flowv1.TokenRequest_TokenExchange{
				TokenExchange: &flowv1.GrantTokenExchange{
					SubjectToken:     subjectAT.Value,
					SubjectTokenType: oidc.TokenExchangeAccessTokenType,
				},
			},
			// The subject token is DPoP-bound (minted through the
			// enforced code flow); present the matching confirmation.
			TokenConfirmation: &tokenv1.TokenConfirmation{Jkt: integrationDPoPJkt},
		})
		if err != nil {
			b.Fatalf("token exchange failed: %v", err)
		}
		if res.Error != nil {
			b.Fatalf("token exchange error: %s", res.Error.Error)
		}
		if res.AccessToken == nil {
			b.Fatal("token exchange must mint an access token")
		}
	}
}

// BenchmarkClientRegistrationFlow measures dynamic client registration
// (RFC 7591) against the open registration posture of the harness.
func BenchmarkClientRegistrationFlow(b *testing.B) {
	h := newHarness(b)
	ctx := benchCtx

	b.ResetTimer()
	i := 0
	for b.Loop() {
		res, err := h.registrz.Register(ctx, &clientv1.RegisterRequest{
			Metadata: &clientv1.ClientMeta{
				ClientName:              new(fmt.Sprintf("bench-registered-client-%d", i)),
				GrantTypes:              []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken},
				ResponseTypes:           []string{oidc.ResponseTypeCode},
				ResponseModes:           []string{oidc.ResponseModeQueryJWT},
				RedirectUris:            []string{testRedirectURI},
				TokenEndpointAuthMethod: new(oidc.AuthMethodPrivateKeyJWT),
				Jwks:                    clientJWKSWithSIG,
			},
		})
		if err != nil {
			b.Fatalf("client registration failed: %v", err)
		}
		if res.Error != nil {
			b.Fatalf("client registration error: %s", res.Error.Error)
		}
		if res.Client == nil || res.Client.ClientId == "" {
			b.Fatal("registration must assign a client_id")
		}
	}
}

// BenchmarkIntrospectionFlow measures client authentication followed by an
// RFC 7662 introspection of an active access token. Introspection does not
// consume the token, so one pre-minted token serves every iteration.
func BenchmarkIntrospectionFlow(b *testing.B) {
	h := newHarness(b)
	client := h.registerConfidentialClient(b, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	at, _ := mintTokens(b, h, client)

	b.ResetTimer()
	for b.Loop() {
		res, err := h.introspect(b, client.ClientId, at.Value)
		if err != nil {
			b.Fatalf("introspection failed: %v", err)
		}
		if res.Error != nil {
			b.Fatalf("introspection error: %s", res.Error.Error)
		}
		if res.Token == nil || res.Token.Status != tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE {
			b.Fatal("active token must introspect as active")
		}
	}
}

// BenchmarkRevocationFlow measures client authentication followed by
// RFC 7009 revocation. Revocation burns the token, so each iteration
// consumes a token minted on first use (b.Loop re-invokes the benchmark
// function with a growing N, so pre-seeding b.N tokens upfront is not
// possible); the mint is excluded from the measurement via StopTimer.
func BenchmarkRevocationFlow(b *testing.B) {
	h := newHarness(b)
	ctx := benchCtx
	client := h.registerConfidentialClient(b, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	values := make(map[int]string)
	b.ResetTimer()
	i := 0
	for b.Loop() {
		value, ok := values[i]
		if !ok {
			// First use of this index across the whole benchmark run:
			// mint the token outside the measured region.
			b.StopTimer()
			value = fmt.Sprintf("bench-revoke-%d-%s", i, randomString(16))
			if err := h.tokens.Create(ctx, h.issuer, &tokenv1.Token{
				Issuer:    h.issuer,
				TokenId:   fmt.Sprintf("bench-revoke-%d", i),
				Value:     value,
				Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
				TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
				Metadata: &tokenv1.TokenMeta{
					Issuer:   h.issuer,
					Subject:  "bench-user-1",
					ClientId: client.ClientId,
					Scope:    "openid profile",
				},
			}); err != nil {
				b.Fatalf("unable to seed token %d: %v", i, err)
			}
			values[i] = value
			b.StartTimer()
		}
		res, err := h.revoke(b, client.ClientId, value)
		if err != nil {
			b.Fatalf("revocation failed: %v", err)
		}
		if res.Error != nil {
			b.Fatalf("revocation error: %s", res.Error.Error)
		}
		i++
	}
}

// BenchmarkClientAuthentication measures the private_key_jwt client
// authentication in isolation: ES256 assertion signing (the client cost)
// plus the full verification pipeline (the server cost).
func BenchmarkClientAuthentication(b *testing.B) {
	h := newHarness(b)
	client := h.registerConfidentialClient(b, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	b.ResetTimer()
	for b.Loop() {
		if _, err := h.authenticate(b, testTokenEndpoint, validClientAssertion(b, client.ClientId)); err != nil {
			b.Fatalf("client authentication failed: %v", err)
		}
	}
}
