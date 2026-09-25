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
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"

	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	oidc "zntr.io/solid/oidc"
	"zntr.io/solid/sdk/random"
)

// Adversarial coverage for draft-ietf-oauth-security-topics-update-03
// ("Updates to OAuth 2.0 Security Best Current Practice"). Each test plays
// the draft's attacker roles against the real service stack wired by
// newHarness: audience injection (section 2.1), COAT cross-toolkit account
// takeover (section 2.2), cross-user session fixation (section 2.3), and
// shared consent in brokered OAuth (section 2.4). Where the countermeasure is
// client-side (sections 2.3, 2.4), the tests pin the AS-side invariants the
// client-side check relies on.

// -----------------------------------------------------------------------------
// Section 2.1 — Audience injection in signature-based client authentication

// TestOAuthSecTopics_AudInjectionCrossEndpointReplay_2_1 asserts an assertion
// minted with aud bound to one endpoint cannot be replayed at another
// endpoint of the same AS: with endpoint-exact audience acceptance
// (draft-ietf-oauth-security-topics-update-03 section 2.1.2.2), the captured
// PAR-endpoint assertion is refused at the token endpoint. Positive control:
// the same assertion shape with aud equal to the receiving endpoint is
// accepted.
func TestOAuthSecTopics_AudInjectionCrossEndpointReplay_2_1(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, nil)

	now := uint64(time.Now().Unix())

	// Attacker model A3/A5: captures an assertion whose aud is the PAR
	// endpoint value and replays it at the token endpoint.
	parAudienceAssertion := generateClientAssertion(t, &privateJWTClaims{
		JTI:       "aud-cross-endpoint-replay",
		Subject:   client.ClientId,
		Issuer:    client.ClientId,
		Audience:  testIssuer + "/par",
		Expires:   now + 300,
		IssuedAt:  now,
		NotBefore: now,
	})

	res, err := h.authenticate(t, testTokenEndpoint, parAudienceAssertion)
	require.Error(t, err, "an assertion minted for the PAR endpoint must not authenticate at the token endpoint")
	if res != nil {
		require.Nil(t, res.Client, "no client may be resolved from a cross-endpoint replayed assertion")
	}

	// Positive control: identical claims, aud = the actual receiving endpoint.
	tokenAudienceAssertion := generateClientAssertion(t, &privateJWTClaims{
		JTI:       "aud-cross-endpoint-replay-ok",
		Subject:   client.ClientId,
		Issuer:    client.ClientId,
		Audience:  testTokenEndpoint,
		Expires:   now + 300,
		IssuedAt:  now,
		NotBefore: now,
	})

	resOK, errOK := h.authenticate(t, testTokenEndpoint, tokenAudienceAssertion)
	require.NoError(t, errOK, "an assertion whose aud equals the receiving endpoint must authenticate")
	require.NotNil(t, resOK.Client)
	require.Equal(t, client.ClientId, resOK.Client.ClientId)
}

// TestOAuthSecTopics_AudInjectionTokenEndpointClaim_2_1 asserts the core
// section 2.1.1 scenario: an attacker AS publishes metadata whose
// token_endpoint points at the honest AS, capturing assertions minted with
// aud = honest-AS token endpoint. When that assertion is presented to the
// honest AS at a different endpoint (here: introspection), it must be
// rejected — the endpoint-exact rule makes a forged token_endpoint in
// attacker metadata useless for capturing endpoint-differentiated assertions.
func TestOAuthSecTopics_AudInjectionTokenEndpointClaim_2_1(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, nil)

	now := uint64(time.Now().Unix())

	// Assertion the honest client minted for what it believed was this AS's
	// token endpoint (attacker-controlled metadata redirect).
	assertion := generateClientAssertion(t, &privateJWTClaims{
		JTI:       "aud-token-endpoint-claim",
		Subject:   client.ClientId,
		Issuer:    client.ClientId,
		Audience:  testTokenEndpoint,
		Expires:   now + 300,
		IssuedAt:  now,
		NotBefore: now,
	})

	// Presented at the introspection endpoint: rejected.
	res, err := h.authenticate(t, testIssuer+"/token/introspect", assertion)
	require.Error(t, err, "an assertion captured via a forged token_endpoint claim must not authenticate at another endpoint")
	if res != nil {
		require.Nil(t, res.Client)
	}
}

// TestOAuthSecTopics_AudIssuerIdentifierAccepted_2_1_2_1 asserts the draft's
// preferred countermeasure works end-to-end: an assertion with aud equal to
// the AS issuer identifier is accepted at every endpoint
// (draft-ietf-oauth-security-topics-update-03 section 2.1.2.1).
func TestOAuthSecTopics_AudIssuerIdentifierAccepted_2_1_2_1(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, nil)

	for _, endpoint := range []string{
		testIssuer + "/par",
		testTokenEndpoint,
		testIssuer + "/token/introspect",
		testIssuer + "/token/revoke",
		testIssuer + "/device/authorize",
	} {
		t.Run(endpoint, func(t *testing.T) {
			now := uint64(time.Now().Unix())
			assertion := generateClientAssertion(t, &privateJWTClaims{
				JTI:       "aud-issuer-identifier-" + random.String(6),
				Subject:   client.ClientId,
				Issuer:    client.ClientId,
				Audience:  testIssuer,
				Expires:   now + 300,
				IssuedAt:  now,
				NotBefore: now,
			})

			res, err := h.authenticate(t, endpoint, assertion)
			require.NoError(t, err, "issuer-identifier aud must be accepted at %s", endpoint)
			require.NotNil(t, res.Client)
			require.Equal(t, client.ClientId, res.Client.ClientId)
		})
	}
}

// TestOAuthSecTopics_AudArrayWithInjectedAudience_2_1 asserts an aud array
// ["<valid audience>", "https://attacker.example"] is rejected: RFC 7519
// section 4.1.3 array semantics would let the attacker identify itself as an
// intended audience of the same assertion; the draft section 2.1.2 mandates
// a single audience value.
func TestOAuthSecTopics_AudArrayWithInjectedAudience_2_1(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, nil)

	now := uint64(time.Now().Unix())

	// Manual assembly: the harness claims struct carries a string aud, so an
	// array aud is signed directly with the fixture key.
	claims := map[string]any{
		"jti": "aud-array-injected",
		"sub": client.ClientId,
		"iss": client.ClientId,
		"aud": []string{testTokenEndpoint, "https://attacker.example"},
		"exp": now + 300,
		"iat": now,
		"nbf": now,
	}
	raw := manualSignAssertion(t, claims)

	res, err := h.authenticate(t, testTokenEndpoint, raw)
	require.Error(t, err, "an aud array carrying an injected audience must not authenticate")
	if res != nil {
		require.Nil(t, res.Client)
	}
}

// -----------------------------------------------------------------------------
// Section 2.2 — Cross-toolkit OAuth Account Takeover (COAT)

// TestOAuthSecTopics_CoatCodeRedeemedAtHonestAS_2_2 asserts the AS-boundary
// barrier of the COAT attack (draft-ietf-oauth-security-topics-update-03
// section 2.2, steps 5/6): an attacker-toolkit client cannot redeem a code
// issued under the honest client's client_id. The full countermeasure
// (connection-context identifier in the redirect URI plus session match,
// section 2.2.2) is client-side; the AS-side contract tested here is the
// code-to-client binding that makes the client-side check meaningful.
func TestOAuthSecTopics_CoatCodeRedeemedAtHonestAS_2_2(t *testing.T) {
	h := newHarness(t)

	honestClient := h.registerConfidentialClient(t, []string{"https://honest.example/cb"}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})
	attackerClient := h.registerConfidentialClient(t, []string{"https://attacker.example/cb"}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	// A code is issued under the honest client's registration.
	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, honestClient, validAuthorizationRequest(honestClient.ClientId, verifier, "https://honest.example/cb"))

	res, err := h.redeemCode(t, attackerClient.ClientId, code, verifier, "https://honest.example/cb")
	require.Error(t, err, "a code issued to the honest client must not be redeemable by the attacker-toolkit client")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_grant", res.Error.Err)
	require.Nil(t, res.AccessToken)
}

// TestOAuthSecTopics_CoatRedirectContextMismatch_2_2 asserts the redirect
// confusion variant of COAT: a code seeded with one redirect URI context
// (honest-cb) cannot be redeemed presenting a second registered redirect URI
// (attack-cb) of the same client — the deployment shape where one client
// registration serves two connection contexts. The AS enforces the
// request-grant identity; the client MUST additionally fail the flow when
// the response-redirect context differs from the session context
// (draft-ietf-oauth-security-topics-update-03 section 2.2.2).
func TestOAuthSecTopics_CoatRedirectContextMismatch_2_2(t *testing.T) {
	h := newHarness(t)

	client := h.registerConfidentialClient(t,
		[]string{"https://client.example.org/honest-cb", "https://client.example.org/attack-cb"},
		[]string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, verifier, "https://client.example.org/honest-cb"))

	// Redeem presenting the other context's URI: rejected.
	res, err := h.redeemCode(t, client.ClientId, code, verifier, "https://client.example.org/attack-cb")
	require.Error(t, err, "a code bound to one redirect context must not be redeemable through another")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_grant", res.Error.Err)
	require.Nil(t, res.AccessToken)
}

// TestOAuthSecTopics_CoatIssParameterPresent_2_2 asserts the RFC 9207 iss
// response parameter — the mix-up mitigation the draft's section 2.2.2
// lists as the approved countermeasure — is emitted by the authorization
// service so clients can verify the AS identity of every response. No prior
// RFC 9207 coverage existed in the integration suite.
func TestOAuthSecTopics_CoatIssParameterPresent_2_2(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode})

	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)

	// Register the request through the PAR-style endpoint.
	requestURI := "urn:solid:" + random.String(32)
	_, err := h.authRequests.Register(t.Context(), h.issuer, requestURI, req)
	require.NoError(t, err)
	req.RequestUri = new(string)
	*req.RequestUri = requestURI

	// Success path: the authorization response carries iss = the AS issuer.
	res, err := h.authz.Authorize(t.Context(), &flowv1.AuthorizeRequest{
		Issuer:  h.issuer,
		Client:  client,
		Subject: "user-1",
		Request: req,
	})
	require.NoError(t, err)
	require.Nil(t, res.Error)
	require.Equal(t, h.issuer, res.Issuer, "RFC 9207: the authorization response must carry the AS issuer identifier")

	// Error path: an invalid redirect_uri fails, and the error response
	// still identifies the issuer.
	verifier2, _ := newPKCEPair(t)
	req2 := validAuthorizationRequest(client.ClientId, verifier2, "https://unregistered.example/cb")
	requestURI2 := "urn:solid:" + random.String(32)
	_, err = h.authRequests.Register(t.Context(), h.issuer, requestURI2, req2)
	require.NoError(t, err)
	req2.RequestUri = new(string)
	*req2.RequestUri = requestURI2

	res2, err2 := h.authz.Authorize(t.Context(), &flowv1.AuthorizeRequest{
		Issuer:  h.issuer,
		Client:  client,
		Subject: "user-1",
		Request: req2,
	})
	require.Error(t, err2, "an unregistered redirect_uri must be rejected")
	req.State = "attacker-state-0123456789abcdef0123456789abcdef"
	require.Equal(t, h.issuer, res2.Issuer, "RFC 9207: the error response must carry the AS issuer identifier so the client can fail the flow on mismatch")
}

// -----------------------------------------------------------------------------
// Section 2.3 — Cross-user session fixation

// TestOAuthSecTopics_SessionFixationStateNotBoundToAttacker_2_3 asserts the
// AS-side invariant the client-side countermeasure relies on: the issued
// state value an attacker may have fixed out-of-band
// (draft-ietf-oauth-security-topics-update-03 section 2.3). The attacker
// initiates a flow with attacker-chosen state; the victim completes it; the
// minted access token must reference the victim's subject, and the state
// round-trips opaquely. The real countermeasure (binding state to the client
// session, section 2.3.2) is client-side.
func TestOAuthSecTopics_SessionFixationStateNotBoundToAttacker_2_3(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	// Attacker-chosen state, as fixed out-of-band (pre-session fixation).
	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	req.State = "attacker-state-0123456789abcdef0123456789abcdef"

	requestURI := "urn:solid:" + random.String(32)
	_, err := h.authRequests.Register(t.Context(), h.issuer, requestURI, req)
	require.NoError(t, err)
	req.RequestUri = new(string)
	*req.RequestUri = requestURI

	// The victim (a different subject) completes the authorization.
	res, err := h.authz.Authorize(t.Context(), &flowv1.AuthorizeRequest{
		Issuer:  h.issuer,
		Client:  client,
		Subject: "user-victim",
		Request: req,
	})
	require.NoError(t, err)
	require.Nil(t, res.Error)
	require.Equal(t, "attacker-state-0123456789abcdef0123456789abcdef", res.State, "state must round-trip opaquely")
	require.NotEmpty(t, res.Code)

	// The victim redeems the code; the tokens must be bound to the victim.
	tokenRes, err := h.redeemCode(t, client.ClientId, res.Code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, tokenRes.AccessToken)
	require.Equal(t, "user-victim", tokenRes.AccessToken.Metadata.Subject,
		"the token subject must be the completing user, never derived from the attacker-fixed state or initiating context")
}

// TestOAuthSecTopics_SessionFixationSubjectNotInRequest_2_3 asserts the
// AuthorizationRequest proto carries no subject influence: the subject is
// supplied exclusively by the presentation layer's AuthorizeRequest, and an
// authorization without a subject is refused with no code minted. This pins
// the invariant against a future proto regression putting subject influence
// in the request parameters.
func TestOAuthSecTopics_SessionFixationSubjectNotInRequest_2_3(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, nil)

	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)

	requestURI := "urn:solid:" + random.String(32)
	_, err := h.authRequests.Register(t.Context(), h.issuer, requestURI, req)
	require.NoError(t, err)
	req.RequestUri = new(string)
	*req.RequestUri = requestURI

	// Empty subject: refused, invalid_request.
	res, err := h.authz.Authorize(t.Context(), &flowv1.AuthorizeRequest{
		Issuer:  h.issuer,
		Client:  client,
		Subject: "",
		Request: req,
	})
	require.Error(t, err, "authorization without an authenticated subject must be refused")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_request", res.Error.Err)
	require.Empty(t, res.Code, "no code may be minted without a subject")
}

// -----------------------------------------------------------------------------
// Section 2.4 — Shared consent in brokered OAuth

// TestOAuthSecTopics_SharedConsentPerClientRegistration_2_4_2_1 asserts the
// AS-side countermeasure for shared consent in brokered OAuth: each
// downstream client is a distinct registration, even when a broker reuses
// the same key material for both (H-Client and M-Client share the JWKS
// fixture here — the worst case). A code granted under H-Client's id cannot
// be redeemed by M-Client, and a refresh token from H-Client's grant cannot
// be refreshed by M-Client. Broker-side consent screens (section 2.4.2.2)
// are out of scope: this repo ships no broker.
func TestOAuthSecTopics_SharedConsentPerClientRegistration_2_4_2_1(t *testing.T) {
	h := newHarness(t)

	// Same JWKS fixture (registerConfidentialClient always uses it) —
	// simulating one broker's key material reused for both registrations.
	hClient := h.registerConfidentialClient(t, []string{"https://h-client.example/cb"}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})
	mClient := h.registerConfidentialClient(t, []string{"https://m-client.example/cb"}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})
	require.NotEqual(t, hClient.ClientId, mClient.ClientId)

	// H-Client obtains a code + refresh token through a full grant.
	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, hClient, validAuthorizationRequest(hClient.ClientId, verifier, "https://h-client.example/cb"))
	res, err := h.redeemCode(t, hClient.ClientId, code, verifier, "https://h-client.example/cb")
	require.NoError(t, err)
	require.NotNil(t, res.AccessToken)
	require.NotNil(t, res.RefreshToken, "offline_access scope must yield a refresh token")

	// M-Client cannot redeem a fresh code granted under H-Client's id.
	verifier2, _ := newPKCEPair(t)
	code2 := h.seedAuthorization(t, hClient, validAuthorizationRequest(hClient.ClientId, verifier2, "https://h-client.example/cb"))
	res2, err2 := h.redeemCode(t, mClient.ClientId, code2, verifier2, "https://h-client.example/cb")
	require.Error(t, err2, "a code granted under H-Client's registration must not be redeemable by M-Client")
	require.NotNil(t, res2.Error)
	require.Equal(t, "invalid_grant", res2.Error.Err)
	require.Nil(t, res2.AccessToken)

	// M-Client cannot refresh H-Client's refresh token.
	res3, err3 := h.refresh(t, mClient.ClientId, res.RefreshToken.Value)
	require.Error(t, err3, "a refresh token from H-Client's grant must not be refreshable by M-Client")
	require.NotNil(t, res3.Error)
	require.Equal(t, "invalid_grant", res3.Error.Err)
}

// -----------------------------------------------------------------------------

// manualSignAssertion signs an arbitrary claim set with the shared ES256
// fixture key (used for aud shapes the harness claims struct cannot carry,
// like arrays).
func manualSignAssertion(t *testing.T, claims map[string]any) string {
	t.Helper()

	privateKey, err := jwxjwk.ParseKey(clientPrivateKey)
	require.NoError(t, err)
	var rawKey any
	require.NoError(t, jwxjwk.Export(privateKey, &rawKey))

	tok := gojwt.NewWithClaims(gojwt.SigningMethodES256, gojwt.MapClaims(claims))
	tok.Header["typ"] = "JWT"
	raw, err := tok.SignedString(rawKey)
	require.NoError(t, err)
	return raw
}
