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

// OAuth 2.1 (draft-ietf-oauth-v2-1-16) conformance surface: each case maps
// to a normative requirement of the vendored draft under docs/rfcs/.

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/dpop"
	"zntr.io/solid/sdk/random"
	"zntr.io/solid/sdk/spiffe"
	"zntr.io/solid/server/httpkit"
	"zntr.io/solid/server/profile"
	"zntr.io/solid/server/storage/inmemory"
)

// -----------------------------------------------------------------------------
// §4.1.2.1 / §7.13.2: an invalid redirect_uri must not result in an
// authorization code; the AS answers an error response instead of redirecting
// to an unvalidated URI.

func TestOAuth21_InvalidRedirectUri_NoCodeIssued_4_1_2_1(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, "https://attacker.example.org/cb")

	ctx := context.Background()
	requestURI := "urn:solid:" + randomString(32)
	if _, err := h.authRequests.Register(ctx, h.issuer, requestURI, req); err != nil {
		t.Fatalf("unable to register authorization request: %v", err)
	}
	req.RequestUri = &requestURI

	res, err := h.authz.Authorize(ctx, &flowv1.AuthorizeRequest{
		Issuer:  h.issuer,
		Client:  client,
		Subject: "user-1",
		Request: req,
	})
	require.Error(t, err, "an unregistered redirect_uri must fail the authorization request")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_request", res.Error.Error)
	require.Empty(t, res.Code, "no authorization code must be issued for an invalid redirect_uri")
}

// -----------------------------------------------------------------------------
// §2.3: the redirect URI MUST NOT include a fragment component.

func TestOAuth21_FragmentRedirectUri_Rejected_2_3(t *testing.T) {
	h := newHarness(t)
	// The fragment variant of an otherwise registered URI.
	client := h.registerConfidentialClient(t, []string{"https://client.example.org/cb#frag"}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, "https://client.example.org/cb#frag")

	ctx := context.Background()
	requestURI := "urn:solid:" + randomString(32)
	if _, err := h.authRequests.Register(ctx, h.issuer, requestURI, req); err != nil {
		t.Fatalf("unable to register authorization request: %v", err)
	}
	req.RequestUri = &requestURI

	res, err := h.authz.Authorize(ctx, &flowv1.AuthorizeRequest{
		Issuer:  h.issuer,
		Client:  client,
		Subject: "user-1",
		Request: req,
	})
	require.Error(t, err, "a redirect_uri with a fragment component must be rejected")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_request", res.Error.Error)
	require.Empty(t, res.Code, "no authorization code must be issued for a fragment redirect_uri")
}

// -----------------------------------------------------------------------------
// §7.5.2: the plain code_challenge_method is removed; only S256 is valid.

func TestOAuth21_PlainPKCE_Rejected_7_5_2(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	// Attacker sends method "plain" with the challenge equal to the
	// verifier — valid PKCE plain, but plain is not offered by OAuth 2.1.
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	req.CodeChallenge = verifier
	req.CodeChallengeMethod = "plain"

	ctx := context.Background()
	requestURI := "urn:solid:" + randomString(32)
	if _, err := h.authRequests.Register(ctx, h.issuer, requestURI, req); err != nil {
		t.Fatalf("unable to register authorization request: %v", err)
	}
	req.RequestUri = &requestURI

	res, err := h.authz.Authorize(ctx, &flowv1.AuthorizeRequest{
		Issuer:  h.issuer,
		Client:  client,
		Subject: "user-1",
		Request: req,
	})
	require.Error(t, err, "code_challenge_method=plain must be rejected")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_request", res.Error.Error)
	require.Empty(t, res.Code)
}

// -----------------------------------------------------------------------------
// §4.1.3: the authorization code redemption no longer carries a redirect_uri
// parameter; its absence must be tolerated (PKCE protects the redemption).

func TestOAuth21_RedemptionWithoutRedirectUri_4_1_3(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, verifier, testRedirectURI))

	h.authenticateClient(t, client.ClientId)
	res, err := h.tokenz.Token(context.Background(), &flowv1.TokenRequest{
		Issuer:    h.issuer,
		GrantType: oidc.GrantTypeAuthorizationCode,
		Client:    &clientv1.Client{ClientId: client.ClientId},
		Grant: &flowv1.TokenRequest_AuthorizationCode{
			AuthorizationCode: &flowv1.GrantAuthorizationCode{
				Code:         code,
				CodeVerifier: verifier,
			},
		},
	})
	require.NoError(t, err, "redeeming a code without redirect_uri must succeed (draft §4.1.3)")
	require.Nil(t, res.Error)
	require.NotNil(t, res.AccessToken)
}

// -----------------------------------------------------------------------------
// §4.3.1: the scope of a refresh request may be narrowed but MUST NOT be
// broadened; a broader scope is an invalid_scope.

func TestOAuth21_RefreshScopeNarrowing_4_3_1(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, verifier, testRedirectURI))

	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, res.RefreshToken, "offline_access scope must yield a refresh token")

	// Narrow: only a subset of the granted scopes.
	h.authenticateClient(t, client.ClientId)
	narrowed := "openid profile"
	narrowReq := refreshGrantRequest(h.issuer, client.ClientId, res.RefreshToken.Value)
	narrowReq.Scope = &narrowed
	narrowRes, err := h.tokenz.Token(context.Background(), narrowReq)
	require.NoError(t, err, "narrowing the scope on refresh must succeed")
	require.Nil(t, narrowRes.Error)
	require.NotNil(t, narrowRes.AccessToken)
	require.Equal(t, narrowed, narrowRes.AccessToken.Metadata.Scope, "the narrowed scope must be carried by the new access token")

	// Exceed: a scope beyond the granted set.
	h.authenticateClient(t, client.ClientId)
	exceeding := "openid profile admin"
	exceedReq := refreshGrantRequest(h.issuer, client.ClientId, narrowRes.RefreshToken.Value)
	exceedReq.Scope = &exceeding
	exceedRes, err := h.tokenz.Token(context.Background(), exceedReq)
	require.Error(t, err, "requesting a broader scope on refresh must fail")
	require.NotNil(t, exceedRes.Error)
	require.Equal(t, "invalid_scope", exceedRes.Error.Error)
	require.Nil(t, exceedRes.AccessToken)
}

// -----------------------------------------------------------------------------
// §4.3.1 (pin): refresh token rotation — replaying the original refresh
// token after rotation fails and revokes the grant family.

func TestOAuth21_RefreshRotationInvariant_4_3_1(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, verifier, testRedirectURI))

	first, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, first.RefreshToken)

	// Honest rotation.
	rotated, err := h.refresh(t, client.ClientId, first.RefreshToken.Value)
	require.NoError(t, err)
	require.NotNil(t, rotated.RefreshToken)

	// Attacker replays the original (already-rotated) token: invalid_grant
	// and family revocation.
	replayed, err := h.refresh(t, client.ClientId, first.RefreshToken.Value)
	require.Error(t, err, "a rotated refresh token must not be reusable")
	require.NotNil(t, replayed.Error)
	require.Equal(t, "invalid_grant", replayed.Error.Error)

	// The rotated token is revoked too (grant family revocation).
	familyRes, err := h.refresh(t, client.ClientId, rotated.RefreshToken.Value)
	require.Error(t, err, "the grant family must be revoked after refresh token replay")
	if familyRes != nil {
		require.NotNil(t, familyRes.Error)
	}
}

// -----------------------------------------------------------------------------
// §8.4.2: loopback interface redirect URIs match the registered URI with any
// port; the port exception applies at both authorize and redeem time.

func TestOAuth21_LoopbackPortVariance_8_4_2(t *testing.T) {
	h := newHarness(t)
	registered := "http://127.0.0.1:8080/cb"
	varying := "http://127.0.0.1:9527/cb"
	client := h.registerConfidentialClient(t, []string{registered}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, verifier, varying))

	// Redeem with the same varying-port URI: the client registration check
	// honors the loopback exception.
	res, err := h.redeemCode(t, client.ClientId, code, verifier, varying)
	require.NoError(t, err, "loopback port variance must be accepted at redemption")
	require.NotNil(t, res.AccessToken)
}

// -----------------------------------------------------------------------------
// §4.1.2.1 (pin): the error redirect response carries state and issuer
// (RFC 9207), so the client can attribute failures to the right AS.

func TestOAuth21_ErrorRedirectCarriesStateAndIssuer_4_1_2_1(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	// Invalid: a response_mode the AS does not offer.
	unsupported := "unsupported_mode"
	req.ResponseMode = &unsupported

	ctx := context.Background()
	requestURI := "urn:solid:" + randomString(32)
	if _, err := h.authRequests.Register(ctx, h.issuer, requestURI, req); err != nil {
		t.Fatalf("unable to register authorization request: %v", err)
	}
	req.RequestUri = &requestURI

	res, err := h.authz.Authorize(ctx, &flowv1.AuthorizeRequest{
		Issuer:  h.issuer,
		Client:  client,
		Subject: "user-1",
		Request: req,
	})
	require.Error(t, err)
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_request", res.Error.Error)
	require.Equal(t, req.State, res.State, "the error response must echo the request state")
	require.Equal(t, h.issuer, res.Issuer, "the error response must carry the issuer identifier")
}

// -----------------------------------------------------------------------------
// §3.2.3 / §3.2.4 / §4.3.1: token-endpoint HTTP presentation —
// Cache-Control: no-store on every token response, the "error" JSON key, and
// token_type "DPoP" for DPoP-bound tokens (RFC 9449 section 6 via draft
// section 4.3.1).

// oauth21HTTPServer wires the real example Token handler behind the real
// client-authentication middleware and the harness service stack.
func oauth21HTTPServer(h *harness, dpopVerifier dpop.Verifier) *httptest.Server {
	return httptest.NewServer(httpkit.ClientAuthentication(
		h.clients,
		h.issuer,
		[]string{"ES256"},
		spiffe.NewStaticBundleSource(nil),
		inmemory.DPoPProofs(),
		profile.Strict(),
	)(httpkit.Token(h.issuer, h.tokenz, dpopVerifier, profile.Strict())))
}

// postToken performs a token-endpoint POST with urlencoded form values.
func postToken(t *testing.T, ts *httptest.Server, assertion, grantType string, form url.Values) (*http.Response, map[string]any) {
	t.Helper()

	form.Set("grant_type", grantType)
	form.Set("client_assertion_type", oidc.AssertionTypeJWTBearer)
	form.Set("client_assertion", assertion)

	res, err := http.PostForm(ts.URL, form)
	require.NoError(t, err)
	t.Cleanup(func() { _ = res.Body.Close() })

	var body map[string]any
	require.NoError(t, json.NewDecoder(res.Body).Decode(&body))
	return res, body
}

func TestOAuth21_TokenEndpointHTTPPresentation_3_2_3_3_2_4(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})
	ts := oauth21HTTPServer(h, buildDPoPVerifier())
	t.Cleanup(ts.Close)

	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, verifier, testRedirectURI))

	// Success: Cache-Control: no-store on the token response (§3.2.3).
	res, body := postToken(t, ts, validClientAssertion(t, client.ClientId), oidc.GrantTypeAuthorizationCode, url.Values{
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {testRedirectURI},
	})
	require.Equal(t, http.StatusOK, res.StatusCode, "body: %v", body)
	require.Equal(t, "no-store", res.Header.Get("Cache-Control"), "§3.2.3: token responses MUST NOT be cached")
	require.Equal(t, "Bearer", body["token_type"], "non-DPoP tokens signal Bearer")
	require.NotEmpty(t, body["access_token"])

	// Error: no-store on error responses too, and the error key is "error"
	// (§3.2.4). The code was burned by the redemption above.
	errRes, errBody := postToken(t, ts, validClientAssertion(t, client.ClientId), oidc.GrantTypeAuthorizationCode, url.Values{
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {testRedirectURI},
	})
	require.Equal(t, http.StatusBadRequest, errRes.StatusCode)
	require.Equal(t, "no-store", errRes.Header.Get("Cache-Control"), "§3.2.3: error responses must not be cached either")
	require.Equal(t, "invalid_grant", errBody["error"], "the wire error key MUST be \"error\" with the RFC 6749 §5.2 code")
	require.NotContains(t, errBody, "err", "the legacy \"err\" key must not appear")
}

func TestOAuth21_TokenEndpointDPoPTokenType_3_2(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})
	ts := oauth21HTTPServer(h, buildDPoPVerifier())
	t.Cleanup(ts.Close)

	// Mint a DPoP-bound code: authorization request carries dpop_jkt
	// (RFC 9449 section 10), the token request presents a DPoP proof.
	prover := buildDPoPProver(t)
	htu := h.issuer + "/resource"
	probeProof, err := prover.Prove("GET", htu)
	require.NoError(t, err)
	jkt, err := buildDPoPVerifier().Verify(t.Context(), "GET", htu, probeProof)
	require.NoError(t, err)

	verifier, _ := newPKCEPair(t)
	authzReq := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	authzReq.DpopJkt = &jkt
	code := h.seedAuthorization(t, client, authzReq)

	// DPoP proof for the token endpoint request itself.
	tokenHTU := ts.URL + "/"
	tokenProof, err := prover.Prove(http.MethodPost, tokenHTU)
	require.NoError(t, err)

	form := url.Values{
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {testRedirectURI},
	}
	form.Set("client_assertion_type", oidc.AssertionTypeJWTBearer)
	form.Set("client_assertion", validClientAssertion(t, client.ClientId))
	form.Set("grant_type", oidc.GrantTypeAuthorizationCode)

	req, err := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", tokenProof)

	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = res.Body.Close() })

	var body map[string]any
	require.NoError(t, json.NewDecoder(res.Body).Decode(&body))
	require.Equal(t, http.StatusOK, res.StatusCode, "body: %v", body)

	// RFC 9449 section 6 (via draft §4.3.1): the DPoP-bound access token
	// signals its sender-constraint through token_type "DPoP".
	require.Equal(t, "DPoP", body["token_type"], "DPoP-bound tokens MUST signal token_type DPoP")
	require.NotEmpty(t, body["access_token"])
	require.Equal(t, "no-store", res.Header.Get("Cache-Control"))
}

// -----------------------------------------------------------------------------
// helpers

// randomString wraps sdk/random.String for request URIs in this file.
func randomString(n int) string {
	return random.String(n)
}
