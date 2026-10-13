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
	"zntr.io/solid/oidc"
)

// Scope elevation adversarial coverage (RFC 6749 section 3.3: "If the
// client omits the scope parameter [...] the authorization server MAY use
// a preconfigured default value or process the request with an invalid
// scope"; section F.1.1: clients must not gain access beyond their
// entitlement). The attacker (A3) requests scope values beyond the client
// registration — the AS must fail closed with invalid_scope (solid stronger
// posture: no silent widening, no silent clamp).

// registerScopedConfidentialClient registers a confidential client with a
// pinned registered scope (the entitlement the AS enforces).
func registerScopedConfidentialClient(h *harness, t *testing.T, scope string) *clientv1.Client {
	t.Helper()

	c := &clientv1.Client{
		ClientName:              "scoped-adversarial-test-client",
		ClientType:              clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		GrantTypes:              []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken},
		ResponseTypes:           []string{oidc.ResponseTypeCode},
		ResponseModes:           []string{oidc.ResponseModeQueryJWT},
		RedirectUris:            []string{testRedirectURI},
		TokenEndpointAuthMethod: oidc.AuthMethodPrivateKeyJWT,
		Jwks:                    clientJWKSWithSIG,
		Scope:                   &scope,
	}

	if _, err := h.clients.Register(t.Context(), c); err != nil {
		t.Fatalf("unable to register scoped client: %v", err)
	}
	return c
}

// TestScope_ElevationBeyondClientRegistration asserts RFC 6749 section
// 3.3/F.1.1: a client whose registration pins "openid profile" cannot
// obtain an authorization for "openid profile admin" — the authorization
// request is rejected with invalid_scope, never silently granted.
func TestScope_ElevationBeyondClientRegistration(t *testing.T) {
	h := newHarness(t)
	client := registerScopedConfidentialClient(h, t, "openid profile")

	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	req.Scope = "openid profile admin"

	// Register the request (PAR-style) then drive Authorize: the
	// registered-scope enforcement fires inside validate.
	res, err := h.authz.Authorize(t.Context(), &flowv1.AuthorizeRequest{
		Issuer:  h.issuer,
		Client:  client,
		Subject: "user-1",
		Request: req,
	})
	require.Error(t, err, "scope beyond the client registration must be rejected")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_scope", res.Error.Error)
	require.Empty(t, res.Code, "no code may be issued for an elevated scope request")
}

// TestScope_ScopedTokenClaims_3_3 asserts RFC 6749 section 3.3: a request
// within the registration mints a token whose scope is exactly the
// requested set — no silent widening beyond what was asked.
func TestScope_ScopedTokenClaims_3_3(t *testing.T) {
	h := newHarness(t)
	client := registerScopedConfidentialClient(h, t, "openid profile")

	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	req.Scope = "openid profile"

	code := h.seedAuthorization(t, client, req)
	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.Nil(t, res.Error)
	require.NotNil(t, res.AccessToken)
	require.Equal(t, "openid profile", res.AccessToken.Metadata.Scope,
		"the minted scope is the requested set, no widening")
}

// TestScope_RefreshElevationRejected_6 asserts RFC 6749 section 6: a
// refresh request carrying a scope beyond the granted token's scope is an
// invalid_scope (narrowing only) — pinned here as the existing behavior of
// the refresh grant.
func TestScope_RefreshElevationRejected_6(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, verifier, testRedirectURI))
	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, res.RefreshToken)

	// Request a scope beyond the granted set ("admin" was never granted).
	elevate := refreshGrantRequest(h.issuer, client.ClientId, res.RefreshToken.Value)
	elevate.Scope = new("openid admin")
	h.authenticateClient(t, client.ClientId)
	elevated, err := h.tokenz.Token(t.Context(), elevate)
	require.Error(t, err)
	require.NotNil(t, elevated.Error)
	require.Equal(t, "invalid_scope", elevated.Error.Error)
}

// TestScope_RegistrationDefaultOpenEnded asserts the open-ended
// registration posture: clients registered without a pinned scope
// (harness fixtures) are unrestricted — every existing harness flow keeps
// working; the enforcement only bites on a pinned registration.
func TestScope_RegistrationDefaultOpenEnded(t *testing.T) {
	h := newHarness(t)
	// nil registered scope: open-ended.
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, verifier, testRedirectURI))
	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.Nil(t, res.Error)
	require.NotNil(t, res.AccessToken)
	require.Contains(t, res.AccessToken.Metadata.Scope, "openid")
}
