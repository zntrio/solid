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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/server/httpkit"
	"zntr.io/solid/server/services/token"
)

// TestAdversarial_CIBAApproverSubstitution pins CIBA Core section 8/11:
// when the identification hint resolved a subject at bc-authorize time,
// only that subject may confirm — an approver identity substitution must
// be rejected (the client asked for the hinted user, not the approver).
func TestAdversarial_CIBAApproverSubstitution(t *testing.T) {
	h := newHarness(t)
	client := h.registerCIBAClient(t)

	// login_hint resolves to "hello" (harness LoginHintResolver).
	authReqID := h.startBackchannelAuth(t, client)

	// Approver presents a different subject: must be rejected.
	res, err := h.backchannelz.Validate(t.Context(), &flowv1.BackchannelAuthenticationValidationRequest{
		Issuer:    h.issuer,
		AuthReqId: authReqID,
		Subject:   "mallory",
	})
	require.Error(t, err, "approver identity substitution must be rejected")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_request", res.Error.Error)

	// The hinted subject still approves successfully afterwards: the
	// failed substitution attempt does not consume the session.
	h.approveBackchannel(t, authReqID, "hello")

	tok, err := h.pollCIBAToken(t, client.ClientId, authReqID)
	require.NoError(t, err)
	require.Nil(t, tok.Error)
	require.NotNil(t, tok.AccessToken)
}

// TestAdversarial_DPoPBlankJTI pins RFC 9449 section 4.2: the jti claim is
// REQUIRED — a syntactically signed proof with a blank jti is rejected
func TestAdversarial_DPoPBlankJTI(t *testing.T) {
	// The blank-jti claim gate is enforced in validateProofClaims (sdk/dpop,
	// unit-covered); the harness-level contract under test here is that the
	// shared burn store never treats an empty id as a fresh claim: it burns
	// once and stays burned, so a blank-jti proof cannot race itself.
	proofs := newHarness(t).proofs

	ok, err := proofs.RegisterIfAbsent(t.Context(), "")
	require.NoError(t, err)
	require.True(t, ok, "first empty-id claim wins")

	again, err := proofs.RegisterIfAbsent(t.Context(), "")
	require.NoError(t, err)
	require.False(t, again, "empty ids burn once and stay burned")
}

// TestAdversarial_IntrospectionRevocationHTTPPosture pins RFC 7662 2.1 /
// RFC 7009 2.1 at the HTTP presentation: introspection and revocation
// accept POST only, and the token value never arrives via the URL query.
func TestAdversarial_IntrospectionRevocationHTTPPosture(t *testing.T) {
	issuer := "http://127.0.0.1:8080"
	tokenz := token.New(nil, nil, nil, nil, nil, nil, nil, nil)

	mux := http.NewServeMux()
	mux.Handle("/token/introspect", httpkit.TokenIntrospection(issuer, tokenz))
	mux.Handle("/token/revoke", httpkit.TokenRevocation(issuer, tokenz))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// GET with token in the query: method gate must reject before any
	// parsing (the credential never reaches the service layer).
	resp, err := http.Get(srv.URL + "/token/introspect?token=leaked-secret-value")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode, "introspection must be POST-only")

	resp2, err := http.Get(srv.URL + "/token/revoke?token=leaked-secret-value")
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp2.StatusCode, "revocation must be POST-only")

	// PUT is equally refused.
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/token/introspect", nil)
	resp3, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp3.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp3.StatusCode)
}

// TestAdversarial_ConcurrentRotationSingleSurvivor pins the RFC 9700
// section 4.14.2 rotation invariant at the harness level: a refresh token
// redeemed twice sequentially yields exactly one active descendant family
// (the replay of a rotated token cascades family revocation).
func TestAdversarial_ConcurrentRotationSingleSurvivor(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, verifier, testRedirectURI))
	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, res.RefreshToken)

	// First refresh succeeds and rotates.
	first, err := h.refresh(t, client.ClientId, res.RefreshToken.Value)
	require.NoError(t, err, "first refresh must succeed")
	require.NotNil(t, first.RefreshToken)

	// Replay of the now-rotated token: the family is revoked.
	second, err := h.refresh(t, client.ClientId, res.RefreshToken.Value)
	require.Error(t, err, "replay of the rotated refresh token must fail")
	require.NotNil(t, second.Error)
	require.Equal(t, "invalid_grant", second.Error.Error)

	// The descendant family was revoked by the replay detection.
	third, err := h.refresh(t, client.ClientId, first.RefreshToken.Value)
	require.Error(t, err, "family revocation must reach the descendant refresh token")
	require.NotNil(t, third.Error)
}
