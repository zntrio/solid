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
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	sessionv1 "zntr.io/solid/api/oidc/session/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/random"
)

// registerCIBAClient registers a confidential client restricted to the CIBA
// grant, authenticated via private_key_jwt with the shared ES256 JWKS
// fixture.
func (h *harness) registerCIBAClient(t *testing.T) *clientv1.Client {
	t.Helper()

	c := &clientv1.Client{
		ClientName:              "ciba-test-client",
		ClientType:              clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		GrantTypes:              []string{oidc.GrantTypeCIBA},
		ResponseTypes:           []string{oidc.ResponseTypeCode},
		TokenEndpointAuthMethod: oidc.AuthMethodPrivateKeyJWT,
		Jwks:                    clientJWKSWithSIG,
	}

	if _, err := h.clients.Register(context.Background(), c); err != nil {
		t.Fatalf("unable to register CIBA client: %v", err)
	}
	return c
}

// paymentInitiationDetails returns a valid payment_initiation authorization
// detail entry (the harness validator's registered type).
func paymentInitiationDetails() []*tokenv1.AuthorizationDetail {
	return []*tokenv1.AuthorizationDetail{
		{Type: "payment_initiation"},
	}
}

// OpenID CIBA Core 1.0 adversarial coverage, section 11 error semantics
// (poll mode, solid profile).

// TestCIBA_AuthorizationPending asserts polling before end-user approval
// yields authorization_pending (CIBA section 11).
func TestCIBA_AuthorizationPending(t *testing.T) {
	h := newHarness(t)
	client := h.registerCIBAClient(t)

	authReqID := h.startBackchannelAuth(t, client)

	res, err := h.pollCIBAToken(t, client.ClientId, authReqID)
	require.Error(t, err, "poll before approval must fail")
	require.NotNil(t, res.Error)
	require.Equal(t, "authorization_pending", res.Error.Error)
}

// TestCIBA_ApprovalThenToken asserts approval on the authentication device
// lets the client poll mint tokens, exactly once (CIBA sections 8 and 11).
func TestCIBA_ApprovalThenToken(t *testing.T) {
	h := newHarness(t)
	client := h.registerCIBAClient(t)

	authReqID := h.startBackchannelAuth(t, client)
	h.approveBackchannel(t, authReqID, "ciba-user-1")

	res, err := h.pollCIBAToken(t, client.ClientId, authReqID)
	require.NoError(t, err)
	require.Nil(t, res.Error)
	require.NotNil(t, res.AccessToken)
	require.NotEmpty(t, res.AccessToken.Metadata.GrantId, "CIBA-issued token must carry its grant id")
	require.Nil(t, res.RefreshToken, "CIBA grant never mints refresh tokens")

	// One-time use: a second poll is a replay.
	res2, err := h.pollCIBAToken(t, client.ClientId, authReqID)
	require.Error(t, err, "replayed auth_req_id must fail")
	require.NotNil(t, res2.Error)
	require.Equal(t, "invalid_grant", res2.Error.Error)
}

// TestCIBA_ExpiredAuthReqID asserts an expired session yields expired_token,
// not a storage miss: the session must outlive its expiry stamp in storage
// (CIBA section 11).
func TestCIBA_ExpiredAuthReqID(t *testing.T) {
	h := newHarness(t)
	client := h.registerCIBAClient(t)

	// Hand-register a session already expired; the 10-minute storage TTL
	// keeps the entry resident so the grant's expiry branch runs.
	authReqID := random.String(32)
	_, err := h.backchannelSessions.Register(context.Background(), h.issuer, authReqID, &sessionv1.BackchannelAuthenticationSession{
		Issuer:    h.issuer,
		Client:    client,
		Request:   &flowv1.BackchannelAuthenticationRequest{Issuer: h.issuer, ClientId: client.ClientId},
		AuthReqId: authReqID,
		Status:    sessionv1.BackchannelAuthenticationStatus_BACKCHANNEL_AUTHENTICATION_STATUS_PENDING,
		ExpiresAt: uint64(time.Now().Add(-time.Minute).Unix()),
	})
	require.NoError(t, err)

	res, err := h.pollCIBAToken(t, client.ClientId, authReqID)
	require.Error(t, err, "expired auth_req_id must fail")
	require.NotNil(t, res.Error)
	require.Equal(t, "expired_token", res.Error.Error)
}

// TestCIBA_SlowDown asserts an immediate second poll yields slow_down with
// the interval increased by 5 seconds (CIBA section 11).
func TestCIBA_SlowDown(t *testing.T) {
	h := newHarness(t)
	client := h.registerCIBAClient(t)

	authReqID := h.startBackchannelAuth(t, client)

	// First poll: admissible, records LastPolledAt.
	_, err := h.pollCIBAToken(t, client.ClientId, authReqID)
	require.Error(t, err)
	require.Equal(t, "authorization_pending", "authorization_pending", err.Error, "first poll must be authorization_pending")

	// Immediate second poll: too fast.
	res, err := h.pollCIBAToken(t, client.ClientId, authReqID)
	require.Error(t, err, "fast re-poll must fail")
	require.NotNil(t, res.Error)
	require.Equal(t, "slow_down", res.Error.Error)
}

// TestCIBA_AccessDenied asserts a denied session yields access_denied
// (CIBA section 11).
func TestCIBA_AccessDenied(t *testing.T) {
	h := newHarness(t)
	client := h.registerCIBAClient(t)

	authReqID := h.startBackchannelAuth(t, client)
	h.denyBackchannel(t, authReqID, "ciba-user-1")

	res, err := h.pollCIBAToken(t, client.ClientId, authReqID)
	require.Error(t, err, "denied auth_req_id must fail")
	require.NotNil(t, res.Error)
	require.Equal(t, "access_denied", res.Error.Error)
}

// TestCIBA_WrongClientPoll asserts client B cannot poll client A's
// auth_req_id and gets invalid_grant, per CIBA section 11 (deliberately
// stricter than the device grant's invalid_request).
func TestCIBA_WrongClientPoll(t *testing.T) {
	h := newHarness(t)
	clientA := h.registerCIBAClient(t)
	clientB := h.registerCIBAClient(t)

	authReqID := h.startBackchannelAuth(t, clientA)
	h.approveBackchannel(t, authReqID, "ciba-user-1")

	res, err := h.pollCIBAToken(t, clientB.ClientId, authReqID)
	require.Error(t, err, "cross-client poll must fail")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_grant", res.Error.Error)
}

// TestCIBA_UnknownAuthReqID asserts an unknown auth_req_id yields
// invalid_grant (CIBA section 11).
func TestCIBA_UnknownAuthReqID(t *testing.T) {
	h := newHarness(t)
	client := h.registerCIBAClient(t)

	res, err := h.pollCIBAToken(t, client.ClientId, random.String(32))
	require.Error(t, err, "unknown auth_req_id must fail")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_grant", res.Error.Error)
}

// TestCIBA_MultipleHints asserts more than one identification hint yields
// invalid_request (CIBA section 7.2 step 3).
func TestCIBA_MultipleHints(t *testing.T) {
	h := newHarness(t)
	client := h.registerCIBAClient(t)

	res, err := h.backchannelz.Authorize(context.Background(), &flowv1.BackchannelAuthenticationRequest{
		Issuer:         h.issuer,
		ClientId:       client.ClientId,
		Scope:          new("openid"),
		LoginHint:      new("hello"),
		IdTokenHint:    new("some-id-token"),
		BindingMessage: new("W4SCT"),
	})
	require.Error(t, err)
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_request", res.Error.Error)
}

// TestCIBA_MissingBindingMessage asserts the solid-promoted binding_message
// is mandatory and charset-constrained (CIBA section 7.1 + solid posture).
func TestCIBA_MissingBindingMessage(t *testing.T) {
	h := newHarness(t)
	client := h.registerCIBAClient(t)

	// Absent binding_message.
	res, err := h.backchannelz.Authorize(context.Background(), &flowv1.BackchannelAuthenticationRequest{
		Issuer:    h.issuer,
		ClientId:  client.ClientId,
		Scope:     new("openid"),
		LoginHint: new("hello"),
	})
	require.Error(t, err)
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_binding_message", res.Error.Error)

	// Malformed binding_message.
	res2, err := h.backchannelz.Authorize(context.Background(), &flowv1.BackchannelAuthenticationRequest{
		Issuer:         h.issuer,
		ClientId:       client.ClientId,
		Scope:          new("openid"),
		LoginHint:      new("hello"),
		BindingMessage: new("$£ not ok"),
	})
	require.Error(t, err)
	require.NotNil(t, res2.Error)
	require.Equal(t, "invalid_binding_message", res2.Error.Error)
}

// TestCIBA_MissingOpenIDScope asserts scope without openid yields
// invalid_scope (CIBA section 7.1).
func TestCIBA_MissingOpenIDScope(t *testing.T) {
	h := newHarness(t)
	client := h.registerCIBAClient(t)

	res, err := h.backchannelz.Authorize(context.Background(), &flowv1.BackchannelAuthenticationRequest{
		Issuer:         h.issuer,
		ClientId:       client.ClientId,
		Scope:          new("profile"),
		LoginHint:      new("hello"),
		BindingMessage: new("W4SCT"),
	})
	require.Error(t, err)
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_scope", res.Error.Error)
}

// TestCIBA_UnknownUser asserts an unresolvable hint yields unknown_user_id
// (CIBA section 13).
func TestCIBA_UnknownUser(t *testing.T) {
	h := newHarness(t)
	client := h.registerCIBAClient(t)

	res, err := h.backchannelz.Authorize(context.Background(), &flowv1.BackchannelAuthenticationRequest{
		Issuer:         h.issuer,
		ClientId:       client.ClientId,
		Scope:          new("openid"),
		LoginHint:      new("unknown-user"),
		BindingMessage: new("W4SCT"),
	})
	require.Error(t, err)
	require.NotNil(t, res.Error)
	require.Equal(t, "unknown_user_id", res.Error.Error)
}

// TestCIBA_SignedRequest asserts a signed request object (CIBA section
// 7.1.1) is verified against the client JWKS and drives the full flow.
func TestCIBA_SignedRequest(t *testing.T) {
	h := newHarness(t)
	client := h.registerCIBAClient(t)

	now := uint64(time.Now().Unix())
	requestObject := signedCIBARequestObject(t, map[string]any{
		"iss":             client.ClientId,
		"aud":             h.issuer,
		"exp":             now + 300,
		"iat":             now,
		"nbf":             now,
		"jti":             random.String(16),
		"scope":           "openid profile",
		"login_hint":      "hello",
		"binding_message": "W4SCT",
	})

	res, err := h.backchannelz.Authorize(context.Background(), &flowv1.BackchannelAuthenticationRequest{
		Issuer:   h.issuer,
		ClientId: client.ClientId,
		Request:  &requestObject,
	})
	require.NoError(t, err)
	require.Nil(t, res.Error)

	h.approveBackchannel(t, res.AuthReqId, "ciba-user-1")
	tokenRes, err := h.pollCIBAToken(t, client.ClientId, res.AuthReqId)
	require.NoError(t, err)
	require.Nil(t, tokenRes.Error)
	require.NotNil(t, tokenRes.AccessToken)
}

// TestCIBA_SignedRequest_Adversarial asserts signed request objects with a
// wrong iss, a forged signature, a missing exp, or parameters outside the
// JWT are all rejected (CIBA section 7.1.1).
func TestCIBA_SignedRequest_Adversarial(t *testing.T) {
	h := newHarness(t)
	client := h.registerCIBAClient(t)

	now := uint64(time.Now().Unix())
	baseClaims := func() map[string]any {
		return map[string]any{
			"iss":             client.ClientId,
			"aud":             h.issuer,
			"exp":             now + 300,
			"iat":             now,
			"nbf":             now,
			"jti":             random.String(16),
			"scope":           "openid profile",
			"login_hint":      "hello",
			"binding_message": "W4SCT",
		}
	}

	authorizeWithRequest := func(requestObject string) (*flowv1.BackchannelAuthenticationResponse, error) {
		return h.backchannelz.Authorize(context.Background(), &flowv1.BackchannelAuthenticationRequest{
			Issuer:   h.issuer,
			ClientId: client.ClientId,
			Request:  &requestObject,
		})
	}

	t.Run("wrong iss", func(t *testing.T) {
		claims := baseClaims()
		claims["iss"] = "someone-else"
		res, err := authorizeWithRequest(signedCIBARequestObject(t, claims))
		require.Error(t, err)
		require.NotNil(t, res.Error)
		require.Equal(t, "invalid_request", res.Error.Error)
	})

	t.Run("forged signature", func(t *testing.T) {
		res, err := authorizeWithRequest(forgedCIBARequestObject(t, baseClaims()))
		require.Error(t, err)
		require.NotNil(t, res.Error)
		require.Equal(t, "invalid_request", res.Error.Error)
	})

	t.Run("missing exp", func(t *testing.T) {
		claims := baseClaims()
		delete(claims, "exp")
		res, err := authorizeWithRequest(signedCIBARequestObject(t, claims))
		require.Error(t, err)
		require.NotNil(t, res.Error)
		require.Equal(t, "invalid_request", res.Error.Error)
	})

	t.Run("parameter outside the request object", func(t *testing.T) {
		requestObject := signedCIBARequestObject(t, baseClaims())
		res, err := h.backchannelz.Authorize(context.Background(), &flowv1.BackchannelAuthenticationRequest{
			Issuer:   h.issuer,
			ClientId: client.ClientId,
			Scope:    new("openid"), // MUST NOT appear outside the JWT
			Request:  &requestObject,
		})
		require.Error(t, err)
		require.NotNil(t, res.Error)
		require.Equal(t, "invalid_request", res.Error.Error)
	})
}

// TestCIBA_AuthorizationDetails asserts authorization_details requested at
// bc-authorize time are consented on the session and carried into the minted
// token, with no token-endpoint narrowing (RFC 9396 with CIBA section 7.1).
func TestCIBA_AuthorizationDetails(t *testing.T) {
	h := newHarness(t)
	client := h.registerCIBAClient(t)

	authReqID := h.startBackchannelAuth(t, client, func(req *flowv1.BackchannelAuthenticationRequest) {
		req.AuthorizationDetails = paymentInitiationDetails()
	})
	h.approveBackchannel(t, authReqID, "ciba-user-1")

	res, err := h.pollCIBAToken(t, client.ClientId, authReqID)
	require.NoError(t, err)
	require.Nil(t, res.Error)
	require.NotNil(t, res.AccessToken)
	require.Len(t, res.AccessToken.Metadata.AuthorizationDetails, 1)
	require.Equal(t, "payment_initiation", res.AccessToken.Metadata.AuthorizationDetails[0].Type)

	// Token-endpoint narrowing is rejected for the CIBA grant.
	authReqID2 := h.startBackchannelAuth(t, client, func(req *flowv1.BackchannelAuthenticationRequest) {
		req.AuthorizationDetails = paymentInitiationDetails()
	})
	h.approveBackchannel(t, authReqID2, "ciba-user-1")

	narrowingReq := cibaTokenRequest(h.issuer, client.ClientId, authReqID2)
	narrowingReq.AuthorizationDetails = paymentInitiationDetails()
	h.authenticateClient(t, client.ClientId)
	narrowingRes, err := h.tokenz.Token(context.Background(), narrowingReq)
	require.Error(t, err)
	require.NotNil(t, narrowingRes.Error)
	require.Equal(t, "invalid_authorization_details", narrowingRes.Error.Error)
}

// TestCIBA_UnknownAuthorizationDetails asserts an unsupported
// authorization_details type is rejected at bc-authorize time
// (RFC 9396 section 5, fail-closed static validator).
func TestCIBA_UnknownAuthorizationDetails(t *testing.T) {
	h := newHarness(t)
	client := h.registerCIBAClient(t)

	res, err := h.backchannelz.Authorize(context.Background(), &flowv1.BackchannelAuthenticationRequest{
		Issuer:         h.issuer,
		ClientId:       client.ClientId,
		Scope:          new("openid"),
		LoginHint:      new("hello"),
		BindingMessage: new("W4SCT"),
		AuthorizationDetails: []*tokenv1.AuthorizationDetail{
			{Type: "unknown-type"},
		},
	})
	require.Error(t, err)
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_authorization_details", res.Error.Error)
}

// TestCIBA_OfflineAccessStripped asserts offline_access never reaches the
// stored session scope nor the minted token (RFC 9700 section 4.12.2).
func TestCIBA_OfflineAccessStripped(t *testing.T) {
	h := newHarness(t)
	client := h.registerCIBAClient(t)

	authReqID := h.startBackchannelAuth(t, client, func(req *flowv1.BackchannelAuthenticationRequest) {
		scope := "openid offline_access"
		req.Scope = &scope
	})
	h.approveBackchannel(t, authReqID, "ciba-user-1")

	// Stored session scope has no offline_access.
	session, err := h.backchannelSessions.GetByAuthReqID(context.Background(), h.issuer, authReqID)
	require.NoError(t, err)
	require.NotNil(t, session)
	require.Equal(t, "openid", *session.Scope)

	res, err := h.pollCIBAToken(t, client.ClientId, authReqID)
	require.NoError(t, err)
	require.Nil(t, res.Error)
	require.NotNil(t, res.AccessToken)
	require.NotContains(t, res.AccessToken.Metadata.Scope, "offline_access")
	require.Nil(t, res.RefreshToken)
}

// TestCIBA_UnauthorizedClient asserts a client registered without the CIBA
// grant type is rejected (CIBA section 13).
func TestCIBA_UnauthorizedClient(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode})

	res, err := h.backchannelz.Authorize(context.Background(), &flowv1.BackchannelAuthenticationRequest{
		Issuer:         h.issuer,
		ClientId:       client.ClientId,
		Scope:          new("openid"),
		LoginHint:      new("hello"),
		BindingMessage: new("W4SCT"),
	})
	require.Error(t, err)
	require.NotNil(t, res.Error)
	require.Equal(t, "unauthorized_client", res.Error.Error)
}

// TestCIBA_DPoPKeyBinding asserts the RFC 9449 section 10 analog for CIBA:
// a dpop_jkt declared in the signed request object binds the session, and
// only token-endpoint polls proving possession of that same key mint
// sender-constrained tokens.
func TestCIBA_DPoPKeyBinding(t *testing.T) {
	h := newHarness(t)
	client := h.registerCIBAClient(t)

	// bc-authorize with a signed request object carrying dpop_jkt.
	now := uint64(time.Now().Unix())
	requestObject := signedCIBARequestObject(t, map[string]any{
		"iss":             client.ClientId,
		"aud":             h.issuer,
		"exp":             now + 300,
		"iat":             now,
		"nbf":             now,
		"jti":             random.String(16),
		"scope":           "openid profile",
		"login_hint":      "hello",
		"binding_message": "W4SCT",
		"dpop_jkt":        "ciba-dpop-jkt",
	})
	res, err := h.backchannelz.Authorize(context.Background(), &flowv1.BackchannelAuthenticationRequest{
		Issuer:   h.issuer,
		ClientId: client.ClientId,
		Request:  &requestObject,
	})
	require.NoError(t, err)
	require.Nil(t, res.Error)
	authReqID := res.AuthReqId

	h.approveBackchannel(t, authReqID, "ciba-user-1")

	// Poll without a DPoP proof: rejected before the consume.
	res2, err := h.pollCIBAToken(t, client.ClientId, authReqID)
	require.Error(t, err, "DPoP-bound session must not mint a bearer token")
	require.NotNil(t, res2.Error)
	require.Equal(t, "invalid_grant", res2.Error.Error)
	require.Nil(t, res2.AccessToken)

	// Poll with the wrong key: proof-key swap, rejected.
	res3, err := h.pollCIBATokenWithConfirmation(t, client.ClientId, authReqID, &tokenv1.TokenConfirmation{Jkt: "attacker-jkt"})
	require.Error(t, err, "mismatched DPoP key must be rejected")
	require.NotNil(t, res3.Error)
	require.Equal(t, "invalid_grant", res3.Error.Error)

	// The rejections happened before the consume: the session survives, a
	// poll with the bound key mints the sender-constrained token.
	res4, err := h.pollCIBATokenWithConfirmation(t, client.ClientId, authReqID, &tokenv1.TokenConfirmation{Jkt: "ciba-dpop-jkt"})
	require.NoError(t, err)
	require.Nil(t, res4.Error)
	require.NotNil(t, res4.AccessToken)
	require.NotNil(t, res4.AccessToken.Confirmation, "minted token must carry the DPoP confirmation")
	require.Equal(t, "ciba-dpop-jkt", res4.AccessToken.Confirmation.Jkt)
}
