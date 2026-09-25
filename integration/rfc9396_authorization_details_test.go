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
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
)

// RFC 9396 (Rich Authorization Requests) end-to-end coverage: PAR →
// Authorize → code redemption → refresh, with token-endpoint narrowing
// semantics (section 6) and grant propagation (section 7).

// paymentInitiationDetail assembles the RFC 9396 running-example detail.
func paymentInitiationDetail() *tokenv1.AuthorizationDetail {
	return &tokenv1.AuthorizationDetail{
		Type:    "payment_initiation",
		Actions: []string{"initiate"},
		Locations: []string{
			"https://example.com/payment-initiation",
		},
		Extensions: map[string]*structpb.Value{
			"instructedAmount": structpb.NewStructValue(&structpb.Struct{
				Fields: map[string]*structpb.Value{
					"currency": structpb.NewStringValue("EUR"),
					"amount":   structpb.NewStringValue("123.45"),
				},
			}),
		},
	}
}

// TestRFC9396_AuthorizationDetailsEndToEnd walks the happy path: details
// seeded at authorization time (via the request object carried by PAR) are
// granted to the minted access and refresh tokens, returned in the token
// response (section 7), and survive a refresh (section 6).
func TestRFC9396_AuthorizationDetailsEndToEnd(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	details := []*tokenv1.AuthorizationDetail{
		paymentInitiationDetail(),
		{Type: "payment_initiation", Actions: []string{"read"}, Datatypes: []string{"transaction"}},
	}

	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	req.AuthorizationDetails = details
	code := h.seedAuthorization(t, client, req)

	// Redeem without requesting narrowing: the AS echoes the granted set.
	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, res.AccessToken)
	require.Empty(t, res.Error.GetErr())
	require.Len(t, res.AuthorizationDetails, 2)
	require.Len(t, res.AccessToken.Metadata.AuthorizationDetails, 2)
	require.True(t, proto.Equal(details[0], res.AccessToken.Metadata.AuthorizationDetails[0]),
		"granted details must proto-equal the consented entries")

	// Refresh without narrowing: the rotated tokens keep the granted set.
	rr, err := h.refresh(t, client.ClientId, res.RefreshToken.Value)
	require.NoError(t, err)
	require.Len(t, rr.AuthorizationDetails, 2)
	require.Len(t, rr.AccessToken.Metadata.AuthorizationDetails, 2)
}

// TestRFC9396_TokenEndpointNarrowing_6 asserts a client may request a
// subset of the granted authorization_details at the token endpoint; the
// minted tokens carry exactly the requested subset (section 6.1).
func TestRFC9396_TokenEndpointNarrowing_6(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	both := []*tokenv1.AuthorizationDetail{
		paymentInitiationDetail(),
		{Type: "payment_initiation", Actions: []string{"read"}, Datatypes: []string{"transaction"}},
	}

	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	req.AuthorizationDetails = both
	code := h.seedAuthorization(t, client, req)

	// Request only the first entry: the narrowed set must be granted.
	msg := codeGrantRequest(h.issuer, client.ClientId, code, verifier, testRedirectURI)
	msg.AuthorizationDetails = []*tokenv1.AuthorizationDetail{both[0]}
	h.authenticateClient(t, client.ClientId)
	res, err := h.tokenz.Token(t.Context(), msg)
	require.NoError(t, err)
	require.Empty(t, res.Error.GetErr())
	require.Len(t, res.AuthorizationDetails, 1)
	require.True(t, proto.Equal(both[0], res.AuthorizationDetails[0]))
	require.Len(t, res.AccessToken.Metadata.AuthorizationDetails, 1)
	require.True(t, proto.Equal(both[0], res.AccessToken.Metadata.AuthorizationDetails[0]))

	// The narrowed refresh token keeps the narrowed set (never more).
	rr, err := h.refresh(t, client.ClientId, res.RefreshToken.Value)
	require.NoError(t, err)
	require.Len(t, rr.AccessToken.Metadata.AuthorizationDetails, 1)
	require.True(t, proto.Equal(both[0], rr.AccessToken.Metadata.AuthorizationDetails[0]))

	// Narrowing further on refresh is permitted within the granted set.
	rmsg := refreshGrantRequest(h.issuer, client.ClientId, rr.RefreshToken.Value)
	rmsg.AuthorizationDetails = []*tokenv1.AuthorizationDetail{both[0]}
	h.authenticateClient(t, client.ClientId)
	nres, nerr := h.tokenz.Token(t.Context(), rmsg)
	require.NoError(t, nerr)
	require.Empty(t, nres.Error.GetErr())
	require.Len(t, nres.AuthorizationDetails, 1)
}

// TestRFC9396_NarrowingViolationRejected_6 asserts requesting an entry not
// consented in the grant is an invalid_authorization_details (section 6:
// the AS MUST NOT grant more than consented).
func TestRFC9396_NarrowingViolationRejected_6(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	granted := []*tokenv1.AuthorizationDetail{paymentInitiationDetail()}

	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	req.AuthorizationDetails = granted
	code := h.seedAuthorization(t, client, req)

	// The entry differs from the consented one (different amount): no
	// proto-equal match exists in the grant.
	forged := paymentInitiationDetail()
	forged.Extensions = map[string]*structpb.Value{
		"instructedAmount": structpb.NewStructValue(&structpb.Struct{
			Fields: map[string]*structpb.Value{
				"currency": structpb.NewStringValue("EUR"),
				"amount":   structpb.NewStringValue("999999.00"),
			},
		}),
	}

	msg := codeGrantRequest(h.issuer, client.ClientId, code, verifier, testRedirectURI)
	msg.AuthorizationDetails = []*tokenv1.AuthorizationDetail{forged}
	h.authenticateClient(t, client.ClientId)
	res, err := h.tokenz.Token(t.Context(), msg)
	require.Error(t, err, "an entry not consented must be rejected")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_authorization_details", res.Error.Err)
	require.Nil(t, res.AccessToken)
}

// TestRFC9396_ClientCredentialsFailsClosed asserts the client_credentials
// grant rejects token requests carrying authorization_details: details are
// consent-bound and this grant has no consent authority.
func TestRFC9396_ClientCredentialsFailsClosed(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeClientCredentials})

	msg := &flowv1.TokenRequest{
		Issuer:    h.issuer,
		GrantType: oidc.GrantTypeClientCredentials,
		Client:    &clientv1.Client{ClientId: client.ClientId},
		Grant: &flowv1.TokenRequest_ClientCredentials{
			ClientCredentials: &flowv1.GrantClientCredentials{},
		},
		AuthorizationDetails: []*tokenv1.AuthorizationDetail{paymentInitiationDetail()},
	}
	h.authenticateClient(t, client.ClientId)
	res, err := h.tokenz.Token(t.Context(), msg)
	require.Error(t, err, "client_credentials must not carry authorization_details")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_authorization_details", res.Error.Err)
}

// TestRFC9396_DeviceFlowCarriesDetails asserts the device authorization
// request's authorization_details ride the session into the minted access
// token (section 3), and the device grant rejects token-endpoint
// narrowing attempts.
func TestRFC9396_DeviceFlowCarriesDetails(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeDeviceCode})

	details := []*tokenv1.AuthorizationDetail{paymentInitiationDetail()}

	scope := "openid"
	dres, derr := h.devicez.Authorize(t.Context(), &flowv1.DeviceAuthorizationRequest{
		Issuer:               h.issuer,
		ClientId:             client.ClientId,
		Scope:                &scope,
		AuthorizationDetails: details,
	})
	require.NoError(t, derr)
	require.Nil(t, dres.Error)

	h.approveDevice(t, dres.UserCode, "device-user-1")

	res, err := h.pollDeviceToken(t, client.ClientId, dres.DeviceCode)
	require.NoError(t, err)
	require.Empty(t, res.Error.GetErr())
	require.NotNil(t, res.AccessToken)
	require.Len(t, res.AccessToken.Metadata.AuthorizationDetails, 1)
	require.True(t, proto.Equal(details[0], res.AccessToken.Metadata.AuthorizationDetails[0]),
		"device token must carry the session's consented details")

	// A second device authorization with a narrowing attempt at the token
	// endpoint is rejected: details are fixed at device authorization time.
	dres2, derr2 := h.devicez.Authorize(t.Context(), &flowv1.DeviceAuthorizationRequest{
		Issuer:               h.issuer,
		ClientId:             client.ClientId,
		Scope:                &scope,
		AuthorizationDetails: details,
	})
	require.NoError(t, derr2)
	h.approveDevice(t, dres2.UserCode, "device-user-2")

	msg := deviceTokenRequest(h.issuer, client.ClientId, dres2.DeviceCode)
	msg.AuthorizationDetails = details
	h.authenticateClient(t, client.ClientId)
	nres, nerr := h.tokenz.Token(t.Context(), msg)
	require.Error(t, nerr, "device grant must not accept authorization_details at the token endpoint")
	require.NotNil(t, nres.Error)
	require.Equal(t, "invalid_authorization_details", nres.Error.Err)
}
