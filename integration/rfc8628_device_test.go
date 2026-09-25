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

	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	sessionv1 "zntr.io/solid/api/oidc/session/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/random"
)

// RFC 8628 (Device Authorization Grant) adversarial coverage, section 3.5
// error semantics.

// TestRFC8628_AuthorizationPending asserts polling before user approval
// yields authorization_pending (RFC 8628 section 3.5).
func TestRFC8628_AuthorizationPending(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeDeviceCode})

	deviceCode, _ := h.startDeviceAuthorization(t, client, []string{"openid"})

	res, err := h.pollDeviceToken(t, client.ClientId, deviceCode)
	require.Error(t, err, "poll before approval must fail")
	require.NotNil(t, res.Error)
	require.Equal(t, "authorization_pending", res.Error.Err)
}

// TestRFC8628_ApprovalThenToken asserts approval via the user code lets the
// device poll issue tokens (RFC 8628 section 3.4 / 3.5).
func TestRFC8628_ApprovalThenToken(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeDeviceCode})

	deviceCode, userCode := h.startDeviceAuthorization(t, client, []string{"openid"})
	h.approveDevice(t, userCode, "device-user-1")

	res, err := h.pollDeviceToken(t, client.ClientId, deviceCode)
	require.NoError(t, err)
	require.Nil(t, res.Error)
	require.NotNil(t, res.AccessToken)
	require.NotEmpty(t, res.AccessToken.Metadata.GrantId, "device-issued token must carry its grant id")
}

// TestRFC8628_ExpiredDeviceCode asserts an expired device session yields
// expired_token, not a storage miss: the session must outlive its expiry
// stamp in storage (RFC 8628 section 3.5).
func TestRFC8628_ExpiredDeviceCode(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeDeviceCode})

	// Hand-register a session already expired; the 10-minute storage TTL
	// keeps the entry resident so the grant's expiry branch runs.
	deviceCode := random.String(32)
	userCode := random.String(8)
	_, err := h.deviceSessions.Register(context.Background(), h.issuer, userCode, &sessionv1.DeviceCodeSession{
		Issuer:     h.issuer,
		Client:     client,
		Request:    &flowv1.DeviceAuthorizationRequest{Issuer: h.issuer, ClientId: client.ClientId},
		DeviceCode: deviceCode,
		Status:     sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_AUTHORIZATION_PENDING,
		ExpiresAt:  uint64(time.Now().Add(-time.Minute).Unix()),
	})
	require.NoError(t, err)

	res, err := h.pollDeviceToken(t, client.ClientId, deviceCode)
	require.Error(t, err, "expired device code must fail")
	require.NotNil(t, res.Error)
	require.Equal(t, "expired_token", res.Error.Err)
}

// TestRFC8628_AccessDenied asserts a denied device session yields
// access_denied (RFC 8628 section 3.5).
func TestRFC8628_AccessDenied(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeDeviceCode})

	deviceCode, userCode := h.startDeviceAuthorization(t, client, []string{"openid"})

	dres, derr := h.devicez.Deny(context.Background(), &flowv1.DeviceCodeValidationRequest{
		Issuer:   h.issuer,
		UserCode: userCode,
		Subject:  "device-user-1",
	})
	require.NoError(t, derr)
	require.Nil(t, dres.Error)

	res, err := h.pollDeviceToken(t, client.ClientId, deviceCode)
	require.Error(t, err, "denied device flow must fail")
	require.NotNil(t, res.Error)
	require.Equal(t, "access_denied", res.Error.Err)
}

// TestRFC8628_WrongClientPoll asserts client B cannot poll client A's device
// code (session-to-client binding).
func TestRFC8628_WrongClientPoll(t *testing.T) {
	h := newHarness(t)
	clientA := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeDeviceCode})
	clientB := h.registerConfidentialClient(t, []string{"https://client-b.example.org/cb"}, []string{oidc.GrantTypeDeviceCode})

	deviceCode, userCode := h.startDeviceAuthorization(t, clientA, []string{"openid"})
	h.approveDevice(t, userCode, "device-user-1")

	res, err := h.pollDeviceToken(t, clientB.ClientId, deviceCode)
	require.Error(t, err, "another client must not consume the device session")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_request", res.Error.Err)
}

// TestRFC8628_UnknownDeviceCode asserts an unknown device_code yields
// invalid_request (RFC 8628 section 3.5; unknown session).
func TestRFC8628_UnknownDeviceCode(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeDeviceCode})

	res, err := h.pollDeviceToken(t, client.ClientId, random.String(32))
	require.Error(t, err)
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_request", res.Error.Err)
}
