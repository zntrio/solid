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

	"github.com/stretchr/testify/require"

	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
)

// RFC 10027 (BCP 247, Security of Cross-Device Flows) adversarial coverage for
// the RFC 8628 device authorization grant — the repo's one RFC 10027-susceptible
// protocol (User-Transferred Session Data Pattern, RFC 10027 section 3.1.1).
// Each test plays a concrete attacker from the RFC's threat model.

// TestRFC10027_DeviceCodeSingleUse asserts one-time device codes (RFC 10027
// section 6.1.3, exploit B1 token harvesting): after a validated session mints
// tokens, re-polling the same device_code fails — a phished code cannot be
// re-polled for a second token set.
func TestRFC10027_DeviceCodeSingleUse(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeDeviceCode})

	deviceCode, userCode := h.startDeviceAuthorization(t, client, []string{"openid"})
	h.approveDevice(t, userCode, "device-user-1")

	res, err := h.pollDeviceToken(t, client.ClientId, deviceCode)
	require.NoError(t, err)
	require.Nil(t, res.Error)
	require.NotNil(t, res.AccessToken)

	// Attacker replays the phished device_code at the token endpoint.
	res2, err2 := h.pollDeviceToken(t, client.ClientId, deviceCode)
	require.Error(t, err2, "consumed device code must not mint tokens twice")
	require.NotNil(t, res2.Error)
	require.Equal(t, "invalid_request", res2.Error.Err)
	require.Nil(t, res2.AccessToken)
}

// TestRFC10027_SlowDownOnFastPolling asserts the server-enforced polling
// interval (RFC 10027 section 6.1.11, RFC 8628 section 3.5): polling faster
// than the advertised interval yields slow_down, and every violation grows
// the required interval by 5 seconds. Consecutive calls are microseconds
// apart, well under the 5 second interval — no sleeps needed.
func TestRFC10027_SlowDownOnFastPolling(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeDeviceCode})

	deviceCode, _ := h.startDeviceAuthorization(t, client, []string{"openid"})

	// First poll: admissible, records the poll timestamp.
	res, err := h.pollDeviceToken(t, client.ClientId, deviceCode)
	require.Error(t, err)
	require.NotNil(t, res.Error)
	require.Equal(t, "authorization_pending", res.Error.Err)

	// Immediate second poll: slow_down.
	res2, err2 := h.pollDeviceToken(t, client.ClientId, deviceCode)
	require.Error(t, err2, "fast poll must be rejected")
	require.NotNil(t, res2.Error)
	require.Equal(t, "slow_down", res2.Error.Err)

	// Immediate third poll: still slow_down — the interval grew 5 -> 10.
	res3, err3 := h.pollDeviceToken(t, client.ClientId, deviceCode)
	require.Error(t, err3, "fast poll must stay rejected after a slow_down")
	require.NotNil(t, res3.Error)
	require.Equal(t, "slow_down", res3.Error.Err)
}

// TestRFC10027_UserCodeBruteForceThrottled asserts user-code attempt
// throttling (RFC 10027 section 6.1.11, RFC 8628 section 5.1): an attacker
// hammering the verification endpoint with wrong codes locks the subject
// out — the 6th attempt is rejected with access_denied even with the
// CORRECT code. The negative control proves legitimate first-attempt users
// are unaffected (the counter resets on success).
func TestRFC10027_UserCodeBruteForceThrottled(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeDeviceCode})

	deviceCode, userCode := h.startDeviceAuthorization(t, client, []string{"openid"})

	// Attacker burns the attempt budget with wrong codes (5 per subject
	// per window, server/services/device maxUserCodeAttempts).
	for i := 0; i < 5; i++ {
		res, err := h.devicez.Validate(context.Background(), &flowv1.DeviceCodeValidationRequest{
			Issuer:   h.issuer,
			UserCode: "BBBB-CCCC",
			Subject:  "attacker-1",
		})
		require.Error(t, err)
		require.NotNil(t, res.Error)
		require.Equal(t, "invalid_request", res.Error.Err)
	}

	// 6th attempt carries the CORRECT user code: throttled anyway.
	res, err := h.devicez.Validate(context.Background(), &flowv1.DeviceCodeValidationRequest{
		Issuer:   h.issuer,
		UserCode: userCode,
		Subject:  "attacker-1",
	})
	require.Error(t, err, "throttled subject must not redeem the correct code")
	require.NotNil(t, res.Error)
	require.Equal(t, "access_denied", res.Error.Err)

	// The device code stays pending and unconsumed.
	pollRes, pollErr := h.pollDeviceToken(t, client.ClientId, deviceCode)
	require.Error(t, pollErr)
	require.NotNil(t, pollRes.Error)
	require.Equal(t, "authorization_pending", pollRes.Error.Err)
}

// TestRFC10027_UserCodeFirstAttemptSucceeds is the negative control for the
// throttle: a legitimate user redeeming the correct code on the first
// attempt is never locked out (the counter resets on success).
func TestRFC10027_UserCodeFirstAttemptSucceeds(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeDeviceCode})

	deviceCode, userCode := h.startDeviceAuthorization(t, client, []string{"openid"})
	h.approveDevice(t, userCode, "legitimate-user-1")

	res, err := h.pollDeviceToken(t, client.ClientId, deviceCode)
	require.NoError(t, err)
	require.Nil(t, res.Error)
	require.NotNil(t, res.AccessToken)
}

// TestRFC10027_NoRefreshTokenFromDeviceGrant asserts limited scopes /
// short-lived tokens (RFC 10027 sections 6.1.9/6.1.10, exploits B1/B2):
// even when the request carries offline_access, the device grant mints an
// access token only — exfiltrated refresh tokens are the primary loot of
// cross-device phishing, so they are never issued from this grant.
func TestRFC10027_NoRefreshTokenFromDeviceGrant(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeDeviceCode})

	deviceCode, userCode := h.startDeviceAuthorization(t, client, []string{"openid", "offline_access"})
	h.approveDevice(t, userCode, "device-user-1")

	res, err := h.pollDeviceToken(t, client.ClientId, deviceCode)
	require.NoError(t, err)
	require.Nil(t, res.Error)
	require.NotNil(t, res.AccessToken, "access token must still be issued")
	require.Nil(t, res.RefreshToken, "device grant must never mint a refresh token")
	require.NotContains(t, res.AccessToken.Metadata.Scope, "offline_access",
		"offline_access must be stripped from the granted scope")
}

// TestRFC10027_DPoPBoundClientRequiresProof asserts sender-constrained
// tokens (RFC 10027 section 6.1.12): a client flagged DpopBoundAccessTokens
// cannot obtain a bearer token from the device grant — a poll without a
// DPoP confirmation is rejected, and a poll carrying one is honored with
// the confirmation bound to the issued access token.
func TestRFC10027_DPoPBoundClientRequiresProof(t *testing.T) {
	h := newHarness(t)
	client := h.registerDeviceDPoPClient(t)

	deviceCode, userCode := h.startDeviceAuthorization(t, client, []string{"openid"})
	h.approveDevice(t, userCode, "device-user-1")

	// Poll without a DPoP proof: rejected.
	res, err := h.pollDeviceTokenWithConfirmation(t, client.ClientId, deviceCode, nil)
	require.Error(t, err, "DPoP-bound client must not obtain a bearer token")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_request", res.Error.Err)
	require.Nil(t, res.AccessToken)

	// The rejection happened before the consume: the session survives,
	// a poll WITH the proof still mints the sender-constrained token.
	res2, err2 := h.pollDeviceTokenWithConfirmation(t, client.ClientId, deviceCode, &tokenv1.TokenConfirmation{Jkt: "test-jkt"})
	require.NoError(t, err2)
	require.Nil(t, res2.Error)
	require.NotNil(t, res2.AccessToken)
	require.Equal(t, "test-jkt", res2.AccessToken.Confirmation.Jkt)
}
