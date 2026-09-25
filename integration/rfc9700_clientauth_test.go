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

	"github.com/stretchr/testify/require"
)

// Attacker models A1/A3 (RFC 9700 section 3) targeting client authentication
// with private_key_jwt assertions (RFC 9700 section 2.5, RFC 7523).

// TestRFC9700_ClientAuthAudienceBinding_2_5 asserts a client assertion with
// the wrong audience (not the token endpoint) is rejected (RFC 9700
// section 2.5: audience restriction prevents assertion replay across
// endpoints or issuers).
func TestRFC9700_ClientAuthAudienceBinding_2_5(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, nil)

	now := uint64(time.Now().Unix())
	assertion := generateClientAssertion(t, &privateJWTClaims{
		JTI:       "jti-aud-attacker",
		Subject:   client.ClientId,
		Issuer:    client.ClientId,
		Audience:  "https://evil.example/token", // attacker audience
		Expires:   now + 300,
		IssuedAt:  now,
		NotBefore: now,
	})

	res, err := h.authenticate(t, testTokenEndpoint, assertion)
	require.Error(t, err, "assertion with wrong audience must not authenticate")
	if res != nil {
		require.Nil(t, res.Client, "no client must be resolved from a misdirected assertion")
	}
}

// TestRFC9700_ClientAuthTemporalWindows_2_5 asserts expired assertions,
// future iat, future nbf, and lifetimes beyond the maximum are all rejected
// (RFC 9700 section 2.5; RFC 7523 section 3: short-lived assertions with
// narrow validity windows).
func TestRFC9700_ClientAuthTemporalWindows_2_5(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, nil)
	now := uint64(time.Now().Unix())

	cases := map[string]privateJWTClaims{
		"expired assertion": {
			JTI:       "jti-expired",
			Subject:   client.ClientId,
			Issuer:    client.ClientId,
			Audience:  testTokenEndpoint,
			Expires:   now - 60,
			IssuedAt:  now - 400,
			NotBefore: now - 400,
		},
		"iat in the future": {
			JTI:       "jti-future-iat",
			Subject:   client.ClientId,
			Issuer:    client.ClientId,
			Audience:  testTokenEndpoint,
			Expires:   now + 900,
			IssuedAt:  now + 600, // beyond the 5 minute clock skew tolerance
			NotBefore: now,
		},
		"nbf in the future": {
			JTI:       "jti-future-nbf",
			Subject:   client.ClientId,
			Issuer:    client.ClientId,
			Audience:  testTokenEndpoint,
			Expires:   now + 600,
			IssuedAt:  now,
			NotBefore: now + 300,
		},
		"lifetime exceeds maximum": {
			JTI:       "jti-lifetime",
			Subject:   client.ClientId,
			Issuer:    client.ClientId,
			Audience:  testTokenEndpoint,
			Expires:   now + 3600, // 1h > 10min maximum
			IssuedAt:  now,
			NotBefore: now,
		},
	}

	for name, claims := range cases {
		t.Run(name, func(t *testing.T) {
			assertion := generateClientAssertion(t, &claims)
			res, err := h.authenticate(t, testTokenEndpoint, assertion)
			require.Error(t, err, "%s must not authenticate", name)
			if res != nil {
				require.Nil(t, res.Client)
			}
		})
	}
}

// TestRFC9700_ClientAuthJtiReplay_4_2_4 asserts a client assertion cannot be
// replayed: the jti is single-use (RFC 9700 section 2.5 / section 4.2.4
// replay protection applied to client assertions).
func TestRFC9700_ClientAuthJtiReplay_4_2_4(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, nil)

	now := uint64(time.Now().Unix())
	assertion := generateClientAssertion(t, &privateJWTClaims{
		JTI:       "jti-replay-once",
		Subject:   client.ClientId,
		Issuer:    client.ClientId,
		Audience:  testTokenEndpoint,
		Expires:   now + 300,
		IssuedAt:  now,
		NotBefore: now,
	})

	// First use succeeds.
	res1, err := h.authenticate(t, testTokenEndpoint, assertion)
	require.NoError(t, err)
	require.NotNil(t, res1.Client)

	// A3 attacker replays the same assertion.
	res2, err := h.authenticate(t, testTokenEndpoint, assertion)
	require.Error(t, err, "assertion replay must be rejected")
	if res2 != nil {
		require.Nil(t, res2.Client)
	}
}
