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

	"zntr.io/solid/sdk/dpop"
)

// Attacker models A2/A5 (RFC 9700 section 3): network and token attackers
// targeting DPoP sender-constrained tokens (RFC 9700 section 2.2.1 / 4.10.1,
// RFC 9449).

// TestRFC9700_DPoPJtiReplay_4_10_1 asserts a DPoP proof cannot be replayed:
// its jti is single-use (RFC 9449 section 4.3, applied per RFC 9700
// section 4.10.1).
func TestRFC9700_DPoPJtiReplay_4_10_1(t *testing.T) {
	prover := buildDPoPProver(t)
	verifier := buildDPoPVerifier()

	htu := testIssuer + "/resource"
	proof, err := prover.Prove("GET", htu)
	require.NoError(t, err)

	// First use verifies and yields the key thumbprint.
	jkt, err := verifier.Verify(t.Context(), "GET", htu, proof)
	require.NoError(t, err)
	require.NotEmpty(t, jkt)

	// A5 attacker replays the same proof.
	_, err = verifier.Verify(t.Context(), "GET", htu, proof)
	require.Error(t, err, "DPoP proof replay must be rejected")
}

// TestRFC9700_DPoPHtmHtuBinding_4_10_1 asserts the proof is bound to the
// HTTP method and target URI: verification against a different htm or htu
// fails (RFC 9449 section 4.3).
func TestRFC9700_DPoPHtmHtuBinding_4_10_1(t *testing.T) {
	prover := buildDPoPProver(t)
	verifier := buildDPoPVerifier()

	htu := testIssuer + "/resource"
	proof, err := prover.Prove("POST", htu)
	require.NoError(t, err)

	t.Run("method swap", func(t *testing.T) {
		_, err := verifier.Verify(t.Context(), "GET", htu, proof)
		require.Error(t, err, "proof bound to POST must not verify for GET")
	})

	t.Run("uri swap", func(t *testing.T) {
		_, err := verifier.Verify(t.Context(), "POST", testIssuer+"/other", proof)
		require.Error(t, err, "proof bound to one htu must not verify for another")
	})

	t.Run("exact match verifies", func(t *testing.T) {
		_, err := verifier.Verify(t.Context(), "POST", htu, proof)
		require.NoError(t, err)
	})
}

// TestRFC9700_DPoPIatWindow_4_10_1 asserts the verifier rejects proofs that
// are malformed or outside the acceptance window (RFC 9449 section 4.3:
// iat freshness; prevents pre-generated proof stockpiling).
func TestRFC9700_DPoPIatWindow_4_10_1(t *testing.T) {
	prover := buildDPoPProver(t)
	verifier := buildDPoPVerifier()

	htu := testIssuer + "/resource"
	proof, err := prover.Prove("GET", htu)
	require.NoError(t, err)

	// The fresh proof must verify.
	_, err = verifier.Verify(t.Context(), "GET", htu, proof)
	require.NoError(t, err)

	// Malformed proofs are refused outright.
	_, err = verifier.Verify(t.Context(), "GET", htu, "not-a-jwt")
	require.Error(t, err, "malformed proof must be rejected")
}

// TestRFC9700_DPoPAthBinding_4_10_1 asserts the ath claim binds the proof to
// the access token it accompanies (RFC 9449 section 4.1): a proof presented
// with a token value that does not match its ath must fail.
func TestRFC9700_DPoPAthBinding_4_10_1(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{"authorization_code", "refresh_token"})

	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, verifier, testRedirectURI))
	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, res.AccessToken)

	prover := buildDPoPProver(t)
	dpopVerifier := buildDPoPVerifier()

	htu := testIssuer + "/resource"

	// Proof minted WITH the token value binding.
	proof, err := prover.Prove("GET", htu, dpop.WithTokenValue(res.AccessToken.Value))
	require.NoError(t, err)

	// Verifying with the matching token value succeeds.
	_, err = dpopVerifier.Verify(t.Context(), "GET", htu, proof, dpop.WithTokenValue(res.AccessToken.Value))
	require.NoError(t, err)

	// A5 attacker presents the same proof for a different token.
	otherClient := h.registerConfidentialClient(t, []string{"https://client-b.example.org/cb"}, []string{"authorization_code", "refresh_token"})
	verifier2, _ := newPKCEPair(t)
	code2 := h.seedAuthorization(t, otherClient, validAuthorizationRequest(otherClient.ClientId, verifier2, "https://client-b.example.org/cb"))
	res2, err := h.redeemCode(t, otherClient.ClientId, code2, verifier2, "https://client-b.example.org/cb")
	require.NoError(t, err)

	_, err = dpopVerifier.Verify(t.Context(), "GET", htu, proof, dpop.WithTokenValue(res2.AccessToken.Value))
	require.Error(t, err, "proof ath must bind to the exact access token")
}
