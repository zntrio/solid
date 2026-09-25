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

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/dpop"
)

// RFC 9449 (DPoP) adversarial coverage.

// TestRFC9449_JktVsCnfMismatch asserts a DPoP proof verified with an explicit
// token confirmation mismatching the proof key is rejected (RFC 9449
// section 4.3: the proof public key must equal the token cnf.jkt).
func TestRFC9449_JktVsCnfMismatch(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	verifier, _ := newPKCEPair(t)
	code := h.seedAuthorization(t, client, validAuthorizationRequest(client.ClientId, verifier, testRedirectURI))
	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, res.AccessToken)

	prover := buildDPoPProver(t)
	dpopVerifier := buildDPoPVerifier()

	htu := testIssuer + "/resource"

	// Proof minted with the fixture key (K1) bound to the token value.
	proof, err := prover.Prove("GET", htu, dpop.WithTokenValue(res.AccessToken.Value))
	require.NoError(t, err)

	// Verify while asserting a DIFFERENT confirmation key (K2 jkt).
	_, err = dpopVerifier.Verify(t.Context(), "GET", htu, proof,
		dpop.WithTokenValue(res.AccessToken.Value),
		dpop.WithTokenConfirmation("totally-different-jkt-value"),
	)
	require.Error(t, err, "proof key must match the asserted token confirmation")
}

// TestRFC9449_DpopJktBinding_10 asserts an authorization request stamped
// with dpop_jkt=K1 cannot be redeemed with a proof of key K2 (RFC 9449
// section 10: authorization code binding to a DPoP key).
func TestRFC9449_DpopJktBinding_10(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	// Compute the attacker key thumbprint (K2): derive it from the proof
	// verifier below.
	prover := buildDPoPProver(t)
	htu := testIssuer + "/resource"
	probeProof, err := prover.Prove("GET", htu)
	require.NoError(t, err)
	k2Jkt, err := buildDPoPVerifier().Verify(t.Context(), "GET", htu, probeProof)
	require.NoError(t, err)
	require.NotEmpty(t, k2Jkt)

	// Seed an authorization request bound to K2's jkt... but redeem with a
	// DIFFERENT confirmation (K1).
	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	code := h.seedAuthorization(t, client, req)

	// Redeem while presenting the proof key K1's confirmation (the
	// attacker's swap).
	h.authenticateClient(t, client.ClientId)
	res, err := h.tokenz.Token(t.Context(), &flowv1.TokenRequest{
		Issuer:    h.issuer,
		GrantType: oidc.GrantTypeAuthorizationCode,
		Client:    &clientv1.Client{ClientId: client.ClientId},
		Grant: &flowv1.TokenRequest_AuthorizationCode{
			AuthorizationCode: &flowv1.GrantAuthorizationCode{
				Code:         code,
				CodeVerifier: verifier,
				RedirectUri:  testRedirectURI,
				// Bind the grant to K2.
				DpopJkt: &k2Jkt,
			},
		},
		// Present K1's confirmation: mismatch.
		TokenConfirmation: &tokenv1.TokenConfirmation{Jkt: "attacker-key-one-jkt"},
	})
	require.Error(t, err, "proof-key swap against the bound dpop_jkt must fail")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_grant", res.Error.Err)
}

// TestRFC9449_TypHeaderHardening asserts a DPoP proof JWT with a typ other
// than dpop+jwt is rejected (RFC 9449 section 4.1: the typ JOSE header MUST
// be dpop+jwt).
func TestRFC9449_TypHeaderHardening(t *testing.T) {
	privateKey, err := jwxjwk.ParseKey(clientPrivateKey)
	require.NoError(t, err)
	require.NoError(t, privateKey.Set(jwxjwk.KeyIDKey, "integration-dpop-key"))
	var rawKey any
	require.NoError(t, jwxjwk.Export(privateKey, &rawKey))

	// Assemble a syntactically valid proof with the WRONG typ header.
	now := time.Now().Unix()
	claims := map[string]any{
		"jti": "typ-header-attacker",
		"htm": "GET",
		"htu": testIssuer + "/resource",
		"iat": now,
	}
	tok := gojwt.NewWithClaims(gojwt.SigningMethodES256, gojwt.MapClaims(claims))
	tok.Header["typ"] = "JWT"
	raw, err := tok.SignedString(rawKey)
	require.NoError(t, err)

	_, err = buildDPoPVerifier().Verify(t.Context(), "GET", testIssuer+"/resource", raw)
	require.Error(t, err, "proof with typ=JWT must be rejected")
}

// TestRFC9449_DpopJktBinding_Match asserts a matching dpop_jkt/confirmation
// pair redeems successfully (positive control for the section 10 binding).
func TestRFC9449_DpopJktBinding_Match(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})

	prover := buildDPoPProver(t)
	htu := testIssuer + "/resource"
	probeProof, err := prover.Prove("GET", htu)
	require.NoError(t, err)
	jkt, err := buildDPoPVerifier().Verify(t.Context(), "GET", htu, probeProof)
	require.NoError(t, err)

	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	code := h.seedAuthorization(t, client, req)

	h.authenticateClient(t, client.ClientId)
	res, err := h.tokenz.Token(t.Context(), &flowv1.TokenRequest{
		Issuer:    h.issuer,
		GrantType: oidc.GrantTypeAuthorizationCode,
		Client:    &clientv1.Client{ClientId: client.ClientId},
		Grant: &flowv1.TokenRequest_AuthorizationCode{
			AuthorizationCode: &flowv1.GrantAuthorizationCode{
				Code:         code,
				CodeVerifier: verifier,
				RedirectUri:  testRedirectURI,
				DpopJkt:      &jkt,
			},
		},
		TokenConfirmation: &tokenv1.TokenConfirmation{Jkt: jkt},
	})
	require.NoError(t, err)
	require.NotNil(t, res.AccessToken)
}
