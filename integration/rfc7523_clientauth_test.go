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
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"
)

// RFC 7523 (JWT Profile for Client Authentication) adversarial coverage.

// TestRFC7523_AlgNoneRejected asserts an unsigned assertion (alg=none) with
// otherwise-valid claims is rejected: only the asymmetric allowlist is
// accepted (RFC 7523 section 3: signature validation is mandatory).
func TestRFC7523_AlgNoneRejected(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, nil)

	now := time.Now().Unix()
	claims := map[string]any{
		"jti": "alg-none-attacker",
		"sub": client.ClientId,
		"iss": client.ClientId,
		"aud": testTokenEndpoint,
		"exp": now + 300,
		"iat": now,
	}

	// Assemble an unsigned JWT: base64url(header).base64url(payload).
	header := map[string]any{"alg": "none", "typ": "JWT"}
	raw := b64JSON(t, header) + "." + b64JSON(t, claims) + "."

	res, err := h.authenticate(t, testTokenEndpoint, raw)
	require.Error(t, err, "alg=none assertion must not authenticate")
	if res != nil {
		require.Nil(t, res.Client, "no client may be resolved from an unsigned assertion")
	}
}

// TestRFC7523_AudArrayRejected asserts the array form of the aud claim is
// rejected even when it contains a valid audience value: per
// draft-ietf-oauth-security-topics-update-03 section 2.1.2, client
// authentication assertions MUST carry a single audience value — an array
// lets an attacker-controlled audience ride alongside the intended one
// (RFC 7519 array semantics would identify the attacker as an intended
// audience too). This inverts the historical RFC 7519 leniency.
func TestRFC7523_AudArrayRejected(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, nil)

	now := uint64(time.Now().Unix())

	// Sign an assertion whose aud is an array containing the valid
	// audience plus an attacker-controlled one.
	privateKey, err := jwxjwk.ParseKey(clientPrivateKey)
	require.NoError(t, err)
	var rawKey any
	require.NoError(t, jwxjwk.Export(privateKey, &rawKey))

	claims := map[string]any{
		"jti": "aud-array-rejected",
		"sub": client.ClientId,
		"iss": client.ClientId,
		"aud": []string{testIssuer, "https://attacker.example/aud"},
		"exp": now + 300,
		"iat": now,
		"nbf": now,
	}
	tok := gojwt.NewWithClaims(gojwt.SigningMethodES256, gojwt.MapClaims(claims))
	tok.Header["typ"] = "JWT"
	raw, err := tok.SignedString(rawKey)
	require.NoError(t, err)

	res, err := h.authenticate(t, testTokenEndpoint, raw)
	require.Error(t, err, "array aud must not authenticate: single audience value is mandated")
	if res != nil {
		require.Nil(t, res.Client, "no client may be resolved from a multi-audience assertion")
	}
}

// b64JSON marshals and base64url-encodes a value.
func b64JSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(b)
}
