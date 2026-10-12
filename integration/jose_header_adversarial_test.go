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
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptoRand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/oidc"
)

// JOSE header adversarial coverage at the private_key_jwt client
// authentication boundary (RFC 8725 section 3: the attacker controls the
// JOSE header — alg none, key confusion, kid injection). The verifier
// under attack is the real clientauthentication service wired over the
// harness.
//
// Solid stronger postures under test:
//   - "none" (and any non-allowlisted alg) is rejected before claims
//     processing (allowlist: ES256 in the harness);
//   - a foreign EC key not in the registered JWKS cannot verify;
//   - unknown kid in the assertion header fails closed: the kid routes
//     against the registered JWKS and an unknown kid never falls back to
//     the full key set (header-injection defense);
//   - an attacker-supplied jwks_uri is never fetched in the auth path
//     (SSRF-by-jwks_uri is dead at this surface).

// joseSignWithKey signs a client assertion with an arbitrary private key
// and an arbitrary header, returning the raw compact JWS.
func joseSignWithKey(t *testing.T, key jwxjwk.Key, header map[string]any, claims gojwt.MapClaims) string {
	t.Helper()

	var rawKey any
	require.NoError(t, jwxjwk.Export(key, &rawKey))

	tok := gojwt.NewWithClaims(gojwt.SigningMethodES256, claims)
	for k, v := range header {
		tok.Header[k] = v
	}
	raw, err := tok.SignedString(rawKey)
	require.NoError(t, err)
	return raw
}

// joseAttackerKey generates a fresh, unregistered ES256 P-256 key.
func joseAttackerKey(t *testing.T) jwxjwk.Key {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), cryptoRand.Reader)
	require.NoError(t, err)
	key, err := jwxjwk.Import(priv)
	require.NoError(t, err)
	require.NoError(t, key.Set(jwxjwk.AlgorithmKey, "ES256"))
	return key
}

// joseValidClaims assembles a fully valid private_key_jwt claim set for
// the given client (aud = the token endpoint).
func joseValidClaims(clientID string) gojwt.MapClaims {
	now := uint64(time.Now().Unix())
	return gojwt.MapClaims{
		"jti": "jose-adversarial-" + clientID,
		"sub": clientID,
		"iss": clientID,
		"aud": testTokenEndpoint,
		"exp": now + 300,
		"iat": now,
	}
}

// TestJOSE_AlgNoneRejected asserts RFC 8725 section 3.1/3.4: an assertion
// with alg "none" (or any unsigned form) must never authenticate — the
// algorithm allowlist rejects it before any claim processing.
func TestJOSE_AlgNoneRejected(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, nil)

	// Hand-craft an unsigned JWT: {"alg":"none"} header.
	headerJSON, err := json.Marshal(map[string]any{"alg": "none", "typ": "JWT"})
	require.NoError(t, err)
	payloadJSON, err := json.Marshal(joseValidClaims(client.ClientId))
	require.NoError(t, err)
	unsigned := base64.RawURLEncoding.EncodeToString(headerJSON) +
		"." + base64.RawURLEncoding.EncodeToString(payloadJSON) + "."

	res, err := h.authenticate(t, testTokenEndpoint, unsigned)
	require.Error(t, err, "alg none must be rejected")
	require.NotNil(t, res.Error)
	require.Nil(t, res.Client, "no client may be resolved from an unsigned assertion")
}

// TestJOSE_AlgConfusionES256HeaderWrongKey asserts RFC 8725 section 3.5
// (key/algorithm confusion): an ES256-signed assertion whose signing key
// is NOT the registered client key (an attacker-generated P-256 pair)
// fails verification — the signature must verify against the registered
// JWKS only.
func TestJOSE_AlgConfusionES256HeaderWrongKey(t *testing.T) {
	h := newHarness(t)
	client := h.registerConfidentialClient(t, []string{testRedirectURI}, nil)

	raw := joseSignWithKey(t, joseAttackerKey(t), map[string]any{"typ": "JWT"}, joseValidClaims(client.ClientId))

	res, err := h.authenticate(t, testTokenEndpoint, raw)
	require.Error(t, err, "a foreign signing key must fail verification against the registered JWKS")
	require.NotNil(t, res.Error)
	require.Nil(t, res.Client)
}

// TestJOSE_KidInjectionUnknownKid asserts the solid strict kid-routing
// posture (sdk/token/jwt verifier): an assertion whose header carries a
// kid that is NOT in the registered JWKS fails closed even when the
// signature itself verifies with a registered key — an unknown kid must
// not bypass the key-set restriction by falling back to all keys.
func TestJOSE_KidInjectionUnknownKid(t *testing.T) {
	h := newHarness(t)

	// A kid-addressed registration: the JWKS publishes its key under a
	// kid (the addressing scheme the strict routing enforces).
	client := h.registerKiddedClient(t, []string{testRedirectURI}, "fixture-client-key")

	// Case 1: unknown kid + signature by an unregistered (attacker) key —
	// rejected outright.
	foreign := joseSignWithKey(t, joseAttackerKey(t),
		map[string]any{"typ": "JWT", "kid": "attacker-kid"}, joseValidClaims(client.ClientId))
	res, err := h.authenticate(t, testTokenEndpoint, foreign)
	require.Error(t, err, "unknown kid + foreign key signature must be rejected")
	require.Nil(t, res.Client)

	// Case 2: unknown kid + signature by the REGISTERED key — still
	// rejected under strict kid routing: the header kid references a key
	// that does not exist in the set, which is a header attack, not a
	// rotation.
	registeredKey, err := jwxjwk.ParseKey(clientPrivateKey)
	require.NoError(t, err)
	misdirected := joseSignWithKey(t, registeredKey,
		map[string]any{"typ": "JWT", "kid": "attacker-kid"}, joseValidClaims(client.ClientId))
	res2, err2 := h.authenticate(t, testTokenEndpoint, misdirected)
	require.Error(t, err2, "an unknown kid must fail closed even with a registered-key signature (strict kid routing)")
	require.NotNil(t, res2.Error)
	require.Nil(t, res2.Client)

	// Positive control: the registered kid + registered key authenticates.
	valid := joseSignWithKey(t, registeredKey,
		map[string]any{"typ": "JWT", "kid": "fixture-client-key"}, joseValidClaims(client.ClientId))
	resOK, errOK := h.authenticate(t, testTokenEndpoint, valid)
	require.NoError(t, errOK, "a correctly kidded assertion must authenticate")
	require.NotNil(t, resOK.Client)
}

// TestJOSE_JwksUriIgnoredAtAuth pins that an attacker-supplied jwks_uri is
// never fetched or considered in the client authentication path: a client
// whose registration carries JwksUri but no inline Jwks fails with
// invalid_client (nil JWKS) — the SSRF-by-jwks_uri surface is dead at this
// boundary (solid posture: the registry JWKS is the trust root).
func TestJOSE_JwksUriIgnoredAtAuth(t *testing.T) {
	h := newHarness(t)

	// Register a client with jwks_uri but no inline JWKS.
	client := &clientv1.Client{
		ClientName:              "jwks-uri-only-client",
		ClientType:              clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		GrantTypes:              []string{oidc.GrantTypeAuthorizationCode},
		ResponseTypes:           []string{oidc.ResponseTypeCode},
		ResponseModes:           []string{oidc.ResponseModeQueryJWT},
		RedirectUris:            []string{testRedirectURI},
		TokenEndpointAuthMethod: oidc.AuthMethodPrivateKeyJWT,
		JwksUri:                 "https://attacker.example/jwks.json",
	}
	registered, err := h.clients.Register(t.Context(), client)
	require.NoError(t, err)

	// Any assertion (even one correctly signed for a key the attacker
	// publishes at that jwks_uri) fails: the service never fetches it.
	signed := joseSignWithKey(t, joseAttackerKey(t), map[string]any{"typ": "JWT"}, joseValidClaims(registered))
	res, err := h.authenticate(t, testTokenEndpoint, signed)
	require.Error(t, err, "an assertion for a jwks_uri-only client must fail: the URI is never fetched")
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_client", res.Error.Error)
	require.Nil(t, res.Client)
}
