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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/authzdetails"
	"zntr.io/solid/sdk/generator"
	"zntr.io/solid/sdk/jwk"
	sdktoken "zntr.io/solid/sdk/token"
	"zntr.io/solid/sdk/token/hpke"
	"zntr.io/solid/sdk/token/jwt"
	"zntr.io/solid/server/clientauthentication"
	"zntr.io/solid/server/services/authorization"
	"zntr.io/solid/server/services/backchannel"
	"zntr.io/solid/server/services/device"
	"zntr.io/solid/server/services/token"
	"zntr.io/solid/server/storage/inmemory"
)

// hpkeHarness is the harness variant whose access and refresh token
// generators emit HPKE-encrypted JWTs (draft-ietf-jose-hpke-encrypt-22,
// HPKE-7 Integrated Encryption), mirroring the reference example assembly.
type hpkeHarness struct {
	harness

	// signingPrivateKey is the AS signing key (ES256) backing the inner
	// JWS of the encrypted tokens.
	signingPrivateKey jwk.Key
	// signingSet holds the AS signing public key.
	signingSet jwk.Set
	// encryptionPrivateKey is the AS HPKE recipient key (P-256).
	encryptionPrivateKey jwk.Key
	// encryptionSet holds the AS HPKE decryption key set.
	encryptionSet jwk.Set
}

// newHPKEHarness builds a service stack whose token service issues
// HPKE-encrypted JWT access and refresh tokens.
func newHPKEHarness(t *testing.T) *hpkeHarness {
	t.Helper()

	storageKey := []byte("hpke-integration-storage-key-0123")

	// AS signing key (ES256, P-256).
	signEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "unable to generate AS signing key")
	signingPrivateKey, err := jwxjwk.Import(signEC)
	require.NoError(t, err, "unable to import AS signing key")
	require.NoError(t, signingPrivateKey.Set(jwk.KeyIDKey, "hpke-as-signing-key"))
	signingPub, err := signingPrivateKey.PublicKey()
	require.NoError(t, err, "unable to derive AS signing public key")
	signingSet := jwk.NewSet()
	require.NoError(t, signingSet.AddKey(signingPub))

	// AS token encryption key (P-256, use=enc, HPKE-7).
	encEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "unable to generate AS encryption key")
	encryptionPrivateKey, err := jwxjwk.Import(encEC)
	require.NoError(t, err, "unable to import AS encryption key")
	require.NoError(t, encryptionPrivateKey.Set(jwk.KeyIDKey, "hpke-as-encryption-key"))
	require.NoError(t, encryptionPrivateKey.Set(jwk.KeyUsageKey, "enc"))
	encryptionSet := jwk.NewSet()
	require.NoError(t, encryptionSet.AddKey(encryptionPrivateKey))

	keyProvider := func(context.Context) (jwk.Key, error) {
		return signingPrivateKey, nil
	}
	encKeyProvider := func(context.Context) (jwk.Key, error) {
		return encryptionPrivateKey, nil
	}

	// Token generators: sign-then-encrypt JWTs.
	atSerializer := sdktoken.Encryption(
		jwt.AccessTokenSigner("ES256", keyProvider),
		hpke.Encrypter(hpke.HPKE7, encKeyProvider),
	)
	rtSerializer := sdktoken.Encryption(
		jwt.RefreshTokenSigner("ES256", keyProvider),
		hpke.Encrypter(hpke.HPKE7, encKeyProvider),
	)
	accessTokens := sdktoken.AccessToken(atSerializer)
	refreshTokens := sdktoken.RefreshToken(rtSerializer)

	// Storage
	clients := inmemory.Clients()
	tokens := inmemory.Tokens(storageKey)
	resources := inmemory.Resources()
	proofs := inmemory.DPoPProofs()
	authRequests := inmemory.AuthorizationRequests(storageKey)
	authSessions := inmemory.AuthorizationCodeSessions(storageKey)
	deviceSessions := inmemory.DeviceCodeSessions(storageKey)
	backchannelSessions := inmemory.BackchannelAuthenticationSessions(storageKey)
	userCodeAttempts := inmemory.UserCodeAttempts()

	// Services
	authz := authorization.New(clients, authRequests, authSessions, generator.DefaultAuthorizationCode(), generator.DefaultRequestURI(),
		authzdetails.NewStaticValidator(map[string]struct{}{"payment_initiation": {}}))
	tokenz := token.New(accessTokens, refreshTokens, clients, authSessions, deviceSessions, backchannelSessions, tokens, resources)
	backchannelz := backchannel.New(clients, backchannelSessions, generator.DefaultAuthReqID(), backchannel.LoginHintResolver(), authzdetails.NewStaticValidator(map[string]struct{}{"payment_initiation": {}}), []string{"ES256"})
	devicez := device.New(clients, deviceSessions, generator.DefaultDeviceCode(), generator.DefaultDeviceUserCode(), userCodeAttempts)
	clientAuth := clientauthentication.PrivateKeyJWT(clients, proofs, testIssuer, []string{"ES256"})

	return &hpkeHarness{
		harness: harness{
			issuer:              testIssuer,
			clients:             clients,
			tokens:              tokens,
			resources:           resources,
			proofs:              proofs,
			authRequests:        authRequests,
			authSessions:        authSessions,
			deviceSessions:      deviceSessions,
			backchannelSessions: backchannelSessions,
			userCodeAttempts:    userCodeAttempts,
			authz:               authz,
			tokenz:              tokenz,
			devicez:             devicez,
			backchannelz:        backchannelz,
			clientAuth:          clientAuth,
		},
		signingPrivateKey:    signingPrivateKey,
		signingSet:           signingSet,
		encryptionPrivateKey: encryptionPrivateKey,
		encryptionSet:        encryptionSet,
	}
}

// hpkeVerifier assembles the AS-side decrypting verifier: HPKE outer JWE,
// ES256 inner JWT.
func (h *hpkeHarness) hpkeVerifier() sdktoken.Verifier {
	return hpke.Verifier(func(context.Context) (jwk.Set, error) {
		return h.encryptionSet, nil
	}, jwt.DefaultVerifier(func(context.Context) (jwk.Set, error) {
		return h.signingSet, nil
	}, []string{"ES256"}))
}

// isJWE asserts the raw token is a 5-segment JWE carrying an HPKE alg.
func isJWE(t *testing.T, raw string) {
	t.Helper()

	parts := strings.Split(raw, ".")
	require.Len(t, parts, 5, "HPKE-encrypted token must be a 5-segment JWE")

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err, "JWE header must be valid base64url")
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Enc string `json:"enc"`
	}
	require.NoError(t, json.Unmarshal(headerJSON, &header), "JWE header must be JSON")
	assert.Equal(t, "HPKE-7", header.Alg, "JWE alg must be HPKE-7")
	assert.Empty(t, header.Enc, "Integrated Encryption JWE must not carry an enc member")
	assert.NotEmpty(t, header.Kid, "JWE header carries the encryption key id")
}

// codeGrantHPKE drives a full authorization code grant (PAR-style seed,
// authorize, PKCE redemption) and returns the token response.
func (h *hpkeHarness) codeGrantHPKE(t *testing.T) (*flowv1.TokenResponse, string) {
	t.Helper()

	client := h.registerConfidentialClient(t, []string{testRedirectURI}, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken})
	verifier, challenge := newPKCEPair(t)
	_ = challenge

	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	code := h.seedAuthorization(t, client, req)

	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err, "authorization code grant must succeed")
	require.NotNil(t, res, "token response must not be nil")

	return res, client.ClientId
}

// TestHPKEAccessTokenRoundTrip issues an access token through the full code
// grant and verifies the HPKE-encrypted JWT decrypts and the inner JWS
// verifies with the expected claims.
func TestHPKEAccessTokenRoundTrip(t *testing.T) {
	h := newHPKEHarness(t)

	res, clientID := h.codeGrantHPKE(t)
	require.NotEmpty(t, res.AccessToken.Value, "token response must carry an access token")
	isJWE(t, res.AccessToken.Value)

	// Decrypt + inner-verify + extract claims.
	verifier := h.hpkeVerifier()
	claims := struct {
		Iss      string `json:"iss"`
		Sub      string `json:"sub"`
		ClientID string `json:"client_id"`
		JTI      string `json:"jti"`
	}{}
	require.NoError(t, verifier.Claims(context.Background(), res.AccessToken.Value, &claims), "HPKE-encrypted access token must decrypt and verify")

	assert.Equal(t, testIssuer, claims.Iss, "issuer claim must match the AS issuer")
	assert.Equal(t, clientID, claims.ClientID, "client_id claim must match the authenticated client")
	assert.NotEmpty(t, claims.Sub, "subject claim must be present")
	assert.NotEmpty(t, claims.JTI, "jti claim must be present")
}

// TestHPKERefreshGrantSurvivesEncryption redeems a code, refreshes with the
// encrypted refresh token, and asserts the new tokens are also HPKE JWEs —
// proving the value-indexed storage path survives the format change.
func TestHPKERefreshGrantSurvivesEncryption(t *testing.T) {
	h := newHPKEHarness(t)

	res, clientID := h.codeGrantHPKE(t)
	require.NotEmpty(t, res.RefreshToken.Value, "token response must carry a refresh token")
	isJWE(t, res.RefreshToken.Value)

	// Refresh grant with the encrypted refresh token.
	refreshed, err := h.refresh(t, clientID, res.RefreshToken.Value)
	require.NoError(t, err, "refresh grant must succeed with the encrypted refresh token")
	require.NotNil(t, refreshed, "refresh response must not be nil")
	require.NotEmpty(t, refreshed.AccessToken.Value, "refresh response must carry a new access token")
	require.NotEmpty(t, refreshed.RefreshToken, "refresh response must carry a new refresh token")

	// New tokens are HPKE JWEs too, and decrypt+verify.
	isJWE(t, refreshed.AccessToken.Value)
	verifier := h.hpkeVerifier()
	claims := struct {
		Iss      string `json:"iss"`
		ClientID string `json:"client_id"`
	}{}
	require.NoError(t, verifier.Claims(context.Background(), refreshed.AccessToken.Value, &claims), "refreshed access token must decrypt and verify")
	assert.Equal(t, clientID, claims.ClientID, "refreshed token client_id must match")
}

// TestHPKEIntrospectionOfEncryptedToken introspects the encrypted access
// token: the value-indexed storage path must resolve it as active with the
// correct claims.
func TestHPKEIntrospectionOfEncryptedToken(t *testing.T) {
	h := newHPKEHarness(t)

	res, clientID := h.codeGrantHPKE(t)

	introspected, err := h.introspect(t, clientID, res.AccessToken.Value)
	require.NoError(t, err, "introspection of the encrypted access token must succeed")
	require.NotNil(t, introspected, "introspection response must not be nil")
	assert.Equal(t, tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE, introspected.Token.Status, "encrypted access token must introspect as active")
	assert.Equal(t, clientID, introspected.Token.Metadata.ClientId, "introspected client_id must match")
}

// TestHPKETamperedAccessTokenRejected plays the RFC 9700 A5 token attacker:
// flip one ciphertext character of the access token; the decrypting
// verifier must reject it (AEAD tag failure).
func TestHPKETamperedAccessTokenRejected(t *testing.T) {
	h := newHPKEHarness(t)

	res, _ := h.codeGrantHPKE(t)

	parts := strings.Split(res.AccessToken.Value, ".")
	ct := []byte(parts[3])
	ct[len(ct)-1] ^= 1
	parts[3] = string(ct)
	tampered := strings.Join(parts, ".")

	verifier := h.hpkeVerifier()
	require.Error(t, verifier.Verify(tampered), "tampered HPKE access token must be rejected")

	var claims map[string]any
	require.Error(t, verifier.Claims(context.Background(), tampered, &claims), "tampered token must not yield claims")
}

// TestHPKEAlgSwapAttack plays the RFC 8725 section 3.4 algorithm
// substitution: rewrite the JWE alg header (HPKE-0 for HPKE-7), keep the
// ciphertext; the header is AEAD-bound, the swap must fail.
func TestHPKEAlgSwapAttack(t *testing.T) {
	h := newHPKEHarness(t)

	res, _ := h.codeGrantHPKE(t)

	parts := strings.Split(res.AccessToken.Value, ".")
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err, "JWE header must decode")

	swapped := strings.Replace(string(headerJSON), `"alg":"HPKE-7"`, `"alg":"HPKE-0"`, 1)
	require.NotEqual(t, string(headerJSON), swapped, "alg substitution must apply")
	parts[0] = base64.RawURLEncoding.EncodeToString([]byte(swapped))
	tampered := strings.Join(parts, ".")

	verifier := h.hpkeVerifier()
	require.Error(t, verifier.Verify(tampered), "alg-swapped token must be rejected")
}

// TestHPKEWrongKeyRejected decrypts with a key set that does not hold the
// AS encryption key: the encapsulation must fail to open.
func TestHPKEWrongKeyRejected(t *testing.T) {
	h := newHPKEHarness(t)

	res, _ := h.codeGrantHPKE(t)

	// A different P-256 encryption key.
	otherEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "unable to generate foreign encryption key")
	otherKey, err := jwxjwk.Import(otherEC)
	require.NoError(t, err, "unable to import foreign encryption key")
	require.NoError(t, otherKey.Set(jwk.KeyUsageKey, "enc"))
	otherSet := jwk.NewSet()
	require.NoError(t, otherSet.AddKey(otherKey))

	foreignVerifier := hpke.Verifier(func(context.Context) (jwk.Set, error) {
		return otherSet, nil
	}, jwt.DefaultVerifier(func(context.Context) (jwk.Set, error) {
		return h.signingSet, nil
	}, []string{"ES256"}))
	require.Error(t, foreignVerifier.Verify(res.AccessToken.Value), "decryption under a foreign key must fail")
}

// TestHPKEMalformedJWEsRejected crafts malformed JWEs by raw string
// surgery on a genuine access token and asserts the verifier fails
// closed on the draft header rules.
func TestHPKEMalformedJWEsRejected(t *testing.T) {
	h := newHPKEHarness(t)

	res, _ := h.codeGrantHPKE(t)
	parts := strings.Split(res.AccessToken.Value, ".")
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err, "JWE header must decode")
	var header map[string]any
	require.NoError(t, json.Unmarshal(headerJSON, &header))

	rewrite := func(mutate func(map[string]any)) string {
		h := map[string]any{}
		for k, v := range header {
			h[k] = v
		}
		mutate(h)
		encoded, err := json.Marshal(h)
		require.NoError(t, err)
		p := append([]string{}, parts...)
		p[0] = base64.RawURLEncoding.EncodeToString(encoded)
		return strings.Join(p, ".")
	}

	malformed := map[string]string{
		"enc header on Integrated": rewrite(func(m map[string]any) { m["enc"] = "A256GCM" }),
		"ek header on Integrated":  rewrite(func(m map[string]any) { m["ek"] = "AAAA" }),
		"crit header":              rewrite(func(m map[string]any) { m["crit"] = []string{"typ"} }),
		"zip header":               rewrite(func(m map[string]any) { m["zip"] = "DEF" }),
		"psk_id header":            rewrite(func(m map[string]any) { m["psk_id"] = "psk" }),
		"iv segment": func() string {
			p := append([]string{}, parts...)
			p[2] = "AAAAAAAAAAAAAAAA"
			return strings.Join(p, ".")
		}(),
		"4-segment": strings.Join(parts[:4], "."),
		"padded segment": func() string {
			p := append([]string{}, parts...)
			p[3] = p[3] + "="
			return strings.Join(p, ".")
		}(),
	}

	verifier := h.hpkeVerifier()
	for name, raw := range malformed {
		t.Run(name, func(t *testing.T) {
			require.Error(t, verifier.Verify(raw), "malformed JWE must be rejected")
			var claims map[string]any
			require.Error(t, verifier.Claims(context.Background(), raw, &claims), "malformed JWE must not yield claims")
		})
	}
}
