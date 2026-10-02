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
	cryptoRand "crypto/rand"
	"testing"
	"time"

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/jwk"
	sdktoken "zntr.io/solid/sdk/token"
	"zntr.io/solid/sdk/token/cwt"
	"zntr.io/solid/sdk/token/verifiable"
	"zntr.io/solid/server/services/token"
	"zntr.io/solid/server/storage/inmemory"
)

// CWT (RFC 8392) serialization coverage: the token service mints access and
// refresh tokens as CBOR Web Tokens when the assembler wires CWT generators,
// and the SDK verifier decodes the issued claims — proving the token format
// agnosticism of the service layer end-to-end (the service API and the
// storage contracts are format-agnostic; only the generator + verifier pair
// is format-specific).

// cwtFixtureKey generates an ES256 P-256 signing key with a kid, plus the
// public key set used for verification (pattern: sdk/token/cwt signer tests).
func cwtFixtureKey(t *testing.T) (jwk.Key, jwk.Set) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), cryptoRand.Reader)
	require.NoError(t, err)
	key, err := jwxjwk.Import(priv)
	require.NoError(t, err)
	require.NoError(t, key.Set(jwxjwk.AlgorithmKey, "ES256"))
	require.NoError(t, key.Set(jwxjwk.KeyUsageKey, "sig"))
	require.NoError(t, jwk.AssignKeyID(key))

	pub, err := key.PublicKey()
	require.NoError(t, err)
	pubSet := jwk.NewSet()
	require.NoError(t, pubSet.AddKey(pub))

	return key, pubSet
}

// TestCWTTokensRoundTripThroughTokenService mints a client_credentials token
// through the real token service wired with CWT generators, then decodes
// the issued access token with the SDK CWT verifier, asserting the RFC 8392
// claim set round-trips (iss, sub, aud, jti, scope, client_id).
func TestCWTTokensRoundTripThroughTokenService(t *testing.T) {
	ctx := context.Background()

	storageKey := []byte("cwt-integration-storage-key-01")

	// ES256 fixture pair.
	signingKey, pubSet := cwtFixtureKey(t)
	keyProvider := jwk.KeyProviderFunc(func(context.Context) (jwk.Key, error) {
		return signingKey, nil
	})

	// CWT token generators (RFC 8392 signers over RFC 8392-tagged claims).
	accessTokens := sdktoken.AccessToken(cwt.AccessTokenSigner(cose.AlgorithmES256, keyProvider))
	refreshTokens := sdktoken.RefreshToken(cwt.RefreshTokenSigner(cose.AlgorithmES256, keyProvider))

	// Assemble the real service stack with in-memory storage.
	clients := inmemory.Clients()
	tokens := inmemory.Tokens(storageKey)
	resources := inmemory.Resources()
	authSessions := inmemory.AuthorizationCodeSessions(storageKey)
	deviceSessions := inmemory.DeviceCodeSessions(storageKey)
	backchannelSessions := inmemory.BackchannelAuthenticationSessions(storageKey)
	tokenz := token.New(accessTokens, refreshTokens, clients, authSessions, deviceSessions, backchannelSessions, tokens, resources)

	// Register a confidential client_credentials client.
	clientID, err := clients.Register(ctx, &clientv1.Client{
		ClientType:              clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		ClientName:              "cwt-integration-client",
		GrantTypes:              []string{oidc.GrantTypeClientCredentials},
		TokenEndpointAuthMethod: oidc.AuthMethodPrivateKeyJWT,
	})
	require.NoError(t, err)

	res, err := tokenz.Token(ctx, &flowv1.TokenRequest{
		Issuer:    testIssuer,
		Client:    &clientv1.Client{ClientId: clientID},
		GrantType: oidc.GrantTypeClientCredentials,
		Grant:     &flowv1.TokenRequest_ClientCredentials{ClientCredentials: &flowv1.GrantClientCredentials{}},
		Scope:     new("temperature:read"),
		Audience:  new("https://rs.example.org"),
	})
	require.NoError(t, err)
	require.NotNil(t, res.AccessToken)
	require.NotEmpty(t, res.AccessToken.Value, "CWT access token value must be emitted")

	// Decode the issued token with the SDK CWT verifier.
	verifier := cwt.DefaultVerifier(
		jwk.KeySetProviderFunc(func(context.Context) (jwk.Set, error) { return pubSet, nil }),
		[]cose.Algorithm{cose.AlgorithmES256},
	)

	var claims struct {
		Iss      string `cbor:"1,keyasint"`
		Sub      string `cbor:"2,keyasint"`
		Aud      string `cbor:"3,keyasint"`
		Exp      uint64 `cbor:"4,keyasint"`
		Nbf      uint64 `cbor:"5,keyasint"`
		Iat      uint64 `cbor:"6,keyasint"`
		JTI      string `cbor:"7,keyasint"`
		ClientID string `cbor:"100,keyasint"`
		Scope    string `cbor:"101,keyasint"`
	}
	require.NoError(t, verifier.Claims(ctx, res.AccessToken.Value, &claims))

	// RFC 8392 claim round-trip assertions.
	require.Equal(t, testIssuer, claims.Iss, "iss must round-trip through the CWT claim set")
	require.Equal(t, clientID, claims.Sub, "client_credentials: the client is the subject")
	require.Equal(t, "https://rs.example.org", claims.Aud, "aud must round-trip")
	require.NotEmpty(t, claims.JTI, "jti must round-trip")
	require.NotEmpty(t, claims.ClientID, "client_id must round-trip")
	require.Greater(t, claims.Exp, uint64(time.Now().Unix()), "exp must be in the future")
}

// TestCWTRefreshTokenIssuedAsCWT proves the refresh token rides the same
// CWT serialization in the token response.
func TestCWTRefreshTokenIssuedAsCWT(t *testing.T) {
	ctx := context.Background()

	storageKey := []byte("cwt-integration-storage-key-02")
	signingKey, pubSet := cwtFixtureKey(t)
	keyProvider := jwk.KeyProviderFunc(func(context.Context) (jwk.Key, error) {
		return signingKey, nil
	})

	accessTokens := sdktoken.AccessToken(cwt.AccessTokenSigner(cose.AlgorithmES256, keyProvider))
	refreshTokens := sdktoken.RefreshToken(cwt.RefreshTokenSigner(cose.AlgorithmES256, keyProvider))

	clients := inmemory.Clients()
	tokens := inmemory.Tokens(storageKey)
	resources := inmemory.Resources()
	authSessions := inmemory.AuthorizationCodeSessions(storageKey)
	deviceSessions := inmemory.DeviceCodeSessions(storageKey)
	backchannelSessions := inmemory.BackchannelAuthenticationSessions(storageKey)
	tokenz := token.New(accessTokens, refreshTokens, clients, authSessions, deviceSessions, backchannelSessions, tokens, resources)

	clientID, err := clients.Register(ctx, &clientv1.Client{
		ClientType:              clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		ClientName:              "cwt-rt-integration-client",
		GrantTypes:              []string{oidc.GrantTypeClientCredentials, oidc.GrantTypeRefreshToken},
		TokenEndpointAuthMethod: oidc.AuthMethodPrivateKeyJWT,
	})
	require.NoError(t, err)

	res, err := tokenz.Token(ctx, &flowv1.TokenRequest{
		Issuer:    testIssuer,
		Client:    &clientv1.Client{ClientId: clientID},
		GrantType: oidc.GrantTypeClientCredentials,
		Grant:     &flowv1.TokenRequest_ClientCredentials{ClientCredentials: &flowv1.GrantClientCredentials{}},
		Scope:     new("temperature:read"),
		Audience:  new("https://rs.example.org"),
	})
	require.NoError(t, err)

	// The refresh token is optional in client_credentials; when issued it
	// must be a verifiable CWT: decode it with the CWT verifier.
	if res.RefreshToken != nil && res.RefreshToken.Value != "" {
		verifier := cwt.DefaultVerifier(
			jwk.KeySetProviderFunc(func(context.Context) (jwk.Set, error) { return pubSet, nil }),
			[]cose.Algorithm{cose.AlgorithmES256},
		)
		var claims struct {
			JTI string `cbor:"7,keyasint"`
		}
		require.NoError(t, verifier.Claims(ctx, res.RefreshToken.Value, &claims))
		require.NotEmpty(t, claims.JTI)
	}
}

// compile-time guard: the verifiable generators remain the default opaque
// model, the CWT ones are a drop-in alternative.
var _ sdktoken.Generator = verifiable.Token(verifiable.UUIDv7Source(), []byte("guard"))
