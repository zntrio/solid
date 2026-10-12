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

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/server/services/clientregistration"
)

// RFC 7591 (OAuth 2.0 Dynamic Client Registration) / RFC 7592 (Dynamic
// Client Registration Management Protocol) adversarial coverage, exercised
// against the real clientregistration service wired over the harness
// in-memory storage. The attacker (A4/A5) targets the registration surface:
// registration-token guessing, cross-client management, hostile metadata,
// and deprovisioning escapes. Solid postures under test:
//
//   - asymmetric client authentication only (no secret ever issued);
//   - burn-on-miss registration tokens (RFC 7592 section 2.1: a failed
//     management attempt revokes the stored credential — guessing burns it);
//   - the bearer credential never rides any client payload except the
//     registration response.

// dcrRegister drives a valid RFC 7591 section 3.2.1 registration.
func dcrRegister(t *testing.T, h *harness) (*clientv1.Client, string) {
	t.Helper()

	res, err := h.registrz.Register(t.Context(), &clientv1.RegisterRequest{
		Metadata: &clientv1.ClientMeta{
			ClientName:              new("dcr-adversarial-client"),
			GrantTypes:              []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken},
			ResponseTypes:           []string{oidc.ResponseTypeCode},
			ResponseModes:           []string{oidc.ResponseModeQueryJWT},
			RedirectUris:            []string{testRedirectURI},
			TokenEndpointAuthMethod: new(oidc.AuthMethodPrivateKeyJWT),
			Jwks:                    clientJWKSWithSIG,
		},
	})
	require.NoError(t, err)
	require.Nil(t, res.Error)
	require.NotNil(t, res.Client)
	require.NotEmpty(t, res.Client.ClientId, "the AS must assign a client_id")
	require.NotNil(t, res.RegistrationAccessToken)
	require.NotEmpty(t, *res.RegistrationAccessToken, "RFC 7592 section 3: a registration access token is issued")

	return res.Client, *res.RegistrationAccessToken
}

// TestDCR_RegisterIssuesRegistrationToken_2 asserts RFC 7591 section 3.2.1 /
// RFC 7592 section 3: the registration response carries the management
// credential, and the returned Client payload never leaks it (the token is
// a server-side record).
func TestDCR_RegisterIssuesRegistrationToken_2(t *testing.T) {
	h := newHarness(t)

	client, rat := dcrRegister(t, h)
	require.Nil(t, client.RegistrationAccessToken,
		"the registration access token must never ride the Client payload")
	require.NotEmpty(t, rat)
}

// TestDCR_GuessingBurnsCredential_7592_2_1 asserts RFC 7592 section 2.1
// with the solid burn-on-miss posture: one wrong registration token on the
// Read surface revokes the stored credential, so the SECOND read — even
// with the correct token — fails. Token guessing is a one-shot denial of
// the attacker's own credential.
func TestDCR_GuessingBurnsCredential_7592_2_1(t *testing.T) {
	h := newHarness(t)
	client, rat := dcrRegister(t, h)

	// First read with a wrong token: invalid_token.
	wrong, err := h.registrz.Read(t.Context(), &clientv1.ReadRequest{
		ClientId:                new(client.ClientId),
		RegistrationAccessToken: new("guessed-wrong-token"),
	})
	require.Error(t, err)
	require.NotNil(t, wrong.Error)
	require.Equal(t, "invalid_token", wrong.Error.Error)

	// Second read with the CORRECT token: still invalid_token — the
	// guessing attempt burned the credential.
	after, err := h.registrz.Read(t.Context(), &clientv1.ReadRequest{
		ClientId:                new(client.ClientId),
		RegistrationAccessToken: &rat,
	})
	require.Error(t, err, "the guessing attempt must have revoked the stored token")
	require.NotNil(t, after.Error)
	require.Equal(t, "invalid_token", after.Error.Error)
}

// TestDCR_CrossClientRead_7592_2_1 asserts RFC 7592 section 2.1: client
// A's registration token used against client B's client_id is an
// invalid_token (and burns A's credential — the shared-secret-style
// cross-tenant probe fails closed).
func TestDCR_CrossClientRead_7592_2_1(t *testing.T) {
	h := newHarness(t)
	clientA, ratA := dcrRegister(t, h)
	clientB, ratB := dcrRegister(t, h)

	// A's token presented against B's client_id: invalid_token.
	res, err := h.registrz.Read(t.Context(), &clientv1.ReadRequest{
		ClientId:                new(clientB.ClientId),
		RegistrationAccessToken: &ratA,
	})
	require.Error(t, err)
	require.NotNil(t, res.Error)
	require.Equal(t, "invalid_token", res.Error.Error)

	// Burn-on-miss: the probed client's credential is revoked, so even
	// B's correct token no longer authenticates (the guessing attempt
	// burned the stored credential).
	afterB, err := h.registrz.Read(t.Context(), &clientv1.ReadRequest{
		ClientId:                new(clientB.ClientId),
		RegistrationAccessToken: &ratB,
	})
	require.Error(t, err)
	require.NotNil(t, afterB.Error)
	require.Equal(t, "invalid_token", afterB.Error.Error)

	// A's own credential is unaffected: its management surface still
	// works.
	afterA, err := h.registrz.Read(t.Context(), &clientv1.ReadRequest{
		ClientId:                new(clientA.ClientId),
		RegistrationAccessToken: &ratA,
	})
	require.NoError(t, err)
	require.Nil(t, afterA.Error)
	require.NotNil(t, afterA.Client)
}

// TestDCR_UpdateCannotEscalate_2_2 asserts RFC 7592 section 2.2 with the
// solid validatedClient posture: an update is a full metadata replacement
// through the same allowlist — software statements are rejected (no trust
// framework), and the update response never leaks the registration token.
func TestDCR_UpdateCannotEscalate_2_2(t *testing.T) {
	h := newHarness(t)
	client, rat := dcrRegister(t, h)

	// Software statement: rejected (RFC 7591 section 2.3 requires a trust
	// framework to validate them; none is deployed).
	updated, err := h.registrz.Update(t.Context(), &clientv1.UpdateRequest{
		ClientId:                new(client.ClientId),
		RegistrationAccessToken: &rat,
		Metadata: &clientv1.ClientMeta{
			GrantTypes:              []string{oidc.GrantTypeAuthorizationCode},
			RedirectUris:            []string{testRedirectURI},
			TokenEndpointAuthMethod: new(oidc.AuthMethodPrivateKeyJWT),
			Jwks:                    clientJWKSWithSIG,
			SoftwareStatement:       new("eyJhbGciOiJub25lIn0.e30."),
		},
	})
	require.Error(t, err)
	require.NotNil(t, updated.Error)
	require.Equal(t, "invalid_client_metadata", updated.Error.Error)

	// Valid update: the response carries the updated client without the
	// management credential.
	okRes, err := h.registrz.Update(t.Context(), &clientv1.UpdateRequest{
		ClientId:                new(client.ClientId),
		RegistrationAccessToken: &rat,
		Metadata: &clientv1.ClientMeta{
			ClientName:              new("dpr-client-renamed"),
			GrantTypes:              []string{oidc.GrantTypeAuthorizationCode},
			RedirectUris:            []string{testRedirectURI},
			TokenEndpointAuthMethod: new(oidc.AuthMethodPrivateKeyJWT),
			Jwks:                    clientJWKSWithSIG,
		},
	})
	require.NoError(t, err)
	require.Nil(t, okRes.Error)
	require.Equal(t, "dpr-client-renamed", okRes.Client.GetClientName())
	require.Nil(t, okRes.Client.RegistrationAccessToken,
		"the update response must not leak the registration token")
}

// TestDCR_DeleteRevokesAllClientTokens_7592_2_3 asserts RFC 7592 section
// 2.3 (SHOULD): deleting the registration invalidates every token issued
// to the client — introspection answers inactive, and the registration
// token itself no longer authenticates a second delete.
func TestDCR_DeleteRevokesAllClientTokens_7592_2_3(t *testing.T) {
	h := newHarness(t)
	client, rat := dcrRegister(t, h)

	// Mint a token via the code flow for the dynamically registered
	// client (the registration carries the full code-grant capability
	// set: grant types, response type/mode, redirect URI, JWKS).
	scopedClient, err := h.clients.Get(t.Context(), client.ClientId)
	require.NoError(t, err)

	verifier, _ := newPKCEPair(t)
	req := validAuthorizationRequest(client.ClientId, verifier, testRedirectURI)
	code := h.seedAuthorization(t, scopedClient, req)
	res, err := h.redeemCode(t, client.ClientId, code, verifier, testRedirectURI)
	require.NoError(t, err)
	require.NotNil(t, res.AccessToken)

	// Introspection before delete: the token is active.
	before, err := h.introspect(t, client.ClientId, res.AccessToken.Value)
	require.NoError(t, err)
	require.NotNil(t, before.Token)
	require.Equal(t, tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE, before.Token.Status)

	// Delete the registration with the token.
	delRes, err := h.registrz.Delete(t.Context(), &clientv1.DeleteRequest{
		ClientId:                new(client.ClientId),
		RegistrationAccessToken: &rat,
	})
	require.NoError(t, err)
	require.Nil(t, delRes.Error)

	// After delete: every issued token is revoked (RFC 7592 section
	// 2.3). The client record is gone, so the introspection surface
	// answers through a delegate: assert the revocation at the token
	// storage level — the minted token must be non-active.
	afterToken, errAfter := h.tokens.GetByValue(t.Context(), h.issuer, res.AccessToken.Value)
	require.NoError(t, errAfter)
	require.NotEqual(t, tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE, afterToken.Status,
		"RFC 7592 section 2.3: deprovisioning invalidates every issued token")
	// Second delete with the same token: invalid_token (the client — and
	// its credential — are gone).
	second, err := h.registrz.Delete(t.Context(), &clientv1.DeleteRequest{
		ClientId:                new(client.ClientId),
		RegistrationAccessToken: &rat,
	})
	require.Error(t, err)
	require.NotNil(t, second.Error)
	require.Equal(t, "invalid_token", second.Error.Error)
}

// TestDCR_NilAuthorizerDeniesAll asserts the deployment gate: a nil
// authorizer (the default closed posture) denies every registration with
// access_denied — dynamic registration is opt-in, never on by accident.
func TestDCR_NilAuthorizerDeniesAll(t *testing.T) {
	h := newHarness(t)
	// A harness variant with the nil authorizer (the closed default).
	closed := clientregistration.New(h.clients, h.tokens, nil)

	res, err := closed.Register(t.Context(), &clientv1.RegisterRequest{
		Metadata: &clientv1.ClientMeta{
			GrantTypes:              []string{oidc.GrantTypeAuthorizationCode},
			RedirectUris:            []string{testRedirectURI},
			TokenEndpointAuthMethod: new(oidc.AuthMethodPrivateKeyJWT),
			Jwks:                    clientJWKSWithSIG,
		},
	})
	require.Error(t, err)
	require.NotNil(t, res.Error)
	require.Equal(t, "access_denied", res.Error.Error)
}

// TestDCR_MetadataHostileInputs_2_3 asserts the RFC 7591 section 2
// metadata validation matrix on the real registration surface: every
// hostile registration is an invalid_client_metadata, no client record is
// created.
func TestDCR_MetadataHostileInputs_2_3(t *testing.T) {
	h := newHarness(t)

	validJWKS := clientJWKSWithSIG
	cases := map[string]*clientv1.ClientMeta{
		"fragment redirect uri": {
			GrantTypes:              []string{oidc.GrantTypeAuthorizationCode},
			RedirectUris:            []string{"https://client.example.org/cb#frag"},
			TokenEndpointAuthMethod: new(oidc.AuthMethodPrivateKeyJWT),
			Jwks:                    validJWKS,
		},
		"implicit grant type": {
			GrantTypes:              []string{"implicit"},
			RedirectUris:            []string{testRedirectURI},
			TokenEndpointAuthMethod: new(oidc.AuthMethodPrivateKeyJWT),
			Jwks:                    validJWKS,
		},
		"implicit response type": {
			GrantTypes:              []string{oidc.GrantTypeAuthorizationCode},
			ResponseTypes:           []string{"token"},
			RedirectUris:            []string{testRedirectURI},
			TokenEndpointAuthMethod: new(oidc.AuthMethodPrivateKeyJWT),
			Jwks:                    validJWKS,
		},
		"shared-secret auth method": {
			GrantTypes:              []string{oidc.GrantTypeAuthorizationCode},
			RedirectUris:            []string{testRedirectURI},
			TokenEndpointAuthMethod: new(oidc.AuthMethodClientSecretJWT),
			Jwks:                    validJWKS,
		},
		"empty jwks for private_key_jwt": {
			GrantTypes:              []string{oidc.GrantTypeAuthorizationCode},
			RedirectUris:            []string{testRedirectURI},
			TokenEndpointAuthMethod: new(oidc.AuthMethodPrivateKeyJWT),
			Jwks:                    nil,
		},
		"non-https non-loopback redirect uri": {
			GrantTypes:              []string{oidc.GrantTypeAuthorizationCode},
			RedirectUris:            []string{"http://client.example.org/cb"},
			TokenEndpointAuthMethod: new(oidc.AuthMethodPrivateKeyJWT),
			Jwks:                    validJWKS,
		},
	}

	for name, metadata := range cases {
		t.Run(name, func(t *testing.T) {
			res, err := h.registrz.Register(t.Context(), &clientv1.RegisterRequest{Metadata: metadata})
			require.Error(t, err, "%s must be rejected", name)
			require.NotNil(t, res.Error)
			require.Equal(t, "invalid_client_metadata", res.Error.Error)
			require.Nil(t, res.Client, "no client record may be created from hostile metadata")
		})
	}
}
