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
// software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

// Adversarial tests for draft-ietf-oauth-attestation-based-client-auth-11
// (attest_jwt_client_auth): each test names the draft section it exercises
// and drives the real client-authentication middleware over HTTP.

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptoRand "crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/spiffe"
	"zntr.io/solid/server/clientauthentication"
	"zntr.io/solid/server/httpkit"
	"zntr.io/solid/server/profile"
)

// attestation constants for the adversarial fixtures.
const (
	abc11AttesterClientID = "urn:test:attester"
	abc11ClientID         = "attest-int-client"
)

// abc11Keys materializes the raw signing keys used by the adversarial tests:
// attesterKey signs attestations, clientKey is bound in cnf and signs the PoP.
type abc11Keys struct {
	attesterRaw any
	clientRaw   any
	clientPub   json.RawMessage // public JWK of clientKey (cnf.jwk payload)
	clientPriv  json.RawMessage // full private JWK of clientKey (adversarial)
}

func newABC11Keys(t *testing.T) *abc11Keys {
	t.Helper()

	attesterKey, err := jwxjwk.ParseKey(clientPrivateKey)
	require.NoError(t, err)
	clientKey, err := jwxjwk.Import(generateABC11ECDSAKey(t))
	require.NoError(t, err)

	var attesterRaw, clientRaw any
	require.NoError(t, jwxjwk.Export(attesterKey, &attesterRaw))
	require.NoError(t, jwxjwk.Export(clientKey, &clientRaw))

	clientPub, err := jwxjwk.PublicKeyOf(clientKey)
	require.NoError(t, err)
	pubJSON, err := json.Marshal(clientPub)
	require.NoError(t, err)
	privJSON, err := json.Marshal(clientKey)
	require.NoError(t, err)

	return &abc11Keys{
		attesterRaw: attesterRaw,
		clientRaw:   clientRaw,
		clientPub:   pubJSON,
		clientPriv:  privJSON,
	}
}

// generateABC11ECDSAKey generates a fresh P-256 key for the PoP signer.
func generateABC11ECDSAKey(t *testing.T) any {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), cryptoRand.Reader)
	require.NoError(t, err)
	return k
}

// registerAttestationClients registers the attester (whose JWKS pins the
// attestation signing key) and the attested client (registered for
// attest_jwt_client_auth), returning the generated client ids. The in-memory
// store assigns random ids; the attestation iss/sub claims are rebuilt per
// test against them. No application type is set, so the middleware's
// profile check is skipped (mirrors registerConfidentialClient).
func registerAttestationClients(t *testing.T, h *harness) (attesterID, attestedID string) {
	t.Helper()

	attesterID, err := h.clients.Register(context.Background(), &clientv1.Client{
		ClientType: clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		ClientName: "test-attester",
		Jwks:       clientJWKSWithSIG,
	})
	require.NoError(t, err)

	attestedID, err = h.clients.Register(context.Background(), &clientv1.Client{
		ClientType:              clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		ClientName:              "attestation-int-client",
		GrantTypes:              []string{oidc.GrantTypeClientCredentials},
		TokenEndpointAuthMethod: oidc.AuthMethodClientAttestationJWT,
	})
	require.NoError(t, err)

	return attesterID, attestedID
}

// buildAttestationJWT signs a Client Attestation JWT (draft section 4).
// cnfPrivate embeds the full private JWK in cnf.jwk (adversarial, section
// 7.1 rule 5). expOffset is added to now for the exp claim (negative for
// stale).
func buildAttestationJWT(t *testing.T, keys *abc11Keys, attesterID, sub string, cnfPrivate bool, typ string, expOffset time.Duration) string {
	t.Helper()

	now := uint64(time.Now().Unix())
	cnf := keys.clientPub
	if cnfPrivate {
		cnf = keys.clientPriv
	}

	tok := gojwt.NewWithClaims(gojwt.SigningMethodES256, gojwt.MapClaims{
		"iss": attesterID,
		"sub": sub,
		"exp": attestationExpiryAt(now, expOffset),
		"iat": now,
		"cnf": map[string]any{
			"jwk": cnf,
		},
	})
	if typ != "" {
		tok.Header["typ"] = typ
	}
	raw, err := tok.SignedString(keys.attesterRaw)
	require.NoError(t, err)
	return raw
}

// buildAttestationJWTWithRawKey signs the attestation with an arbitrary key
// (adversarial: untrusted attester, section 7.1 rule 4).
func buildAttestationJWTWithRawKey(t *testing.T, keys *abc11Keys, attesterID, sub string, signingRaw any, typ string, expOffset time.Duration) string {
	t.Helper()

	now := uint64(time.Now().Unix())
	tok := gojwt.NewWithClaims(gojwt.SigningMethodES256, gojwt.MapClaims{
		"iss": attesterID,
		"sub": sub,
		"iat": now,
		"exp": attestationExpiryAt(now, expOffset),
		"cnf": map[string]any{
			"jwk": keys.clientPub,
		},
	})
	if typ != "" {
		tok.Header["typ"] = typ
	}
	raw, err := tok.SignedString(signingRaw)
	require.NoError(t, err)
	return raw
}

// buildAttestationPoP signs a Client Attestation PoP JWT (draft section 5.1).
// signingRaw overrides the PoP signer (adversarial: key mismatch).
func buildAttestationPoP(t *testing.T, keys *abc11Keys, aud, jti string, iat time.Time, typ string, signingRaw any) string {
	t.Helper()

	if signingRaw == nil {
		signingRaw = keys.clientRaw
	}

	claims := gojwt.MapClaims{
		"aud": aud,
		"jti": jti,
	}
	if !iat.IsZero() {
		claims["iat"] = uint64(iat.Unix())
	}
	tok := gojwt.NewWithClaims(gojwt.SigningMethodES256, claims)
	if typ != "" {
		tok.Header["typ"] = typ
	}
	raw, err := tok.SignedString(signingRaw)
	require.NoError(t, err)
	return raw
}

// abc11HTTPServer wires the client-authentication middleware with a stub
// handler asserting the injected client identity (mirrors oauth21HTTPServer).
func abc11HTTPServer(h *harness, stubHandler http.Handler) *httptest.Server {
	return httptest.NewServer(httpkit.ClientAuthentication(
		h.clients,
		h.issuer,
		[]string{"ES256"},
		spiffe.NewStaticBundleSource(nil),
		h.proofs,
		profile.Strict(),
	)(stubHandler))
}

// abc11StubHandler captures the client resolved by the middleware.
func abc11StubHandler(t *testing.T, gotClientID *string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		client, ok := clientauthentication.FromContext(r.Context())
		require.True(t, ok, "client must be injected into the request context")
		*gotClientID = client.ClientId
		w.WriteHeader(http.StatusOK)
	})
}

// postABC11TokenRequest performs a token-endpoint POST with the
// OAuth-Client-Attestation header pair (draft sections 4/5.1).
func postABC11TokenRequest(t *testing.T, ts *httptest.Server, clientID, attestation, pop string) (*http.Response, map[string]any) {
	t.Helper()

	form := url.Values{}
	form.Set("grant_type", oidc.GrantTypeClientCredentials)
	if clientID != "" {
		form.Set("client_id", clientID)
	}

	req, err := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if attestation != "" {
		req.Header.Set("OAuth-Client-Attestation", attestation)
	}
	if pop != "" {
		req.Header.Set("OAuth-Client-Attestation-PoP", pop)
	}

	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = res.Body.Close() })

	var body map[string]any
	// Stub handlers may reply with an empty body; only a JSON error
	// surface is asserted on.
	_ = json.NewDecoder(res.Body).Decode(&body)
	if body == nil {
		body = map[string]any{}
	}
	return res, body
}

// requireABC11Error asserts the status code and error code of a failed
// request.
func requireABC11Error(t *testing.T, res *http.Response, body map[string]any, wantStatus int, wantCode string) {
	t.Helper()
	require.Equal(t, wantStatus, res.StatusCode, "status code mismatch: body %v", body)
	require.Equal(t, wantCode, body["error"], "error code mismatch: body %v", body)
}

// -----------------------------------------------------------------------------
// Happy paths

// TestABC11_HeaderTransportHappyPath_7 exercises draft sections 4/5.1/7:
// a valid attestation + PoP header pair authenticates the client through the
// real middleware.
func TestABC11_HeaderTransportHappyPath_7(t *testing.T) {
	h := newHarness(t)
	attesterID, attestedID := registerAttestationClients(t, h)
	keys := newABC11Keys(t)

	attestation := buildAttestationJWT(t, keys, attesterID, attestedID, false, oidc.TypClientAttestationJWT, 5*time.Minute)
	pop := buildAttestationPoP(t, keys, h.issuer, "abc11-happy", time.Now(), oidc.TypClientAttestationPoPJWT, nil)

	var gotClientID string
	ts := abc11HTTPServer(h, abc11StubHandler(t, &gotClientID))
	defer ts.Close()

	res, body := postABC11TokenRequest(t, ts, attestedID, attestation, pop)
	require.Equal(t, http.StatusOK, res.StatusCode, "body %v", body)
	require.Equal(t, attestedID, gotClientID, "middleware must resolve the attested client")
}

// TestABC11_TokenGrantEndToEnd_7_5 drives the full token-endpoint stack:
// the middleware-injected client flows into the client_credentials grant and
// mints an access token (draft section 7.5 client_id ↔ sub binding).
func TestABC11_TokenGrantEndToEnd_7_5(t *testing.T) {
	h := newHarness(t)
	attesterID, attestedID := registerAttestationClients(t, h)
	keys := newABC11Keys(t)

	attestation := buildAttestationJWT(t, keys, attesterID, attestedID, false, oidc.TypClientAttestationJWT, 5*time.Minute)
	pop := buildAttestationPoP(t, keys, h.issuer, "abc11-e2e", time.Now(), oidc.TypClientAttestationPoPJWT, nil)

	ts := httptest.NewServer(httpkit.ClientAuthentication(
		h.clients,
		h.issuer,
		[]string{"ES256"},
		spiffe.NewStaticBundleSource(nil),
		h.proofs,
		profile.Strict(),
	)(httpkit.Token(h.issuer, h.tokenz, buildDPoPVerifier(), profile.Strict())))
	defer ts.Close()

	res, body := postABC11TokenRequest(t, ts, attestedID, attestation, pop)
	require.Equal(t, http.StatusOK, res.StatusCode, "body %v", body)
	accessToken, _ := body["access_token"].(string)
	require.NotEmpty(t, accessToken, "token endpoint must mint an access token")
}

// -----------------------------------------------------------------------------
// Adversarial cases

// TestABC11_AttestationTypNotEnforced_4_7_1: the legacy
// client-attestation+jwt typ is rejected (draft section 7.1 rule 2).
func TestABC11_AttestationTypNotEnforced_4_7_1(t *testing.T) {
	h := newHarness(t)
	attesterID, attestedID := registerAttestationClients(t, h)
	keys := newABC11Keys(t)

	attestation := buildAttestationJWT(t, keys, attesterID, attestedID, false, "client-attestation+jwt", 5*time.Minute)
	pop := buildAttestationPoP(t, keys, h.issuer, "abc11-typ-att", time.Now(), oidc.TypClientAttestationPoPJWT, nil)

	ts := abc11HTTPServer(h, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	res, body := postABC11TokenRequest(t, ts, attestedID, attestation, pop)
	requireABC11Error(t, res, body, http.StatusUnauthorized, "invalid_client_attestation")
}

// TestABC11_PoPTypWrong_5_1_7_2: a PoP with the legacy typ is rejected
// (draft sections 5.1 rule 2 / 7.2 rule 2).
func TestABC11_PoPTypWrong_5_1_7_2(t *testing.T) {
	h := newHarness(t)
	attesterID, attestedID := registerAttestationClients(t, h)
	keys := newABC11Keys(t)

	attestation := buildAttestationJWT(t, keys, attesterID, attestedID, false, oidc.TypClientAttestationJWT, 5*time.Minute)
	pop := buildAttestationPoP(t, keys, h.issuer, "abc11-typ-pop", time.Now(), "client-attestation-pop+jwt", nil)

	ts := abc11HTTPServer(h, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	res, body := postABC11TokenRequest(t, ts, attestedID, attestation, pop)
	requireABC11Error(t, res, body, http.StatusUnauthorized, "invalid_client_attestation")
}

// TestABC11_ClientIdSubMismatch_7_1_7_5: a request client_id differing from
// the attestation sub is rejected (draft section 7.5).
func TestABC11_ClientIdSubMismatch_7_1_7_5(t *testing.T) {
	h := newHarness(t)
	attesterID, attestedID := registerAttestationClients(t, h)
	keys := newABC11Keys(t)

	attestation := buildAttestationJWT(t, keys, attesterID, attestedID, false, oidc.TypClientAttestationJWT, 5*time.Minute)
	pop := buildAttestationPoP(t, keys, h.issuer, "abc11-sub-mismatch", time.Now(), oidc.TypClientAttestationPoPJWT, nil)

	ts := abc11HTTPServer(h, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	res, body := postABC11TokenRequest(t, ts, "other-client", attestation, pop)
	requireABC11Error(t, res, body, http.StatusUnauthorized, "invalid_client_attestation")
}

// TestABC11_PoPAudienceForeign_7_2: a PoP addressed to a foreign audience is
// rejected (draft section 7.2 rule 7).
func TestABC11_PoPAudienceForeign_7_2(t *testing.T) {
	h := newHarness(t)
	attesterID, attestedID := registerAttestationClients(t, h)
	keys := newABC11Keys(t)

	attestation := buildAttestationJWT(t, keys, attesterID, attestedID, false, oidc.TypClientAttestationJWT, 5*time.Minute)
	pop := buildAttestationPoP(t, keys, "https://evil.example", "abc11-aud-foreign", time.Now(), oidc.TypClientAttestationPoPJWT, nil)

	ts := abc11HTTPServer(h, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	res, body := postABC11TokenRequest(t, ts, attestedID, attestation, pop)
	requireABC11Error(t, res, body, http.StatusUnauthorized, "invalid_client_attestation")
}

// TestABC11_PoPMissingIat_5_1: a PoP without iat is rejected (draft section
// 5.1 rule 4: iat REQUIRED).
func TestABC11_PoPMissingIat_5_1(t *testing.T) {
	h := newHarness(t)
	attesterID, attestedID := registerAttestationClients(t, h)
	keys := newABC11Keys(t)

	attestation := buildAttestationJWT(t, keys, attesterID, attestedID, false, oidc.TypClientAttestationJWT, 5*time.Minute)
	pop := buildAttestationPoP(t, keys, h.issuer, "abc11-no-iat", time.Time{}, oidc.TypClientAttestationPoPJWT, nil)

	ts := abc11HTTPServer(h, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	res, body := postABC11TokenRequest(t, ts, attestedID, attestation, pop)
	requireABC11Error(t, res, body, http.StatusUnauthorized, "invalid_client_attestation")
}

// TestABC11_PoPKeyMismatch_7_2: a PoP signed by a key that is not the
// cnf-bound key is rejected (draft section 7.2 rule 5).
func TestABC11_PoPKeyMismatch_7_2(t *testing.T) {
	h := newHarness(t)
	attesterID, attestedID := registerAttestationClients(t, h)
	keys := newABC11Keys(t)

	attestation := buildAttestationJWT(t, keys, attesterID, attestedID, false, oidc.TypClientAttestationJWT, 5*time.Minute)
	pop := buildAttestationPoP(t, keys, h.issuer, "abc11-key-mismatch", time.Now(), oidc.TypClientAttestationPoPJWT, generateABC11ECDSAKey(t))

	ts := abc11HTTPServer(h, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	res, body := postABC11TokenRequest(t, ts, attestedID, attestation, pop)
	requireABC11Error(t, res, body, http.StatusUnauthorized, "invalid_client_attestation")
}

// TestABC11_AttesterUntrusted_7_1: an attestation signed by a key outside
// the attester JWKS is rejected (draft section 7.1 rule 4).
func TestABC11_AttesterUntrusted_7_1(t *testing.T) {
	h := newHarness(t)
	attesterID, attestedID := registerAttestationClients(t, h)
	keys := newABC11Keys(t)

	attestation := buildAttestationJWTWithRawKey(t, keys, attesterID, attestedID, generateABC11ECDSAKey(t), oidc.TypClientAttestationJWT, 5*time.Minute)
	pop := buildAttestationPoP(t, keys, h.issuer, "abc11-untrusted", time.Now(), oidc.TypClientAttestationPoPJWT, nil)

	ts := abc11HTTPServer(h, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	res, body := postABC11TokenRequest(t, ts, attestedID, attestation, pop)
	requireABC11Error(t, res, body, http.StatusUnauthorized, "invalid_client_attestation")
}

// TestABC11_StaleAttestation_7_4: an expired attestation yields 400
// use_fresh_attestation (draft section 7.4).
func TestABC11_StaleAttestation_7_4(t *testing.T) {
	h := newHarness(t)
	attesterID, attestedID := registerAttestationClients(t, h)
	keys := newABC11Keys(t)

	attestation := buildAttestationJWT(t, keys, attesterID, attestedID, false, oidc.TypClientAttestationJWT, -5*time.Minute)
	pop := buildAttestationPoP(t, keys, h.issuer, "abc11-stale", time.Now(), oidc.TypClientAttestationPoPJWT, nil)

	ts := abc11HTTPServer(h, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	res, body := postABC11TokenRequest(t, ts, attestedID, attestation, pop)
	requireABC11Error(t, res, body, http.StatusBadRequest, "use_fresh_attestation")
}

// TestABC11_CnfPrivateMaterial_7_1: a cnf.jwk carrying private key material
// is rejected (draft section 7.1 rule 5).
func TestABC11_CnfPrivateMaterial_7_1(t *testing.T) {
	h := newHarness(t)
	attesterID, attestedID := registerAttestationClients(t, h)
	keys := newABC11Keys(t)

	attestation := buildAttestationJWT(t, keys, attesterID, attestedID, true, oidc.TypClientAttestationJWT, 5*time.Minute)
	pop := buildAttestationPoP(t, keys, h.issuer, "abc11-cnf-private", time.Now(), oidc.TypClientAttestationPoPJWT, nil)

	ts := abc11HTTPServer(h, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	res, body := postABC11TokenRequest(t, ts, attestedID, attestation, pop)
	requireABC11Error(t, res, body, http.StatusUnauthorized, "invalid_client_attestation")
}

// TestABC11_PoPReplay_12_1: replaying an identical PoP (same jti) is
// rejected on the second request (draft section 12.1).
func TestABC11_PoPReplay_12_1(t *testing.T) {
	h := newHarness(t)
	attesterID, attestedID := registerAttestationClients(t, h)
	keys := newABC11Keys(t)

	attestation := buildAttestationJWT(t, keys, attesterID, attestedID, false, oidc.TypClientAttestationJWT, 5*time.Minute)
	pop := buildAttestationPoP(t, keys, h.issuer, "abc11-replay", time.Now(), oidc.TypClientAttestationPoPJWT, nil)

	var gotClientID string
	ts := abc11HTTPServer(h, abc11StubHandler(t, &gotClientID))
	defer ts.Close()

	res, body := postABC11TokenRequest(t, ts, attestedID, attestation, pop)
	require.Equal(t, http.StatusOK, res.StatusCode, "first request must succeed: body %v", body)

	res, body = postABC11TokenRequest(t, ts, attestedID, attestation, pop)
	requireABC11Error(t, res, body, http.StatusUnauthorized, "invalid_client_attestation")
}

// TestABC11_MissingPoPHeader_7_2: presenting only the attestation header
// misses the dispatcher (both headers required) and yields 401
// invalid_request.
func TestABC11_MissingPoPHeader_7_2(t *testing.T) {
	h := newHarness(t)
	attesterID, attestedID := registerAttestationClients(t, h)
	keys := newABC11Keys(t)

	attestation := buildAttestationJWT(t, keys, attesterID, attestedID, false, oidc.TypClientAttestationJWT, 5*time.Minute)

	ts := abc11HTTPServer(h, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	res, body := postABC11TokenRequest(t, ts, attestedID, attestation, "")
	requireABC11Error(t, res, body, http.StatusUnauthorized, "invalid_request")
}

// TestABC11_WITRoutingUnaffected: a WIT-SVID pair (typ wit+jwt) still routes
// to the SPIFFE WIT processor and fails on signature (no example.org bundle
// registered) — the typ-based dispatch did not break the WIT route.
func TestABC11_WITRoutingUnaffected(t *testing.T) {
	h := newHarness(t)
	attesterID, _ := registerAttestationClients(t, h)
	keys := newABC11Keys(t)

	attestation := buildAttestationJWT(t, keys, attesterID, "spiffe://example.org/wit-workload", false, "wit+jwt", 5*time.Minute)
	pop := buildAttestationPoP(t, keys, h.issuer, "abc11-wit-route", time.Now(), "oauth-client-attestation-pop+jwt", nil)

	ts := abc11HTTPServer(h, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	res, body := postABC11TokenRequest(t, ts, "", attestation, pop)
	require.Equal(t, http.StatusUnauthorized, res.StatusCode, "body %v", body)
	require.NotEqual(t, "invalid_client_attestation", body["error"],
		"WIT requests must not be handled by the client-attestation processor")
}

// attestationExpiryAt computes the attestation exp claim, supporting negative
// offsets (expiry in the past) without uint64 wraparound.
func attestationExpiryAt(now uint64, offset time.Duration) uint64 {
	if offset >= 0 {
		return now + uint64(offset.Seconds())
	}
	return now - uint64(-offset.Seconds())
}
