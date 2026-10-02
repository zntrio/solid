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

package clientauthentication

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"go.uber.org/mock/gomock"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/server/storage/inmemory"
	storagemock "zntr.io/solid/server/storage/mock"
)

const (
	attestIssuer         = "http://localhost:8080"
	attestTokenEndpoint  = "http://localhost:8080/token"
	attestClientID       = "attest-client"
	testAttesterClientID = "urn:test:attester"
)

// attestationFixture holds the keys used to build a Client Attestation JWT
// and its PoP JWT (draft-ietf-oauth-attestation-based-client-auth-11).
type attestationFixture struct {
	// attesterKey signs the attestation (registered attester signing key).
	attesterKey jwxjwk.Key
	// clientKey is bound in cnf.jwk and signs the PoP.
	clientKey jwxjwk.Key
}

func newAttestationFixture() *attestationFixture {
	return &attestationFixture{
		attesterKey: mustImportTestKey(),
		clientKey:   mustImportTestKey(),
	}
}

// buildAttestationAndPoP builds a Client Attestation JWT and its PoP JWT
// per draft-ietf-oauth-attestation-based-client-auth-11 sections 4 and 5.1.
// attestationLifetime is the attestation exp offset (negative for expired).
// popKey overrides the PoP signer (to simulate a different key); cnfKey
// overrides the cnf.jwk-embedded key.
func (f *attestationFixture) buildAttestationAndPoP(t *testing.T, audience, clientID, jti string, attestationLifetime time.Duration, popKey, cnfKey jwxjwk.Key, attestationTyp, popTyp string, includeIAT bool, cnfPrivate bool) (string, string) {
	t.Helper()

	var attesterRaw any
	if err := jwxjwk.Export(f.attesterKey, &attesterRaw); err != nil {
		t.Fatalf("unable to materialize attester signing key: %v", err)
	}
	if cnfKey == nil {
		cnfKey = f.clientKey
	}
	var cnfKeyForJWK jwxjwk.Key = cnfKey
	if cnfPrivate {
		// Embed the full private JWK (must be rejected per draft section 7.1 rule 5).
		cnfKeyForJWK = cnfKey
	}
	cnfPub, err := jwxjwk.PublicKeyOf(cnfKeyForJWK)
	if err != nil {
		t.Fatalf("unable to derive cnf public key: %v", err)
	}
	var cnfJWK json.RawMessage
	if cnfPrivate {
		privJSON, err := json.Marshal(cnfKey)
		if err != nil {
			t.Fatalf("unable to serialize cnf private key: %v", err)
		}
		cnfJWK = privJSON
	} else {
		pubJSON, err := json.Marshal(cnfPub)
		if err != nil {
			t.Fatalf("unable to serialize cnf public key: %v", err)
		}
		cnfJWK = pubJSON
	}

	now := uint64(time.Now().Unix())

	// Client Attestation JWT (draft section 4).
	attestationClaims := gojwt.MapClaims{
		"iss": testAttesterClientID,
		"sub": clientID,
		"exp": attestationExpiry(now, attestationLifetime),
		"iat": now,
		"cnf": map[string]any{
			"jwk": cnfJWK,
		},
	}
	attestationTok := gojwt.NewWithClaims(gojwt.SigningMethodES256, attestationClaims)
	if attestationTyp != "" {
		attestationTok.Header["typ"] = attestationTyp
	}
	attestation, err := attestationTok.SignedString(attesterRaw)
	if err != nil {
		t.Fatalf("unable to sign attestation: %v", err)
	}

	// Client Attestation PoP JWT (draft section 5.1).
	if popKey == nil {
		popKey = f.clientKey
	}
	var popRaw any
	if err := jwxjwk.Export(popKey, &popRaw); err != nil {
		t.Fatalf("unable to materialize pop key: %v", err)
	}
	popClaims := gojwt.MapClaims{
		"aud": audience,
		"jti": jti,
	}
	if includeIAT {
		popClaims["iat"] = now
	}
	popTok := gojwt.NewWithClaims(gojwt.SigningMethodES256, popClaims)
	if popTyp != "" {
		popTok.Header["typ"] = popTyp
	}
	pop, err := popTok.SignedString(popRaw)
	if err != nil {
		t.Fatalf("unable to sign pop: %v", err)
	}

	return attestation, pop
}

// buildValidPair builds a fully valid attestation + PoP pair.
func (f *attestationFixture) buildValidPair(t *testing.T, clientID, jti string) (string, string) {
	t.Helper()
	return f.buildAttestationAndPoP(t, attestIssuer, clientID, jti, 5*time.Minute, nil, nil,
		oidc.TypClientAttestationJWT, oidc.TypClientAttestationPoPJWT, true, false)
}

func Test_clientAttestationAuthentication_Authenticate(t *testing.T) {
	tests := []struct {
		name    string
		build   func(t *testing.T, f *attestationFixture) (attestation, pop string)
		prepare func(clients *storagemock.MockClientReader, f *attestationFixture)
		wantErr bool
		// wantErrorCode asserts the emitted protocol error code (draft section 7.4).
		wantErrorCode string
		// replay means: the first call must succeed and the second must fail.
		replay bool
	}{
		{
			name: "valid",
			build: func(t *testing.T, f *attestationFixture) (string, string) {
				return f.buildValidPair(t, attestClientID, "pop-ok-1")
			},
			prepare: func(clients *storagemock.MockClientReader, f *attestationFixture) {
				attesterJWKS := attesterJWKSFor(t, f)
				clients.EXPECT().Get(gomock.Any(), testAttesterClientID).Return(&clientv1.Client{
					ClientId: testAttesterClientID,
					Jwks:     attesterJWKS,
				}, nil)
				clients.EXPECT().Get(gomock.Any(), attestClientID).Return(&clientv1.Client{
					ClientId:                attestClientID,
					TokenEndpointAuthMethod: oidc.AuthMethodClientAttestationJWT,
				}, nil)
			},
		},
		{
			// draft section 7.1 rule 2: typ must be oauth-client-attestation+jwt.
			name: "attestation typ wrong (legacy client-attestation+jwt)",
			build: func(t *testing.T, f *attestationFixture) (string, string) {
				return f.buildAttestationAndPoP(t, attestIssuer, attestClientID, "pop-typ-att", 5*time.Minute, nil, nil,
					"client-attestation+jwt", oidc.TypClientAttestationPoPJWT, true, false)
			},
			prepare: func(clients *storagemock.MockClientReader, f *attestationFixture) {},
			wantErr: true, wantErrorCode: "invalid_client_attestation",
		},
		{
			// draft section 7.1 rule 2: typ is required.
			name: "attestation typ missing",
			build: func(t *testing.T, f *attestationFixture) (string, string) {
				return f.buildAttestationAndPoP(t, attestIssuer, attestClientID, "pop-typ-att2", 5*time.Minute, nil, nil,
					"", oidc.TypClientAttestationPoPJWT, true, false)
			},
			prepare: func(clients *storagemock.MockClientReader, f *attestationFixture) {},
			wantErr: true, wantErrorCode: "invalid_client_attestation",
		},
		{
			// draft section 5.1 rule 2 / section 7.2 rule 2: PoP typ must be
			// oauth-client-attestation-pop+jwt.
			name: "PoP typ wrong (legacy client-attestation-pop+jwt)",
			build: func(t *testing.T, f *attestationFixture) (string, string) {
				return f.buildAttestationAndPoP(t, attestIssuer, attestClientID, "pop-typ-wrong", 5*time.Minute, nil, nil,
					oidc.TypClientAttestationJWT, "client-attestation-pop+jwt", true, false)
			},
			prepare: func(clients *storagemock.MockClientReader, f *attestationFixture) {
				clients.EXPECT().Get(gomock.Any(), testAttesterClientID).Return(&clientv1.Client{
					ClientId: testAttesterClientID,
					Jwks:     attesterJWKSFor(t, f),
				}, nil)
			},
			wantErr: true, wantErrorCode: "invalid_client_attestation",
		},
		{
			// draft section 7.5: request client_id MUST match attestation sub.
			name: "attestation sub does not match request client_id",
			build: func(t *testing.T, f *attestationFixture) (string, string) {
				return f.buildValidPair(t, "other-client-id", "pop-sub-mismatch")
			},
			prepare: func(clients *storagemock.MockClientReader, f *attestationFixture) {
				clients.EXPECT().Get(gomock.Any(), testAttesterClientID).Return(&clientv1.Client{
					ClientId: testAttesterClientID,
					Jwks:     attesterJWKSFor(t, f),
				}, nil)
				clients.EXPECT().Get(gomock.Any(), "other-client-id").Return(&clientv1.Client{
					ClientId:                "other-client-id",
					TokenEndpointAuthMethod: oidc.AuthMethodClientAttestationJWT,
				}, nil)
			},
			wantErr: true, wantErrorCode: "invalid_client_attestation",
		},
		{
			// draft section 7.2 rule 7: aud must identify the receiving server.
			name: "PoP aud neither issuer nor endpoint",
			build: func(t *testing.T, f *attestationFixture) (string, string) {
				return f.buildAttestationAndPoP(t, "https://evil.example", attestClientID, "pop-aud-foreign", 5*time.Minute, nil, nil,
					oidc.TypClientAttestationJWT, oidc.TypClientAttestationPoPJWT, true, false)
			},
			prepare: func(clients *storagemock.MockClientReader, f *attestationFixture) {
				clients.EXPECT().Get(gomock.Any(), testAttesterClientID).Return(&clientv1.Client{
					ClientId: testAttesterClientID,
					Jwks:     attesterJWKSFor(t, f),
				}, nil)
			},
			wantErr: true, wantErrorCode: "invalid_client_attestation",
		},
		{
			// draft section 5.1 rule 4: iat is REQUIRED in the PoP.
			name: "PoP missing iat",
			build: func(t *testing.T, f *attestationFixture) (string, string) {
				return f.buildAttestationAndPoP(t, attestIssuer, attestClientID, "pop-no-iat", 5*time.Minute, nil, nil,
					oidc.TypClientAttestationJWT, oidc.TypClientAttestationPoPJWT, false, false)
			},
			prepare: func(clients *storagemock.MockClientReader, f *attestationFixture) {
				clients.EXPECT().Get(gomock.Any(), testAttesterClientID).Return(&clientv1.Client{
					ClientId: testAttesterClientID,
					Jwks:     attesterJWKSFor(t, f),
				}, nil)
			},
			wantErr: true, wantErrorCode: "invalid_client_attestation",
		},
		{
			// draft section 7.2 rule 6: creation time within the local-policy
			// freshness window.
			name: "PoP iat older than the freshness window",
			build: func(t *testing.T, f *attestationFixture) (string, string) {
				attestation, _ := f.buildAttestationAndPoP(t, attestIssuer, attestClientID, "pop-stale", 5*time.Minute, nil, nil,
					oidc.TypClientAttestationJWT, oidc.TypClientAttestationPoPJWT, true, false)
				// Rebuild the PoP with an old iat by signing directly.
				var clientRaw any
				if err := jwxjwk.Export(f.clientKey, &clientRaw); err != nil {
					t.Fatalf("unable to materialize client key: %v", err)
				}
				popTok := gojwt.NewWithClaims(gojwt.SigningMethodES256, gojwt.MapClaims{
					"aud": attestIssuer,
					"iat": uint64(time.Now().Add(-15 * time.Minute).Unix()),
					"jti": "pop-stale",
				})
				popTok.Header["typ"] = oidc.TypClientAttestationPoPJWT
				pop, err := popTok.SignedString(clientRaw)
				if err != nil {
					t.Fatalf("unable to sign pop: %v", err)
				}
				return attestation, pop
			},
			prepare: func(clients *storagemock.MockClientReader, f *attestationFixture) {
				clients.EXPECT().Get(gomock.Any(), testAttesterClientID).Return(&clientv1.Client{
					ClientId: testAttesterClientID,
					Jwks:     attesterJWKSFor(t, f),
				}, nil)
			},
			wantErr: true, wantErrorCode: "invalid_client_attestation",
		},
		{
			// draft section 7.2 rule 5: PoP signature must verify with the
			// cnf-bound key.
			name: "PoP signed by a different key than cnf.jwk",
			build: func(t *testing.T, f *attestationFixture) (string, string) {
				otherKey := mustImportTestKey()
				return f.buildAttestationAndPoP(t, attestIssuer, attestClientID, "pop-key-mismatch", 5*time.Minute, otherKey, nil,
					oidc.TypClientAttestationJWT, oidc.TypClientAttestationPoPJWT, true, false)
			},
			prepare: func(clients *storagemock.MockClientReader, f *attestationFixture) {
				clients.EXPECT().Get(gomock.Any(), testAttesterClientID).Return(&clientv1.Client{
					ClientId: testAttesterClientID,
					Jwks:     attesterJWKSFor(t, f),
				}, nil)
			},
			wantErr: true, wantErrorCode: "invalid_client_attestation",
		},
		{
			// draft section 7.1 rule 4: attestation signature must verify with
			// a trusted attester key.
			name: "attestation signed by a key not in the attester JWKS",
			build: func(t *testing.T, f *attestationFixture) (string, string) {
				return f.buildValidPair(t, attestClientID, "pop-untrusted-attester")
			},
			prepare: func(clients *storagemock.MockClientReader, f *attestationFixture) {
				// The registered attester pins a DIFFERENT key than the
				// fixture signing key.
				otherKey := mustImportTestKey()
				clients.EXPECT().Get(gomock.Any(), testAttesterClientID).Return(&clientv1.Client{
					ClientId: testAttesterClientID,
					Jwks:     attesterJWKSFor(t, &attestationFixture{attesterKey: otherKey, clientKey: f.clientKey}),
				}, nil)
			},
			wantErr: true, wantErrorCode: "invalid_client_attestation",
		},
		{
			// draft section 7.4: an expired attestation is the sole
			// use_fresh_attestation condition.
			name: "attestation exp in the past",
			build: func(t *testing.T, f *attestationFixture) (string, string) {
				return f.buildAttestationAndPoP(t, attestIssuer, attestClientID, "pop-exp-att", -5*time.Minute, nil, nil,
					oidc.TypClientAttestationJWT, oidc.TypClientAttestationPoPJWT, true, false)
			},
			prepare: func(clients *storagemock.MockClientReader, f *attestationFixture) {},
			wantErr: true, wantErrorCode: "use_fresh_attestation",
		},
		{
			// draft section 7.1 rule 5: cnf.jwk must not carry private key
			// material ("d" member).
			name: "cnf.jwk carrying a d member",
			build: func(t *testing.T, f *attestationFixture) (string, string) {
				return f.buildAttestationAndPoP(t, attestIssuer, attestClientID, "pop-cnf-private", 5*time.Minute, nil, nil,
					oidc.TypClientAttestationJWT, oidc.TypClientAttestationPoPJWT, true, true)
			},
			prepare: func(clients *storagemock.MockClientReader, f *attestationFixture) {
				clients.EXPECT().Get(gomock.Any(), testAttesterClientID).Return(&clientv1.Client{
					ClientId: testAttesterClientID,
					Jwks:     attesterJWKSFor(t, f),
				}, nil)
			},
			wantErr: true, wantErrorCode: "invalid_client_attestation",
		},
		{
			// draft section 12.1: the PoP jti is single-use.
			name: "PoP jti replay",
			build: func(t *testing.T, f *attestationFixture) (string, string) {
				return f.buildValidPair(t, attestClientID, "pop-replay")
			},
			prepare: func(clients *storagemock.MockClientReader, f *attestationFixture) {
				attesterJWKS := attesterJWKSFor(t, f)
				clients.EXPECT().Get(gomock.Any(), testAttesterClientID).Return(&clientv1.Client{
					ClientId: testAttesterClientID,
					Jwks:     attesterJWKS,
				}, nil).Times(2)
				clients.EXPECT().Get(gomock.Any(), attestClientID).Return(&clientv1.Client{
					ClientId:                attestClientID,
					TokenEndpointAuthMethod: oidc.AuthMethodClientAttestationJWT,
				}, nil).Times(2)
			},
			replay:        true,
			wantErr:       true,
			wantErrorCode: "invalid_client_attestation",
		},
		{
			// Fail-closed registration check: the client must be registered
			// for attest_jwt_client_auth.
			name: "client not registered for attest_jwt_client_auth",
			build: func(t *testing.T, f *attestationFixture) (string, string) {
				return f.buildValidPair(t, attestClientID, "pop-not-registered")
			},
			prepare: func(clients *storagemock.MockClientReader, f *attestationFixture) {
				clients.EXPECT().Get(gomock.Any(), testAttesterClientID).Return(&clientv1.Client{
					ClientId: testAttesterClientID,
					Jwks:     attesterJWKSFor(t, f),
				}, nil)
				clients.EXPECT().Get(gomock.Any(), attestClientID).Return(&clientv1.Client{
					ClientId:                attestClientID,
					TokenEndpointAuthMethod: oidc.AuthMethodPrivateKeyJWT,
				}, nil)
			},
			wantErr: true, wantErrorCode: "invalid_client_attestation",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Arm mocks
			clients := storagemock.NewMockClientReader(ctrl)
			proofs := inmemory.DPoPProofs()
			f := newAttestationFixture()

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(clients, f)
			}

			// Build the attestation + PoP pair.
			attestation, pop := tt.build(t, f)

			// Prepare the request (header-transport fields, draft sections 4/5.1).
			req := &clientv1.AuthenticateRequest{
				ClientAttestation:    &attestation,
				ClientAttestationPop: &pop,
				ClientId:             new(attestClientID),
				Endpoint:             new(attestTokenEndpoint),
			}

			// Prepare service
			underTest := ClientAttestation(clients, proofs, attestIssuer, []string{"ES256"})

			got, err := underTest.Authenticate(context.Background(), req)
			if tt.replay {
				// First call must succeed, second must be rejected.
				if err != nil {
					t.Fatalf("first Authenticate() call unexpectedly failed: %v", err)
				}
				got, err = underTest.Authenticate(context.Background(), req)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("clientAttestationAuthentication.Authenticate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if got == nil || got.Error == nil {
					t.Fatalf("clientAttestationAuthentication.Authenticate() = %v, want error assigned", got)
				}
				if tt.wantErrorCode != "" && got.Error.Error != tt.wantErrorCode {
					t.Errorf("error code = %q, want %q", got.Error.Error, tt.wantErrorCode)
				}
				if tt.wantErrorCode == "" {
					// Default expectation: syntax/missing-field failures are
					// invalid_request.
					if got.Error.Error != "invalid_request" && got.Error.Error != "invalid_client_attestation" {
						t.Errorf("unexpected error code %q", got.Error.Error)
					}
				}
			} else if got.Client == nil {
				t.Errorf("clientAttestationAuthentication.Authenticate() = %v, want client assigned", got)
			}
		})
	}
}

// attesterJWKSFor serializes the fixture attester public key as a JWKS.
func attesterJWKSFor(t *testing.T, f *attestationFixture) []byte {
	t.Helper()
	attesterPub, err := jwxjwk.PublicKeyOf(f.attesterKey)
	if err != nil {
		t.Fatalf("unable to derive attester public key: %v", err)
	}
	pubJSON, err := json.Marshal(attesterPub)
	if err != nil {
		t.Fatalf("unable to serialize attester public key: %v", err)
	}
	return []byte(`{"keys": [` + string(pubJSON) + `]}`)
}

// silence unused-constant linters for shared fixtures.
var _ = rfcerrors.InvalidClientAttestation

// attestationExpiry computes the attestation exp claim, supporting negative
// lifetimes (expiry in the past) without uint64 wraparound.
func attestationExpiry(now uint64, lifetime time.Duration) uint64 {
	if lifetime >= 0 {
		return now + uint64(lifetime.Seconds())
	}
	return now - uint64(-lifetime.Seconds())
}
