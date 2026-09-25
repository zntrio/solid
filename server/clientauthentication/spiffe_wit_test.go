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
	"zntr.io/solid/sdk/spiffe"
	spiffemock "zntr.io/solid/sdk/spiffe/mock"
	"zntr.io/solid/server/storage/inmemory"
	storagemock "zntr.io/solid/server/storage/mock"
)

const (
	spiffeWITIssuer  = "spiffe://example.org/my-spiffe-workload-api"
	spiffeWITSubject = "spiffe://example.org/wit-workload"
)

// witFixture holds the keys used to build a WIT-SVID + PoP pair.
type witFixture struct {
	// signingKey signs the WIT-SVID (trust domain wit-svid key).
	signingKey jwxjwk.Key
	// clientKey is bound in cnf and signs the PoP.
	clientKey jwxjwk.Key
}

func newWITFixture() *witFixture {
	return &witFixture{
		signingKey: mustImportTestKey(),
		clientKey:  mustImportTestKey(),
	}
}

func mustImportTestKey() jwxjwk.Key {
	k, err := jwxjwk.Import(generateTestECDSAKey())
	if err != nil {
		panic(err)
	}
	return k
}

// buildWITAndPoP builds a WIT-SVID and its Client Attestation PoP JWT.
// popKey overrides the PoP signer (to simulate a different key).
func (f *witFixture) buildWITAndPoP(t *testing.T, audience, jti string, lifetime time.Duration, popKey jwxjwk.Key, typ string) (string, string) {
	t.Helper()

	var witRaw any
	if err := jwxjwk.Export(f.signingKey, &witRaw); err != nil {
		t.Fatalf("unable to materialize wit signing key: %v", err)
	}
	clientPub, err := jwxjwk.PublicKeyOf(f.clientKey)
	if err != nil {
		t.Fatalf("unable to derive client public key: %v", err)
	}
	pubJSON, err := json.Marshal(clientPub)
	if err != nil {
		t.Fatalf("unable to serialize client public key: %v", err)
	}

	now := uint64(time.Now().Unix())

	witTok := gojwt.NewWithClaims(gojwt.SigningMethodES256, gojwt.MapClaims{
		"iss": spiffeWITIssuer,
		"sub": spiffeWITSubject,
		"exp": now + uint64(lifetime.Seconds()),
		"iat": now,
		"cnf": map[string]any{
			"jwk": json.RawMessage(pubJSON),
		},
	})
	witTok.Header["typ"] = typ
	wit, err := witTok.SignedString(witRaw)
	if err != nil {
		t.Fatalf("unable to sign wit-svid: %v", err)
	}

	var popRaw any
	if err := jwxjwk.Export(popKey, &popRaw); err != nil {
		t.Fatalf("unable to materialize pop key: %v", err)
	}
	popTok := gojwt.NewWithClaims(gojwt.SigningMethodES256, gojwt.MapClaims{
		"iss": spiffeWITSubject,
		"aud": audience,
		"exp": now + uint64(lifetime.Seconds()),
		"iat": now,
		"jti": jti,
	})
	popTok.Header["typ"] = "oauth-client-attestation-pop+jwt"
	pop, err := popTok.SignedString(popRaw)
	if err != nil {
		t.Fatalf("unable to sign pop: %v", err)
	}

	return wit, pop
}

func Test_spiffeWITAuthentication_Authenticate(t *testing.T) {
	tests := []struct {
		name    string
		build   func(t *testing.T, f *witFixture) (wit, pop string)
		prepare func(clients *storagemock.MockClientReader, bundles *spiffemock.MockBundleSource, f *witFixture)
		wantErr bool
		// replay means: the first call must succeed and the second must fail.
		replay bool
	}{
		{
			name: "valid",
			build: func(t *testing.T, f *witFixture) (string, string) {
				return f.buildWITAndPoP(t, expectedSpiffeAudience, "wit-pop-ok", 5*time.Minute, f.clientKey, "wit+jwt")
			},
			prepare: func(clients *storagemock.MockClientReader, bundles *spiffemock.MockBundleSource, f *witFixture) {
				bundles.EXPECT().Get(gomock.Any(), "example.org").Return(spiffeBundleSet(t, f.signingKey, spiffe.KeyUseWITSVID), nil)
				clients.EXPECT().Get(gomock.Any(), spiffeWITSubject).Return(&clientv1.Client{
					ClientId:                spiffeWITSubject,
					SpiffeId:                spiffeWITSubject,
					TokenEndpointAuthMethod: oidc.AuthMethodSPIFFEWIT,
				}, nil)
			},
		},
		{
			name: "missing typ header",
			build: func(t *testing.T, f *witFixture) (string, string) {
				return f.buildWITAndPoP(t, expectedSpiffeAudience, "wit-pop-notyp", 5*time.Minute, f.clientKey, "JWT")
			},
			prepare: func(_ *storagemock.MockClientReader, _ *spiffemock.MockBundleSource, _ *witFixture) {},
			wantErr: true,
		},
		{
			name: "wrong audience",
			build: func(t *testing.T, f *witFixture) (string, string) {
				return f.buildWITAndPoP(t, "https://evil.example", "wit-pop-aud", 5*time.Minute, f.clientKey, "wit+jwt")
			},
			prepare: func(_ *storagemock.MockClientReader, bundles *spiffemock.MockBundleSource, f *witFixture) {
				bundles.EXPECT().Get(gomock.Any(), "example.org").Return(spiffeBundleSet(t, f.signingKey, spiffe.KeyUseWITSVID), nil)
			},
			wantErr: true,
		},
		{
			name: "pop signed by different key",
			build: func(t *testing.T, f *witFixture) (string, string) {
				return f.buildWITAndPoP(t, expectedSpiffeAudience, "wit-pop-foreignkey", 5*time.Minute, mustImportTestKey(), "wit+jwt")
			},
			prepare: func(_ *storagemock.MockClientReader, bundles *spiffemock.MockBundleSource, f *witFixture) {
				bundles.EXPECT().Get(gomock.Any(), "example.org").Return(spiffeBundleSet(t, f.signingKey, spiffe.KeyUseWITSVID), nil)
			},
			wantErr: true,
		},
		{
			name: "unknown trust domain",
			build: func(t *testing.T, f *witFixture) (string, string) {
				return f.buildWITAndPoP(t, expectedSpiffeAudience, "wit-pop-unk", 5*time.Minute, f.clientKey, "wit+jwt")
			},
			prepare: func(_ *storagemock.MockClientReader, bundles *spiffemock.MockBundleSource, _ *witFixture) {
				bundles.EXPECT().Get(gomock.Any(), "example.org").Return(nil, errNoBundle)
			},
			wantErr: true,
		},
		{
			name: "spiffe_id mismatch",
			build: func(t *testing.T, f *witFixture) (string, string) {
				return f.buildWITAndPoP(t, expectedSpiffeAudience, "wit-pop-mismatch", 5*time.Minute, f.clientKey, "wit+jwt")
			},
			prepare: func(clients *storagemock.MockClientReader, bundles *spiffemock.MockBundleSource, f *witFixture) {
				bundles.EXPECT().Get(gomock.Any(), "example.org").Return(spiffeBundleSet(t, f.signingKey, spiffe.KeyUseWITSVID), nil)
				clients.EXPECT().Get(gomock.Any(), spiffeWITSubject).Return(&clientv1.Client{
					ClientId: spiffeWITSubject,
					SpiffeId: "spiffe://example.org/other-workload",
				}, nil)
			},
			wantErr: true,
		},
		{
			name: "client not registered for spiffe_wit",
			build: func(t *testing.T, f *witFixture) (string, string) {
				return f.buildWITAndPoP(t, expectedSpiffeAudience, "wit-pop-notreg", 5*time.Minute, f.clientKey, "wit+jwt")
			},
			prepare: func(clients *storagemock.MockClientReader, bundles *spiffemock.MockBundleSource, f *witFixture) {
				bundles.EXPECT().Get(gomock.Any(), "example.org").Return(spiffeBundleSet(t, f.signingKey, spiffe.KeyUseWITSVID), nil)
				clients.EXPECT().Get(gomock.Any(), spiffeWITSubject).Return(&clientv1.Client{
					ClientId:                spiffeWITSubject,
					SpiffeId:                spiffeWITSubject,
					TokenEndpointAuthMethod: oidc.AuthMethodSPIFFEX509,
				}, nil)
			},
			wantErr: true,
		},
		{
			name: "replay rejected",
			build: func(t *testing.T, f *witFixture) (string, string) {
				return f.buildWITAndPoP(t, expectedSpiffeAudience, "wit-pop-replay", 5*time.Minute, f.clientKey, "wit+jwt")
			},
			prepare: func(clients *storagemock.MockClientReader, bundles *spiffemock.MockBundleSource, f *witFixture) {
				bundles.EXPECT().Get(gomock.Any(), "example.org").Return(spiffeBundleSet(t, f.signingKey, spiffe.KeyUseWITSVID), nil).Times(2)
				clients.EXPECT().Get(gomock.Any(), spiffeWITSubject).Return(&clientv1.Client{
					ClientId:                spiffeWITSubject,
					SpiffeId:                spiffeWITSubject,
					TokenEndpointAuthMethod: oidc.AuthMethodSPIFFEWIT,
				}, nil).Times(2)
			},
			wantErr: true,
			replay:  true,
		},
		{
			name: "missing wit",
			build: func(_ *testing.T, _ *witFixture) (string, string) {
				return "", ""
			},
			prepare: func(_ *storagemock.MockClientReader, _ *spiffemock.MockBundleSource, _ *witFixture) {},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			clients := storagemock.NewMockClientReader(ctrl)
			bundles := spiffemock.NewMockBundleSource(ctrl)
			proofs := inmemory.DPoPProofs()
			fixture := newWITFixture()

			if tt.prepare != nil {
				tt.prepare(clients, bundles, fixture)
			}

			wit, pop := tt.build(t, fixture)
			underTest := SPIFFEWIT(clients, bundles, proofs, expectedSpiffeAudience, []string{"ES256"})

			req := &clientv1.AuthenticateRequest{
				ClientAttestation:    new(wit),
				ClientAttestationPop: new(pop),
			}
			got, err := underTest.Authenticate(context.Background(), req)
			if tt.replay {
				if err != nil {
					t.Fatalf("first Authenticate() call unexpectedly failed: %v", err)
				}
				got, err = underTest.Authenticate(context.Background(), req)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("Authenticate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got.Client == nil {
				t.Errorf("Authenticate() = %v, want client assigned", got)
			}
			if tt.wantErr && got != nil && got.Error == nil {
				t.Errorf("Authenticate() = %v, want protocol error assigned", got)
			}
		})
	}
}
