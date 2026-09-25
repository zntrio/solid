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
	corev1 "zntr.io/solid/api/oidc/core/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/server/storage/inmemory"
	storagemock "zntr.io/solid/server/storage/mock"
)

const expectedAttestationAudience = "http://localhost:8080/token"

func Test_clientAttestationAuthentication_Authenticate(t *testing.T) {
	type args struct {
		ctx context.Context
		req *clientv1.AuthenticateRequest
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*storagemock.MockClientReader)
		want    *clientv1.AuthenticateResponse
		wantErr bool
		// replay means: the first call must succeed and the second must fail.
		replay bool
	}{
		{
			name: "PoP aud mismatch",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTClientAttestation),
					ClientAssertion:     new(buildClientAttestationAssertion(t, "https://evil.example", "38174623762", "1234567890")),
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "38174623762").Return(&clientv1.Client{
					Jwks: clientJWKSWithSIG,
				}, nil)
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: unauthorizedClientError(),
			},
		},
		{
			name: "attestation sub does not match PoP iss",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTClientAttestation),
					ClientAssertion:     new(buildClientAttestationAssertion(t, "http://localhost:8080/token", "other-client-id", "1234567890")),
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "other-client-id").Return(&clientv1.Client{
					Jwks: clientJWKSWithSIG,
				}, nil)
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: unauthorizedClientError(),
			},
		},
		{
			name: "PoP jti replay",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTClientAttestation),
					ClientAssertion:     new(buildClientAttestationAssertion(t, "http://localhost:8080/token", "38174623762", "1234567890")),
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "38174623762").Return(&clientv1.Client{
					Jwks: clientJWKSWithSIG,
				}, nil).Times(4)
			},
			replay:  true,
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: unauthorizedClientError(),
			},
		},
		{
			name: "valid",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTClientAttestation),
					ClientAssertion:     new(buildClientAttestationAssertion(t, "http://localhost:8080/token", "38174623762", "1234567891")),
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "38174623762").Return(&clientv1.Client{
					Jwks: clientJWKSWithSIG,
				}, nil).Times(2)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Arm mocks
			clients := storagemock.NewMockClientReader(ctrl)
			proofs := inmemory.DPoPProofs()

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(clients)
			}

			// Prepare service
			underTest := ClientAttestation(clients, proofs, expectedAttestationAudience, []string{"ES256"})

			got, err := underTest.Authenticate(tt.args.ctx, tt.args.req)
			if tt.replay {
				// First call must succeed, second must be rejected.
				if err != nil {
					t.Fatalf("first Authenticate() call unexpectedly failed: %v", err)
				}
				got, err = underTest.Authenticate(tt.args.ctx, tt.args.req)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("clientAttestationAuthentication.Authenticate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want != nil && tt.want.Error != nil {
				if got == nil || got.Error == nil {
					t.Errorf("clientAttestationAuthentication.Authenticate() = %v, want error %v", got, tt.want.Error)
				}
			}
			if !tt.wantErr && got.Client == nil {
				t.Errorf("clientAttestationAuthentication.Authenticate() = %v, want client assigned", got)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Helpers

func unauthorizedClientError() *corev1.Error {
	return rfcerrors.UnauthorizedClient().Build()
}

func buildClientAttestationAssertion(t *testing.T, popAudience, attestationSubject, jti string) string {
	t.Helper()

	// Decode the shared test signing key.
	privateKey, err := jwxjwk.ParseKey(clientPrivateKey)
	if err != nil {
		t.Fatalf("unable to decode client private key: %v", err)
	}

	// Materialize the signing key.
	var rawKey any
	if err := jwxjwk.Export(privateKey, &rawKey); err != nil {
		t.Fatalf("unable to materialize client private key: %v", err)
	}

	// Extract matching public key for the attestation cnf claim.
	publicKey, err := jwxjwk.PublicKeyOf(privateKey)
	if err != nil {
		t.Fatalf("unable to derive client public key: %v", err)
	}
	pubJSON, err := json.Marshal(publicKey)
	if err != nil {
		t.Fatalf("unable to serialize client public key: %v", err)
	}

	now := uint64(time.Now().Unix())

	// Build the attestation JWT.
	attestationTok := gojwt.NewWithClaims(gojwt.SigningMethodES256, gojwt.MapClaims{
		"iss": attestationSubject,
		"sub": attestationSubject,
		"exp": now + 300,
		"nbf": now,
		"iat": now,
		"jti": "attestation-jti",
		"cnf": map[string]any{
			"jwk": json.RawMessage(pubJSON),
		},
	})
	attestationTok.Header["typ"] = "JWT"
	attestation, err := attestationTok.SignedString(rawKey)
	if err != nil {
		t.Fatalf("unable to generate attestation: %v", err)
	}

	// Build the PoP JWT, signed by the attested key.
	popTok := gojwt.NewWithClaims(gojwt.SigningMethodES256, gojwt.MapClaims{
		"iss": "38174623762",
		"aud": popAudience,
		"exp": now + 300,
		"nbf": now,
		"iat": now,
		"jti": jti,
	})
	popTok.Header["typ"] = "JWT"
	pop, err := popTok.SignedString(rawKey)
	if err != nil {
		t.Fatalf("unable to generate PoP: %v", err)
	}

	// Combine.
	return attestation + "~" + pop
}
