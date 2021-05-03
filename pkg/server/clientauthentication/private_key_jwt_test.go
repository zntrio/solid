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
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/ptypes/wrappers"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/api/oidc"
	"zntr.io/solid/pkg/sdk/rfcerrors"
	"zntr.io/solid/pkg/server/storage"
	storagemock "zntr.io/solid/pkg/server/storage/mock"
)

func Test_privateKeyJWTAuthentication_Authenticate(t *testing.T) {
	type args struct {
		ctx context.Context
		req *corev1.ClientAuthenticationRequest
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*storagemock.MockClientReader)
		want    *corev1.ClientAuthenticationResponse
		wantErr bool
	}{
		{
			name:    "nil request",
			wantErr: true,
			want: &corev1.ClientAuthenticationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty request",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientAuthenticationRequest{},
			},
			wantErr: true,
			want: &corev1.ClientAuthenticationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty client_assertion_type",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientAuthenticationRequest{
					ClientAssertionType: &wrappers.StringValue{
						Value: "",
					},
				},
			},
			wantErr: true,
			want: &corev1.ClientAuthenticationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid client_assertion_type",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientAuthenticationRequest{
					ClientAssertionType: &wrappers.StringValue{
						Value: "foo",
					},
				},
			},
			wantErr: true,
			want: &corev1.ClientAuthenticationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "nil client_assertion",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientAuthenticationRequest{
					ClientAssertionType: &wrappers.StringValue{
						Value: oidc.AssertionTypeJWTBearer,
					},
				},
			},
			wantErr: true,
			want: &corev1.ClientAuthenticationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty client_assertion",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientAuthenticationRequest{
					ClientAssertionType: &wrappers.StringValue{
						Value: oidc.AssertionTypeJWTBearer,
					},
					ClientAssertion: &wrappers.StringValue{
						Value: "",
					},
				},
			},
			wantErr: true,
			want: &corev1.ClientAuthenticationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid JWT",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientAuthenticationRequest{
					ClientAssertionType: &wrappers.StringValue{
						Value: oidc.AssertionTypeJWTBearer,
					},
					ClientAssertion: &wrappers.StringValue{
						Value: "..YB4gdhWUGRjWEsEbKDs7-",
					},
				},
			},
			wantErr: true,
			want: &corev1.ClientAuthenticationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid JWT: invalid json body",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientAuthenticationRequest{
					ClientAssertionType: &wrappers.StringValue{
						Value: oidc.AssertionTypeJWTBearer,
					},
					ClientAssertion: &wrappers.StringValue{
						Value: "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJteUpXVElkMDAxIiwic3ViIjoiMzgxNzQ2MjM3NjIiLCJpc3MiOiIzODE3NCwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAwL2FwaS9hdXRoL3Rva2VuL2RpcmVjdC8yNDUyMzEzODIwNSIsImV4cCI6MTUzNjEzMjcwOCwiaWF0IjoxNTM2MTMyNzA4fQ.7Q53dOARBi-GE45VmA0QjO96BEQanSRYuvi6pS4RVr0",
					},
				},
			},
			wantErr: true,
			want: &corev1.ClientAuthenticationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid JWT: jti empty",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientAuthenticationRequest{
					ClientAssertionType: &wrappers.StringValue{
						Value: oidc.AssertionTypeJWTBearer,
					},
					ClientAssertion: &wrappers.StringValue{
						Value: generateAssertion(t, &privateJWTClaims{
							JTI:      "",
							Subject:  "38174623762",
							Issuer:   "38174623762",
							Audience: "http://localhost:8080/token",
							Expires:  uint64(time.Now().Add(2 * time.Hour).Unix()),
							IssuedAt: uint64(time.Now().Unix()),
						}),
					},
				},
			},
			wantErr: true,
			want: &corev1.ClientAuthenticationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid JWT: sub empty",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientAuthenticationRequest{
					ClientAssertionType: &wrappers.StringValue{
						Value: oidc.AssertionTypeJWTBearer,
					},
					ClientAssertion: &wrappers.StringValue{
						Value: generateAssertion(t, &privateJWTClaims{
							JTI:      "123456789",
							Subject:  "",
							Issuer:   "38174623762",
							Audience: "http://localhost:8080/token",
							Expires:  uint64(time.Now().Add(2 * time.Hour).Unix()),
							IssuedAt: uint64(time.Now().Unix()),
						}),
					},
				},
			},
			wantErr: true,
			want: &corev1.ClientAuthenticationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid JWT: iss empty",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientAuthenticationRequest{
					ClientAssertionType: &wrappers.StringValue{
						Value: oidc.AssertionTypeJWTBearer,
					},
					ClientAssertion: &wrappers.StringValue{
						Value: generateAssertion(t, &privateJWTClaims{
							JTI:      "123456789",
							Subject:  "38174623762",
							Issuer:   "",
							Audience: "http://localhost:8080/token",
							Expires:  uint64(time.Now().Add(2 * time.Hour).Unix()),
							IssuedAt: uint64(time.Now().Unix()),
						}),
					},
				},
			},
			wantErr: true,
			want: &corev1.ClientAuthenticationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid JWT: aud empty",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientAuthenticationRequest{
					ClientAssertionType: &wrappers.StringValue{
						Value: oidc.AssertionTypeJWTBearer,
					},
					ClientAssertion: &wrappers.StringValue{
						Value: generateAssertion(t, &privateJWTClaims{
							JTI:      "123456789",
							Subject:  "38174623762",
							Issuer:   "38174623762",
							Audience: "",
							Expires:  uint64(time.Now().Add(2 * time.Hour).Unix()),
							IssuedAt: uint64(time.Now().Unix()),
						}),
					},
				},
			},
			wantErr: true,
			want: &corev1.ClientAuthenticationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid JWT: exp equal 0",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientAuthenticationRequest{
					ClientAssertionType: &wrappers.StringValue{
						Value: oidc.AssertionTypeJWTBearer,
					},
					ClientAssertion: &wrappers.StringValue{
						Value: generateAssertion(t, &privateJWTClaims{
							JTI:      "123456789",
							Subject:  "38174623762",
							Issuer:   "38174623762",
							Audience: "http://localhost:8080/token",
							Expires:  0,
							IssuedAt: uint64(time.Now().Unix()),
						}),
					},
				},
			},
			wantErr: true,
			want: &corev1.ClientAuthenticationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid JWT: iss and sub mismatch",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientAuthenticationRequest{
					ClientAssertionType: &wrappers.StringValue{
						Value: oidc.AssertionTypeJWTBearer,
					},
					ClientAssertion: &wrappers.StringValue{
						Value: generateAssertion(t, &privateJWTClaims{
							JTI:      "123456789",
							Subject:  "38174623762",
							Issuer:   "45678941561",
							Audience: "http://localhost:8080/token",
							Expires:  uint64(time.Now().Add(2 * time.Hour).Unix()),
							IssuedAt: uint64(time.Now().Unix()),
						}),
					},
				},
			},
			wantErr: true,
			want: &corev1.ClientAuthenticationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid JWT: expired assertion",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientAuthenticationRequest{
					ClientAssertionType: &wrappers.StringValue{
						Value: oidc.AssertionTypeJWTBearer,
					},
					ClientAssertion: &wrappers.StringValue{
						Value: "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJteUpXVElkMDAxIiwic3ViIjoiMzgxNzQ2MjM3NjIiLCJpc3MiOiIzODE3NDYyMzc2MiIsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMC9hcGkvYXV0aC90b2tlbi9kaXJlY3QvMjQ1MjMxMzgyMDUiLCJleHAiOjE1MzYxMzI3MDgsImlhdCI6MTUzNjEzMjcwOH0.7Q53dOARBi-GE45VmA0QjO96BEQanSRYuvi6pS4RVr0",
					},
				},
			},
			wantErr: true,
			want: &corev1.ClientAuthenticationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "client not found",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientAuthenticationRequest{
					ClientAssertionType: &wrappers.StringValue{
						Value: oidc.AssertionTypeJWTBearer,
					},
					ClientAssertion: &wrappers.StringValue{
						Value: generateAssertion(t, &privateJWTClaims{
							JTI:      "123456789",
							Subject:  "38174623762",
							Issuer:   "38174623762",
							Audience: "http://localhost:8080/token",
							Expires:  uint64(time.Now().Add(2 * time.Hour).Unix()),
							IssuedAt: uint64(time.Now().Unix()),
						}),
					},
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "38174623762").Return(nil, storage.ErrNotFound)
			},
			wantErr: true,
			want: &corev1.ClientAuthenticationResponse{
				Error: rfcerrors.InvalidClient().Build(),
			},
		},
		{
			name: "client storage error",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientAuthenticationRequest{
					ClientAssertionType: &wrappers.StringValue{
						Value: oidc.AssertionTypeJWTBearer,
					},
					ClientAssertion: &wrappers.StringValue{
						Value: generateAssertion(t, &privateJWTClaims{
							JTI:      "123456789",
							Subject:  "38174623762",
							Issuer:   "38174623762",
							Audience: "http://localhost:8080/token",
							Expires:  uint64(time.Now().Add(2 * time.Hour).Unix()),
							IssuedAt: uint64(time.Now().Unix()),
						}),
					},
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "38174623762").Return(nil, fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.ClientAuthenticationResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "retrieve client have nil jwks",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientAuthenticationRequest{
					ClientAssertionType: &wrappers.StringValue{
						Value: oidc.AssertionTypeJWTBearer,
					},
					ClientAssertion: &wrappers.StringValue{
						Value: generateAssertion(t, &privateJWTClaims{
							JTI:      "123456789",
							Subject:  "38174623762",
							Issuer:   "38174623762",
							Audience: "http://localhost:8080/token",
							Expires:  uint64(time.Now().Add(2 * time.Hour).Unix()),
							IssuedAt: uint64(time.Now().Unix()),
						}),
					},
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "38174623762").Return(&corev1.Client{
					Jwks: nil,
				}, nil)
			},
			wantErr: true,
			want: &corev1.ClientAuthenticationResponse{
				Error: rfcerrors.InvalidClient().Build(),
			},
		},
		{
			name: "retrieve client have empty jwks",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientAuthenticationRequest{
					ClientAssertionType: &wrappers.StringValue{
						Value: oidc.AssertionTypeJWTBearer,
					},
					ClientAssertion: &wrappers.StringValue{
						Value: generateAssertion(t, &privateJWTClaims{
							JTI:      "123456789",
							Subject:  "38174623762",
							Issuer:   "38174623762",
							Audience: "http://localhost:8080/token",
							Expires:  uint64(time.Now().Add(2 * time.Hour).Unix()),
							IssuedAt: uint64(time.Now().Unix()),
						}),
					},
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "38174623762").Return(&corev1.Client{
					Jwks: []byte{},
				}, nil)
			},
			wantErr: true,
			want: &corev1.ClientAuthenticationResponse{
				Error: rfcerrors.InvalidClient().Build(),
			},
		},
		{
			name: "retrieve client have invalid jwks json",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientAuthenticationRequest{
					ClientAssertionType: &wrappers.StringValue{
						Value: oidc.AssertionTypeJWTBearer,
					},
					ClientAssertion: &wrappers.StringValue{
						Value: generateAssertion(t, &privateJWTClaims{
							JTI:      "123456789",
							Subject:  "38174623762",
							Issuer:   "38174623762",
							Audience: "http://localhost:8080/token",
							Expires:  uint64(time.Now().Add(2 * time.Hour).Unix()),
							IssuedAt: uint64(time.Now().Unix()),
						}),
					},
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "38174623762").Return(&corev1.Client{
					Jwks: []byte(`{"fo:"bar"}`),
				}, nil)
			},
			wantErr: true,
			want: &corev1.ClientAuthenticationResponse{
				Error: rfcerrors.InvalidClient().Build(),
			},
		},
		{
			name: "retrieve client have invalid jwks",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientAuthenticationRequest{
					ClientAssertionType: &wrappers.StringValue{
						Value: oidc.AssertionTypeJWTBearer,
					},
					ClientAssertion: &wrappers.StringValue{
						Value: generateAssertion(t, &privateJWTClaims{
							JTI:      "123456789",
							Subject:  "38174623762",
							Issuer:   "38174623762",
							Audience: "http://localhost:8080/token",
							Expires:  uint64(time.Now().Add(2 * time.Hour).Unix()),
							IssuedAt: uint64(time.Now().Unix()),
						}),
					},
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "38174623762").Return(&corev1.Client{
					Jwks: []byte(`{"foo":"bar"}`),
				}, nil)
			},
			wantErr: true,
			want: &corev1.ClientAuthenticationResponse{
				Error: rfcerrors.InvalidClient().Build(),
			},
		},
		{
			name: "retrieve client have valid jwks but no sig key",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientAuthenticationRequest{
					ClientAssertionType: &wrappers.StringValue{
						Value: oidc.AssertionTypeJWTBearer,
					},
					ClientAssertion: &wrappers.StringValue{
						Value: generateAssertion(t, &privateJWTClaims{
							JTI:      "123456789",
							Subject:  "38174623762",
							Issuer:   "38174623762",
							Audience: "http://localhost:8080/token",
							Expires:  uint64(time.Now().Add(2 * time.Hour).Unix()),
							IssuedAt: uint64(time.Now().Unix()),
						}),
					},
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "38174623762").Return(&corev1.Client{
					Jwks: clientJWKSWithENC,
				}, nil)
			},
			wantErr: true,
			want: &corev1.ClientAuthenticationResponse{
				Error: rfcerrors.InvalidClient().Build(),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "valid",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientAuthenticationRequest{
					ClientAssertionType: &wrappers.StringValue{
						Value: oidc.AssertionTypeJWTBearer,
					},
					ClientAssertion: &wrappers.StringValue{
						Value: generateAssertion(t, &privateJWTClaims{
							JTI:      "123456789",
							Subject:  "38174623762",
							Issuer:   "38174623762",
							Audience: "http://localhost:8080/token",
							Expires:  uint64(time.Now().Add(2 * time.Hour).Unix()),
							IssuedAt: uint64(time.Now().Unix()),
						}),
					},
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "38174623762").Return(&corev1.Client{
					Jwks: clientJWKSWithSIG,
				}, nil)
			},
			wantErr: false,
			want: &corev1.ClientAuthenticationResponse{
				Client: &corev1.Client{
					Jwks: clientJWKSWithSIG,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Arm mocks
			clients := storagemock.NewMockClientReader(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(clients)
			}

			// Prepare service
			underTest := PrivateKeyJWT(clients)

			got, err := underTest.Authenticate(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("privateKeyJWTAuthentication.Authenticate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("privateKeyJWTAuthentication.Authenticate() = %v, want %v", got, tt.want)
			}
		})
	}
}

// -----------------------------------------------------------------------------

var (
	clientPrivateKey  = []byte(`{"kty": "EC","d": "olYJLJ3aiTyP44YXs0R3g1qChRKnYnk7GDxffQhAgL8","use": "sig","crv": "P-256","x": "h6jud8ozOJ93MvHZCxvGZnOVHLeTX-3K9LkAvKy1RSs","y": "yY0UQDLFPM8OAgkOYfotwzXCGXtBYinBk1EURJQ7ONk","alg": "ES256"}`)
	clientJWKSWithSIG = []byte(`{"keys": [{"kty": "EC","use": "sig","crv": "P-256","x": "h6jud8ozOJ93MvHZCxvGZnOVHLeTX-3K9LkAvKy1RSs","y": "yY0UQDLFPM8OAgkOYfotwzXCGXtBYinBk1EURJQ7ONk","alg": "ES256"}]}`)
	clientJWKSWithENC = []byte(`{"keys": [{"kty": "EC","use": "enc","crv": "P-256","x": "h6jud8ozOJ93MvHZCxvGZnOVHLeTX-3K9LkAvKy1RSs","y": "yY0UQDLFPM8OAgkOYfotwzXCGXtBYinBk1EURJQ7ONk","alg": "ES256"}]}`)
)

func generateAssertion(t *testing.T, claims *privateJWTClaims) string {
	var privateKey jose.JSONWebKey
	// Decode JWK
	err := json.Unmarshal(clientPrivateKey, &privateKey)
	if err != nil {
		t.Fatalf("unable to decode client private key: %v", err)
		return ""
	}

	// Prepare a signer
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: privateKey}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatalf("unable to prepare signer: %v", err)
		return ""
	}

	raw, err := jwt.Signed(sig).Claims(claims).CompactSerialize()
	if err != nil {
		t.Fatalf("unable to generate final assertion")
	}

	// Assertion
	return raw
}
