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
	"fmt"
	"reflect"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"go.uber.org/mock/gomock"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/server/storage"
	"zntr.io/solid/server/storage/inmemory"
	storagemock "zntr.io/solid/server/storage/mock"
)

func Test_privateKeyJWTAuthentication_Authenticate(t *testing.T) {
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
		// wantFirst false means the FIRST call must fail (aud/iat/nbf);
		// true means the first call succeeds and the second (replay) fails.
		replay bool
	}{
		{
			name:    "nil request",
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty request",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{},
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty client_assertion_type",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(""),
				},
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid client_assertion_type",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new("foo"),
				},
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "nil client_assertion",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
				},
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty client_assertion",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
					ClientAssertion:     new(""),
				},
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid JWT",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
					ClientAssertion:     new("..YB4gdhWUGRjWEsEbKDs7-"),
				},
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid JWT: invalid json body",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
					ClientAssertion:     new("eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJteUpXVElkMDAxIiwic3ViIjoiMzgxNzQ2MjM3NjIiLCJpc3MiOiIzODE3NCwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAwL2FwaS9hdXRoL3Rva2VuL2RpcmVjdC8yNDUyMzEzODIwNSIsImV4cCI6MTUzNjEzMjcwOCwiaWF0IjoxNTM2MTMyNzA4fQ.7Q53dOARBi-GE45VmA0QjO96BEQanSRYuvi6pS4RVr0"),
				},
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid JWT: jti empty",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
					ClientAssertion: new(generateAssertion(t, &privateJWTClaims{
						JTI:      "",
						Subject:  "38174623762",
						Issuer:   "38174623762",
						Audience: audClaim{"http://localhost:8080"},
						Expires:  uint64(time.Now().Add(5 * time.Minute).Unix()),
						IssuedAt: uint64(time.Now().Unix()),
					})),
				},
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid JWT: sub empty",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
					ClientAssertion: new(generateAssertion(t, &privateJWTClaims{
						JTI:      "123456789",
						Subject:  "",
						Issuer:   "38174623762",
						Audience: audClaim{"http://localhost:8080"},
						Expires:  uint64(time.Now().Add(5 * time.Minute).Unix()),
						IssuedAt: uint64(time.Now().Unix()),
					})),
				},
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid JWT: iss empty",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
					ClientAssertion: new(generateAssertion(t, &privateJWTClaims{
						JTI:      "123456789",
						Subject:  "38174623762",
						Issuer:   "",
						Audience: audClaim{"http://localhost:8080"},
						Expires:  uint64(time.Now().Add(5 * time.Minute).Unix()),
						IssuedAt: uint64(time.Now().Unix()),
					})),
				},
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid JWT: aud empty",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
					ClientAssertion: new(generateAssertion(t, &privateJWTClaims{
						JTI:      "123456789",
						Subject:  "38174623762",
						Issuer:   "38174623762",
						Audience: nil,
						Expires:  uint64(time.Now().Add(5 * time.Minute).Unix()),
						IssuedAt: uint64(time.Now().Unix()),
					})),
				},
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid JWT: exp equal 0",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
					ClientAssertion: new(generateAssertion(t, &privateJWTClaims{
						JTI:      "123456789",
						Subject:  "38174623762",
						Issuer:   "38174623762",
						Audience: audClaim{"http://localhost:8080"},
						Expires:  0,
						IssuedAt: uint64(time.Now().Unix()),
					})),
				},
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid JWT: iss and sub mismatch",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
					ClientAssertion: new(generateAssertion(t, &privateJWTClaims{
						JTI:      "123456789",
						Subject:  "38174623762",
						Issuer:   "45678941561",
						Audience: audClaim{"http://localhost:8080"},
						Expires:  uint64(time.Now().Add(5 * time.Minute).Unix()),
						IssuedAt: uint64(time.Now().Unix()),
					})),
				},
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid JWT: aud mismatch",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
					ClientAssertion: new(generateAssertion(t, &privateJWTClaims{
						JTI:      "123456789",
						Subject:  "38174623762",
						Issuer:   "38174623762",
						Audience: audClaim{"https://evil.example"},
						Expires:  uint64(time.Now().Add(5 * time.Minute).Unix()),
						IssuedAt: uint64(time.Now().Unix()),
					})),
				},
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid JWT: iat in the future",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
					ClientAssertion: new(generateAssertion(t, &privateJWTClaims{
						JTI:      "123456789",
						Subject:  "38174623762",
						Issuer:   "38174623762",
						Audience: audClaim{"http://localhost:8080"},
						Expires:  uint64(time.Now().Add(5 * time.Minute).Unix()),
						IssuedAt: uint64(time.Now().Add(1 * time.Hour).Unix()),
					})),
				},
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid JWT: exp too far in the future",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
					ClientAssertion: new(generateAssertion(t, &privateJWTClaims{
						JTI:      "123456789",
						Subject:  "38174623762",
						Issuer:   "38174623762",
						Audience: audClaim{"http://localhost:8080"},
						Expires:  uint64(time.Now().Add(2 * time.Hour).Unix()),
						IssuedAt: uint64(time.Now().Unix()),
					})),
				},
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid JWT: nbf in the future",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
					ClientAssertion: new(generateAssertion(t, &privateJWTClaims{
						JTI:       "123456789",
						Subject:   "38174623762",
						Issuer:    "38174623762",
						Audience:  audClaim{"http://localhost:8080"},
						Expires:   uint64(time.Now().Add(5 * time.Minute).Unix()),
						IssuedAt:  uint64(time.Now().Unix()),
						NotBefore: uint64(time.Now().Add(1 * time.Hour).Unix()),
					})),
				},
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid JWT: assertion replay",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
					ClientAssertion: new(generateAssertion(t, &privateJWTClaims{
						JTI:      "123456789",
						Subject:  "38174623762",
						Issuer:   "38174623762",
						Audience: audClaim{"http://localhost:8080"},
						Expires:  uint64(time.Now().Add(5 * time.Minute).Unix()),
						IssuedAt: uint64(time.Now().Unix()),
					})),
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "38174623762").Return(&clientv1.Client{
					Jwks:                    clientJWKSWithSIG,
					TokenEndpointAuthMethod: oidc.AuthMethodPrivateKeyJWT,
				}, nil).Times(2)
			},
			replay:  true,
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid JWT: expired assertion",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
					ClientAssertion:     new("eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJteUpXVElkMDAxIiwic3ViIjoiMzgxNzQ2MjM3NjIiLCJpc3MiOiIzODE3NDYyMzc2MiIsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMC9hcGkvYXV0aC90b2tlbi9kaXJlY3QvMjQ1MjMxMzgyMDUiLCJleHAiOjE1MzYxMzI3MDgsImlhdCI6MTUzNjEzMjcwOH0.7Q53dOARBi-GE45VmA0QjO96BEQanSRYuvi6pS4RVr0"),
				},
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "client not found",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
					ClientAssertion: new(generateAssertion(t, &privateJWTClaims{
						JTI:      "123456789",
						Subject:  "38174623762",
						Issuer:   "38174623762",
						Audience: audClaim{"http://localhost:8080"},
						Expires:  uint64(time.Now().Add(5 * time.Minute).Unix()),
						IssuedAt: uint64(time.Now().Unix()),
					})),
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "38174623762").Return(nil, storage.ErrNotFound)
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidClient().Build(),
			},
		},
		{
			name: "client storage error",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
					ClientAssertion: new(generateAssertion(t, &privateJWTClaims{
						JTI:      "123456789",
						Subject:  "38174623762",
						Issuer:   "38174623762",
						Audience: audClaim{"http://localhost:8080"},
						Expires:  uint64(time.Now().Add(5 * time.Minute).Unix()),
						IssuedAt: uint64(time.Now().Unix()),
					})),
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "38174623762").Return(nil, fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "retrieve client have nil jwks",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
					ClientAssertion: new(generateAssertion(t, &privateJWTClaims{
						JTI:      "123456789",
						Subject:  "38174623762",
						Issuer:   "38174623762",
						Audience: audClaim{"http://localhost:8080"},
						Expires:  uint64(time.Now().Add(5 * time.Minute).Unix()),
						IssuedAt: uint64(time.Now().Unix()),
					})),
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "38174623762").Return(&clientv1.Client{
					Jwks: nil,
				}, nil)
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidClient().Build(),
			},
		},
		{
			name: "retrieve client have empty jwks",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
					ClientAssertion: new(generateAssertion(t, &privateJWTClaims{
						JTI:      "123456789",
						Subject:  "38174623762",
						Issuer:   "38174623762",
						Audience: audClaim{"http://localhost:8080"},
						Expires:  uint64(time.Now().Add(5 * time.Minute).Unix()),
						IssuedAt: uint64(time.Now().Unix()),
					})),
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "38174623762").Return(&clientv1.Client{
					Jwks: []byte{},
				}, nil)
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidClient().Build(),
			},
		},
		{
			name: "retrieve client have invalid jwks json",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
					ClientAssertion: new(generateAssertion(t, &privateJWTClaims{
						JTI:      "123456789",
						Subject:  "38174623762",
						Issuer:   "38174623762",
						Audience: audClaim{"http://localhost:8080"},
						Expires:  uint64(time.Now().Add(5 * time.Minute).Unix()),
						IssuedAt: uint64(time.Now().Unix()),
					})),
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "38174623762").Return(&clientv1.Client{
					Jwks: []byte(`{"fo:"bar"}`),
				}, nil)
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidClient().Build(),
			},
		},
		{
			name: "retrieve client have invalid jwks",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
					ClientAssertion: new(generateAssertion(t, &privateJWTClaims{
						JTI:      "123456789",
						Subject:  "38174623762",
						Issuer:   "38174623762",
						Audience: audClaim{"http://localhost:8080"},
						Expires:  uint64(time.Now().Add(5 * time.Minute).Unix()),
						IssuedAt: uint64(time.Now().Unix()),
					})),
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "38174623762").Return(&clientv1.Client{
					Jwks: []byte(`{"foo":"bar"}`),
				}, nil)
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidClient().Build(),
			},
		},
		{
			name: "retrieve client have valid jwks but no sig key",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
					ClientAssertion: new(generateAssertion(t, &privateJWTClaims{
						JTI:      "123456789",
						Subject:  "38174623762",
						Issuer:   "38174623762",
						Audience: audClaim{"http://localhost:8080"},
						Expires:  uint64(time.Now().Add(5 * time.Minute).Unix()),
						IssuedAt: uint64(time.Now().Unix()),
					})),
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "38174623762").Return(&clientv1.Client{
					Jwks: clientJWKSWithENC,
				}, nil)
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidClient().Build(),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "valid",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
					ClientAssertion: new(generateAssertion(t, &privateJWTClaims{
						JTI:      "123456789",
						Subject:  "38174623762",
						Issuer:   "38174623762",
						Audience: audClaim{"http://localhost:8080"},
						Expires:  uint64(time.Now().Add(5 * time.Minute).Unix()),
						IssuedAt: uint64(time.Now().Unix()),
					})),
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "38174623762").Return(&clientv1.Client{
					Jwks:                    clientJWKSWithSIG,
					TokenEndpointAuthMethod: oidc.AuthMethodPrivateKeyJWT,
				}, nil)
			},
			wantErr: false,
			want: &clientv1.AuthenticateResponse{
				Client: &clientv1.Client{
					Jwks:                    clientJWKSWithSIG,
					TokenEndpointAuthMethod: oidc.AuthMethodPrivateKeyJWT,
				},
			},
		},
		{
			name: "valid: aud equals receiving endpoint",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
					Endpoint:            new("http://localhost:8080/token"),
					ClientAssertion: new(generateAssertion(t, &privateJWTClaims{
						JTI:      "123456789",
						Subject:  "38174623762",
						Issuer:   "38174623762",
						Audience: audClaim{"http://localhost:8080/token"},
						Expires:  uint64(time.Now().Add(5 * time.Minute).Unix()),
						IssuedAt: uint64(time.Now().Unix()),
					})),
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "38174623762").Return(&clientv1.Client{
					Jwks:                    clientJWKSWithSIG,
					TokenEndpointAuthMethod: oidc.AuthMethodPrivateKeyJWT,
				}, nil)
			},
			wantErr: false,
			want: &clientv1.AuthenticateResponse{
				Client: &clientv1.Client{
					Jwks:                    clientJWKSWithSIG,
					TokenEndpointAuthMethod: oidc.AuthMethodPrivateKeyJWT,
				},
			},
		},
		{
			name: "invalid JWT: aud is a different endpoint than the receiving one (cross-endpoint replay)",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
					Endpoint:            new("http://localhost:8080/token"),
					ClientAssertion: new(generateAssertion(t, &privateJWTClaims{
						JTI:      "123456789",
						Subject:  "38174623762",
						Issuer:   "38174623762",
						Audience: audClaim{"http://localhost:8080/par"},
						Expires:  uint64(time.Now().Add(5 * time.Minute).Unix()),
						IssuedAt: uint64(time.Now().Unix()),
					})),
				},
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid JWT: aud array with injected audience (draft security-topics-update-03 section 2.1.2)",
			args: args{
				ctx: context.Background(),
				req: &clientv1.AuthenticateRequest{
					ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
					Endpoint:            new("http://localhost:8080/token"),
					ClientAssertion: new(generateAssertion(t, &privateJWTClaims{
						JTI:      "123456789",
						Subject:  "38174623762",
						Issuer:   "38174623762",
						Audience: audClaim{"http://localhost:8080", "https://attacker.example"},
						Expires:  uint64(time.Now().Add(5 * time.Minute).Unix()),
						IssuedAt: uint64(time.Now().Unix()),
					})),
				},
			},
			wantErr: true,
			want: &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
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
			underTest := PrivateKeyJWT(clients, proofs, "http://localhost:8080", []string{"ES256"})

			got, err := underTest.Authenticate(tt.args.ctx, tt.args.req)
			if tt.replay {
				// First call must succeed, second must be rejected.
				if err != nil {
					t.Fatalf("first Authenticate() call unexpectedly failed: %v", err)
				}
				got, err = underTest.Authenticate(tt.args.ctx, tt.args.req)
			}
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
	// Decode JWK
	privateKey, err := jwxjwk.ParseKey(clientPrivateKey)
	if err != nil {
		t.Fatalf("unable to decode client private key: %v", err)
		return ""
	}

	// Materialize the signing key
	var rawKey any
	if err := jwxjwk.Export(privateKey, &rawKey); err != nil {
		t.Fatalf("unable to materialize client private key: %v", err)
		return ""
	}

	// Sign the assertion
	claimsMap := gojwt.MapClaims{
		"jti": claims.JTI,
		"sub": claims.Subject,
		"iss": claims.Issuer,
		"aud": claims.Audience,
		"exp": claims.Expires,
		"iat": claims.IssuedAt,
	}
	if claims.NotBefore > 0 {
		claimsMap["nbf"] = claims.NotBefore
	}
	tok := gojwt.NewWithClaims(gojwt.SigningMethodES256, claimsMap)
	raw, err := tok.SignedString(rawKey)
	if err != nil {
		t.Fatalf("unable to generate final assertion")
	}

	// Assertion
	return raw
}
