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

package token

import (
	"context"
	"fmt"
	"testing"

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
	registrationv1 "go.zenithar.org/solid/api/gen/go/oidc/registration/v1"
	sessionv1 "go.zenithar.org/solid/api/gen/go/oidc/session/v1"
	"go.zenithar.org/solid/api/oidc"
	"go.zenithar.org/solid/pkg/rfcerrors"
	"go.zenithar.org/solid/pkg/storage"
	storagemock "go.zenithar.org/solid/pkg/storage/mock"
	"go.zenithar.org/solid/pkg/token"
	tokenmock "go.zenithar.org/solid/pkg/token/mock"

	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var (
	cmpOpts = []cmp.Option{
		cmpopts.IgnoreUnexported(wrappers.StringValue{}),
		cmpopts.IgnoreUnexported(corev1.TokenRequest{}),
		cmpopts.IgnoreUnexported(corev1.TokenRequest_AuthorizationCode{}),
		cmpopts.IgnoreUnexported(corev1.TokenRequest_ClientCredentials{}),
		cmpopts.IgnoreUnexported(corev1.TokenRequest_DeviceCode{}),
		cmpopts.IgnoreUnexported(corev1.TokenRequest_RefreshToken{}),
		cmpopts.IgnoreUnexported(corev1.TokenResponse{}),
		cmpopts.IgnoreUnexported(corev1.Error{}),
		cmpopts.IgnoreUnexported(corev1.OpenIDToken{}),
		cmpopts.IgnoreUnexported(sessionv1.Session{}),
	}
)

func Test_service_Token(t *testing.T) {
	type fields struct {
		accessTokenGenerator  token.AccessTokenGenerator
		idTokenGenerator      token.IDTokenGenerator
		clients               storage.ClientReader
		authorizationRequests storage.AuthorizationRequestReader
		sessions              storage.Session
	}
	type args struct {
		ctx context.Context
		req *corev1.TokenRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		prepare func(*storagemock.MockClientReader, *storagemock.MockAuthorizationRequestReader, *tokenmock.MockAccessTokenGenerator, *storagemock.MockSession)
		want    *corev1.TokenResponse
		wantErr bool
	}{
		{
			name: "nil",
			args: args{
				ctx: context.Background(),
				req: nil,
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: &corev1.Error{
					Err: "invalid_request",
					ErrorDescription: &wrappers.StringValue{
						Value: "request is nil",
					},
				},
			},
		},
		{
			name: "empty request",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRequest{},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidClient(""),
			},
		},
		{
			name: "client authentication nil",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRequest{
					Client:    nil,
					GrantType: "authorization_code",
				},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidClient(""),
			},
		},
		{
			name: "empty grant_type",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRequest{
					Client: &corev1.ClientAuthentication{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: "",
				},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidGrant(""),
			},
		},
		{
			name: "invalid grant_type",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRequest{
					Client: &corev1.ClientAuthentication{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: "foo",
				},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidGrant(""),
			},
		},
		{
			name: "grant_type mismatch: authorization_code",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRequest{
					Client: &corev1.ClientAuthentication{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
				},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidGrant(""),
			},
		},
		{
			name: "grant_type mismatch: client_credentials",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRequest{
					Client: &corev1.ClientAuthentication{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeClientCredentials,
				},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidGrant(""),
			},
		},
		{
			name: "grant_type mismatch: device_code",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRequest{
					Client: &corev1.ClientAuthentication{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeDeviceCode,
				},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidGrant(""),
			},
		},
		{
			name: "grant_type mismatch: refresh_token",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRequest{
					Client: &corev1.ClientAuthentication{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeRefreshToken,
				},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidGrant(""),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "client not found",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRequest{
					Client: &corev1.ClientAuthentication{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &corev1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &corev1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "azertyuiop",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockAuthorizationRequestReader, _ *tokenmock.MockAccessTokenGenerator, _ *storagemock.MockSession) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(nil, storage.ErrNotFound)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidClient(""),
			},
		},
		{
			name: "client storage error",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRequest{
					Client: &corev1.ClientAuthentication{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &corev1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &corev1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "azertyuiop",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockAuthorizationRequestReader, _ *tokenmock.MockAccessTokenGenerator, _ *storagemock.MockSession) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(nil, fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError(""),
			},
		},
		{
			name: "unknown grant type",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRequest{
					Client: &corev1.ClientAuthentication{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: "foo",
					Grant: &corev1.TokenRequest_ClientCredentials{
						ClientCredentials: &corev1.GrantClientCredentials{},
					},
				},
			},
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockAuthorizationRequestReader, _ *tokenmock.MockAccessTokenGenerator, _ *storagemock.MockSession) {
				validateRequest = func(ctx context.Context, req *corev1.TokenRequest) *corev1.Error {
					// Disable request validator
					return nil
				}
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&registrationv1.Client{
					GrantTypes: []string{oidc.GrantTypeClientCredentials},
				}, nil)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidGrant(""),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "client_credentials",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRequest{
					Client: &corev1.ClientAuthentication{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeClientCredentials,
					Grant: &corev1.TokenRequest_ClientCredentials{
						ClientCredentials: &corev1.GrantClientCredentials{},
					},
				},
			},
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockAuthorizationRequestReader, _ *tokenmock.MockAccessTokenGenerator, _ *storagemock.MockSession) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&registrationv1.Client{
					GrantTypes: []string{oidc.GrantTypeClientCredentials},
				}, nil)
			},
			wantErr: false,
			want:    &corev1.TokenResponse{},
		},
		// ---------------------------------------------------------------------
		{
			name: "authorization_code",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRequest{
					Client: &corev1.ClientAuthentication{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &corev1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &corev1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(clients *storagemock.MockClientReader, ar *storagemock.MockAuthorizationRequestReader, at *tokenmock.MockAccessTokenGenerator, sessions *storagemock.MockSession) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&registrationv1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				}, nil)
				sessions.EXPECT().Get(gomock.Any(), "1234567891234567890").Return(&sessionv1.Session{
					Request: &corev1.AuthorizationRequest{
						ResponseType:        "code",
						Scope:               "openid profile email offline_access",
						ClientId:            "s6BhdRkqt3",
						State:               "af0ifjsldkj",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
						CodeChallengeMethod: "S256",
					},
				}, nil)
				sessions.EXPECT().Delete(gomock.Any(), "1234567891234567890").Return(nil)
				accessTokenSuccess := at.EXPECT().Generate(gomock.Any()).Return("1/fFAGRNJru1FTz70BzhT3Zg", nil)
				at.EXPECT().Generate(gomock.Any()).Return("5ZsdF6h/sQAghJFRD", nil).After(accessTokenSuccess)
			},
			wantErr: false,
			want: &corev1.TokenResponse{
				Error: nil,
				Openid: &corev1.OpenIDToken{
					AccessToken:  "1/fFAGRNJru1FTz70BzhT3Zg",
					ExpiresIn:    3600,
					RefreshToken: &wrappers.StringValue{Value: "5ZsdF6h/sQAghJFRD"},
					TokenType:    "Bearer",
				},
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "device_code",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRequest{
					Client: &corev1.ClientAuthentication{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &corev1.TokenRequest_DeviceCode{
						DeviceCode: &corev1.GrantDeviceCode{},
					},
				},
			},
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockAuthorizationRequestReader, _ *tokenmock.MockAccessTokenGenerator, sessions *storagemock.MockSession) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&registrationv1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
				}, nil)
			},
			wantErr: false,
			want:    &corev1.TokenResponse{},
		},
		// ---------------------------------------------------------------------
		{
			name: "refresh_token",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRequest{
					Client: &corev1.ClientAuthentication{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeRefreshToken,
					Grant: &corev1.TokenRequest_RefreshToken{
						RefreshToken: &corev1.GrantRefreshToken{},
					},
				},
			},
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockAuthorizationRequestReader, _ *tokenmock.MockAccessTokenGenerator, sessions *storagemock.MockSession) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&registrationv1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
				}, nil)
			},
			wantErr: false,
			want:    &corev1.TokenResponse{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Arm mocks
			clients := storagemock.NewMockClientReader(ctrl)
			authorizationRequests := storagemock.NewMockAuthorizationRequestReader(ctrl)
			accessTokens := tokenmock.NewMockAccessTokenGenerator(ctrl)
			idTokens := tokenmock.NewMockIDTokenGenerator(ctrl)
			sessions := storagemock.NewMockSession(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(clients, authorizationRequests, accessTokens, sessions)
			}

			// Instanciate service
			underTest := New(accessTokens, idTokens, clients, authorizationRequests, sessions)

			// Under test
			got, err := underTest.Token(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("service.Token() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
				t.Errorf("service.Token() res =%s", diff)
			}
		})
	}
}
