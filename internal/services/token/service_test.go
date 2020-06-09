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
	"time"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/api/oidc"
	"zntr.io/solid/pkg/generator"
	generatormock "zntr.io/solid/pkg/generator/mock"
	"zntr.io/solid/pkg/rfcerrors"
	"zntr.io/solid/pkg/storage"
	storagemock "zntr.io/solid/pkg/storage/mock"

	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var cmpOpts = []cmp.Option{cmpopts.IgnoreFields(corev1.Token{}, "TokenId"), cmpopts.IgnoreUnexported(wrappers.StringValue{}), cmpopts.IgnoreUnexported(corev1.TokenRequest{}), cmpopts.IgnoreUnexported(corev1.TokenIntrospectionRequest{}), cmpopts.IgnoreUnexported(corev1.TokenRevocationRequest{}), cmpopts.IgnoreUnexported(corev1.TokenRequest_AuthorizationCode{}), cmpopts.IgnoreUnexported(corev1.TokenRequest_ClientCredentials{}), cmpopts.IgnoreUnexported(corev1.TokenRequest_DeviceCode{}), cmpopts.IgnoreUnexported(corev1.TokenRequest_RefreshToken{}), cmpopts.IgnoreUnexported(corev1.TokenResponse{}), cmpopts.IgnoreUnexported(corev1.TokenIntrospectionResponse{}), cmpopts.IgnoreUnexported(corev1.TokenRevocationResponse{}), cmpopts.IgnoreUnexported(corev1.Error{}), cmpopts.IgnoreUnexported(corev1.Token{}), cmpopts.IgnoreUnexported(corev1.TokenMeta{}), cmpopts.IgnoreUnexported(corev1.AuthorizationCodeSession{}), cmpopts.IgnoreUnexported(corev1.DeviceCodeSession{})}

func Test_service_Token(t *testing.T) {
	type fields struct {
		accessTokenGenerator      generator.Token
		idTokenGenerator          generator.Identity
		clients                   storage.ClientReader
		authorizationRequests     storage.AuthorizationRequestReader
		authorizationCodeSessions storage.AuthorizationCodeSession
		deviceCodeSessions        storage.DeviceCodeSession
	}
	type args struct {
		ctx context.Context
		req *corev1.TokenRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		prepare func(*storagemock.MockClientReader, *storagemock.MockAuthorizationRequestReader, *generatormock.MockToken, *storagemock.MockAuthorizationCodeSession, *storagemock.MockDeviceCodeSession, *storagemock.MockToken)
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
					Err:              "invalid_request",
					ErrorDescription: "request is nil",
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
				Error: rfcerrors.ServerError(""),
			},
		},
		{
			name: "issuer missing",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRequest{
					Client:    nil,
					GrantType: "authorization_code",
				},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError(""),
			},
		},
		{
			name: "client authentication nil",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
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
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
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
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
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
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
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
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
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
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
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
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
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
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
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
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockAuthorizationRequestReader, _ *generatormock.MockToken, _ *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockDeviceCodeSession, tokens *storagemock.MockToken) {
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
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
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
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockAuthorizationRequestReader, _ *generatormock.MockToken, _ *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockDeviceCodeSession, tokens *storagemock.MockToken) {
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
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: "foo",
					Grant: &corev1.TokenRequest_ClientCredentials{
						ClientCredentials: &corev1.GrantClientCredentials{},
					},
				},
			},
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockAuthorizationRequestReader, at *generatormock.MockToken, _ *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockDeviceCodeSession, tokens *storagemock.MockToken) {
				validateRequest = func(ctx context.Context, req *corev1.TokenRequest) *corev1.Error {
					// Disable request validator
					return nil
				}
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&corev1.Client{
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
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeClientCredentials,
					Grant: &corev1.TokenRequest_ClientCredentials{
						ClientCredentials: &corev1.GrantClientCredentials{},
					},
				},
			},
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockAuthorizationRequestReader, at *generatormock.MockToken, _ *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockDeviceCodeSession, tokens *storagemock.MockToken) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&corev1.Client{
					GrantTypes: []string{oidc.GrantTypeClientCredentials},
				}, nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo", nil)
				tokens.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
			},
			wantErr: false,
			want: &corev1.TokenResponse{
				Error: nil,
				AccessToken: &corev1.Token{
					TokenType: corev1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &corev1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						IssuedAt:  1,
						ExpiresAt: 3601,
					},
					Value: "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
				},
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "authorization_code",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
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
			prepare: func(clients *storagemock.MockClientReader, ar *storagemock.MockAuthorizationRequestReader, at *generatormock.MockToken, sessions *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockDeviceCodeSession, tokens *storagemock.MockToken) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&corev1.Client{
					GrantTypes:       []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes:    []string{"code"},
					RedirectUris:     []string{"https://client.example.org/cb"},
					SubjectType:      corev1.SubjectType_SUBJECT_TYPE_PAIRWISE,
					SectorIdentifier: "https://client.example.org",
				}, nil)
				sessions.EXPECT().Get(gomock.Any(), "1234567891234567890").Return(&corev1.AuthorizationCodeSession{
					Request: &corev1.AuthorizationRequest{
						Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
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
				atGen := at.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo", nil)
				atSave := tokens.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi", nil).After(atGen)
				tokens.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil).After(atSave)
			},
			wantErr: false,
			want: &corev1.TokenResponse{
				Error: nil,
				AccessToken: &corev1.Token{
					TokenType: corev1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &corev1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						Subject:   "BFNSOa3f3zMwuO53izk4i4Wtwbnsrewmz-DSEo26YGQ",
						Audience:  "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						Scope:     "openid profile email offline_access",
						IssuedAt:  1,
						ExpiresAt: 3601,
					},
					Value: "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
				},
				RefreshToken: &corev1.Token{
					TokenType: corev1.TokenType_TOKEN_TYPE_REFRESH_TOKEN,
					Status:    corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &corev1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						Subject:   "BFNSOa3f3zMwuO53izk4i4Wtwbnsrewmz-DSEo26YGQ",
						Audience:  "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						Scope:     "openid profile email offline_access",
						IssuedAt:  1,
						ExpiresAt: 604801,
					},
					Value: "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi",
				},
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "device_code",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &corev1.TokenRequest_DeviceCode{
						DeviceCode: &corev1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockAuthorizationRequestReader, at *generatormock.MockToken, _ *storagemock.MockAuthorizationCodeSession, sessions *storagemock.MockDeviceCodeSession, tokens *storagemock.MockToken) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&corev1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
				}, nil)
				sessions.EXPECT().Get(gomock.Any(), "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&corev1.DeviceCodeSession{
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &corev1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: 200,
					Status:    corev1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED,
				}, nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo", nil)
				tokens.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
			},
			wantErr: false,
			want: &corev1.TokenResponse{
				Error: nil,
				AccessToken: &corev1.Token{
					TokenType: corev1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &corev1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						IssuedAt:  1,
						ExpiresAt: 3601,
						ClientId:  "s6BhdRkqt3",
					},
					Value: "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
				},
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "refresh_token",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeRefreshToken,
					Grant: &corev1.TokenRequest_RefreshToken{
						RefreshToken: &corev1.GrantRefreshToken{
							RefreshToken: "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi",
						},
					},
				},
			},
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockAuthorizationRequestReader, at *generatormock.MockToken, sessions *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockDeviceCodeSession, tokens *storagemock.MockToken) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&corev1.Client{
					GrantTypes: []string{oidc.GrantTypeRefreshToken},
				}, nil)
				tokens.EXPECT().GetByValue(gomock.Any(), "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi").Return(&corev1.Token{
					Value:     "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi",
					TokenId:   "0123456789",
					TokenType: corev1.TokenType_TOKEN_TYPE_REFRESH_TOKEN,
					Status:    corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &corev1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						Audience:  "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						Scope:     "openid profile email offline_access",
						IssuedAt:  1,
						ExpiresAt: 604801,
					},
				}, nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("xtU.GvmXVrPVNqSnHjpZbEarIqOPAlfXfQpM", nil)
				tokens.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
			},
			wantErr: false,
			want: &corev1.TokenResponse{
				AccessToken: &corev1.Token{
					Value:     "xtU.GvmXVrPVNqSnHjpZbEarIqOPAlfXfQpM",
					TokenId:   "0123456789",
					TokenType: corev1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &corev1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						Audience:  "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						Scope:     "openid profile email offline_access",
						IssuedAt:  1,
						ExpiresAt: 3601,
					},
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
			accessTokens := generatormock.NewMockToken(ctrl)
			idTokens := generatormock.NewMockIdentity(ctrl)
			tokens := storagemock.NewMockToken(ctrl)
			authorizationRequests := storagemock.NewMockAuthorizationRequestReader(ctrl)
			authorizationCodeSessions := storagemock.NewMockAuthorizationCodeSession(ctrl)
			deviceCodeSessions := storagemock.NewMockDeviceCodeSession(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(clients, authorizationRequests, accessTokens, authorizationCodeSessions, deviceCodeSessions, tokens)
			}

			// instantiate service
			underTest := New(accessTokens, idTokens, clients, authorizationRequests, authorizationCodeSessions, deviceCodeSessions, tokens)

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
