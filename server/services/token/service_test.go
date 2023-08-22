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

	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	corev1 "zntr.io/solid/api/oidc/core/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	sessionv1 "zntr.io/solid/api/oidc/session/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/rfcerrors"
	tokenmock "zntr.io/solid/sdk/token/mock"
	"zntr.io/solid/sdk/types"
	"zntr.io/solid/server/storage"
	storagemock "zntr.io/solid/server/storage/mock"
)

var cmpOpts = []cmp.Option{cmpopts.IgnoreFields(tokenv1.Token{}, "TokenId"), cmpopts.IgnoreUnexported(wrappers.StringValue{}), cmpopts.IgnoreUnexported(flowv1.TokenRequest{}), cmpopts.IgnoreUnexported(tokenv1.IntrospectRequest{}), cmpopts.IgnoreUnexported(tokenv1.RevokeRequest{}), cmpopts.IgnoreUnexported(flowv1.TokenRequest_AuthorizationCode{}), cmpopts.IgnoreUnexported(flowv1.TokenRequest_ClientCredentials{}), cmpopts.IgnoreUnexported(flowv1.TokenRequest_DeviceCode{}), cmpopts.IgnoreUnexported(flowv1.TokenRequest_RefreshToken{}), cmpopts.IgnoreUnexported(flowv1.TokenResponse{}), cmpopts.IgnoreUnexported(tokenv1.IntrospectResponse{}), cmpopts.IgnoreUnexported(tokenv1.RevokeResponse{}), cmpopts.IgnoreUnexported(corev1.Error{}), cmpopts.IgnoreUnexported(tokenv1.Token{}), cmpopts.IgnoreUnexported(tokenv1.TokenMeta{}), cmpopts.IgnoreUnexported(sessionv1.AuthorizationCodeSession{}), cmpopts.IgnoreUnexported(sessionv1.DeviceCodeSession{})}

func Test_service_Token(t *testing.T) {
	type args struct {
		ctx context.Context
		req *flowv1.TokenRequest
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*storagemock.MockClientReader, *storagemock.MockAuthorizationRequestReader, *tokenmock.MockGenerator, *tokenmock.MockGenerator, *storagemock.MockAuthorizationCodeSession, *storagemock.MockDeviceCodeSession, *storagemock.MockToken)
		want    *flowv1.TokenResponse
		wantErr bool
	}{
		{
			name: "nil",
			args: args{
				ctx: context.Background(),
				req: nil,
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
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
				req: &flowv1.TokenRequest{},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "issuer missing",
			args: args{
				ctx: context.Background(),
				req: &flowv1.TokenRequest{
					Client:    nil,
					GrantType: "authorization_code",
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "client authentication nil",
			args: args{
				ctx: context.Background(),
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					Client:    nil,
					GrantType: "authorization_code",
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidClient().Build(),
			},
		},
		{
			name: "empty grant_type",
			args: args{
				ctx: context.Background(),
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: "",
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "invalid grant_type",
			args: args{
				ctx: context.Background(),
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: "foo",
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "grant_type mismatch: authorization_code",
			args: args{
				ctx: context.Background(),
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "grant_type mismatch: client_credentials",
			args: args{
				ctx: context.Background(),
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeClientCredentials,
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "grant_type mismatch: device_code",
			args: args{
				ctx: context.Background(),
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeDeviceCode,
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "grant_type mismatch: refresh_token",
			args: args{
				ctx: context.Background(),
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeRefreshToken,
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "client not found",
			args: args{
				ctx: context.Background(),
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "azertyuiop",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockAuthorizationRequestReader, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator, _ *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockDeviceCodeSession, tokens *storagemock.MockToken) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(nil, storage.ErrNotFound)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidClient().Build(),
			},
		},
		{
			name: "client storage error",
			args: args{
				ctx: context.Background(),
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "azertyuiop",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockAuthorizationRequestReader, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator, _ *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockDeviceCodeSession, tokens *storagemock.MockToken) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(nil, fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "unknown grant type",
			args: args{
				ctx: context.Background(),
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: "foo",
					Grant: &flowv1.TokenRequest_ClientCredentials{
						ClientCredentials: &flowv1.GrantClientCredentials{},
					},
				},
			},
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockAuthorizationRequestReader, at *tokenmock.MockGenerator, _ *tokenmock.MockGenerator, _ *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockDeviceCodeSession, tokens *storagemock.MockToken) {
				validateRequest = func(ctx context.Context, req *flowv1.TokenRequest) *corev1.Error {
					// Disable request validator
					return nil
				}
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeClientCredentials},
				}, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "client_credentials",
			args: args{
				ctx: context.Background(),
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId:   "s6BhdRkqt3",
						ClientType: clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
					},
					GrantType: oidc.GrantTypeClientCredentials,
					Grant: &flowv1.TokenRequest_ClientCredentials{
						ClientCredentials: &flowv1.GrantClientCredentials{},
					},
				},
			},
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockAuthorizationRequestReader, at *tokenmock.MockGenerator, _ *tokenmock.MockGenerator, _ *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockDeviceCodeSession, tokens *storagemock.MockToken) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeClientCredentials},
					ClientType: clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
				}, nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo", nil)
				tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(nil)
			},
			wantErr: false,
			want: &flowv1.TokenResponse{
				Error: nil,
				AccessToken: &tokenv1.Token{
					TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						IssuedAt:  1,
						NotBefore: 2,
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
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(clients *storagemock.MockClientReader, ar *storagemock.MockAuthorizationRequestReader, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator, sessions *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockDeviceCodeSession, tokens *storagemock.MockToken) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&clientv1.Client{
					GrantTypes:       []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes:    []string{"code"},
					RedirectUris:     []string{"https://client.example.org/cb"},
					SubjectType:      oidc.SubjectTypePublic,
					SectorIdentifier: "https://client.example.org",
				}, nil)
				sessions.EXPECT().Get(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(&sessionv1.AuthorizationCodeSession{
					Request: &flowv1.AuthorizationRequest{
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
				sessions.EXPECT().Delete(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo", nil)
				atSave := tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(nil)
				rt.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi", nil)
				tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(nil).After(atSave)
			},
			wantErr: false,
			want: &flowv1.TokenResponse{
				Error: nil,
				AccessToken: &tokenv1.Token{
					TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						Subject:   "",
						Audience:  "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						Scope:     "openid profile email offline_access",
						IssuedAt:  1,
						NotBefore: 2,
						ExpiresAt: 3601,
					},
					Value: "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
				},
				RefreshToken: &tokenv1.Token{
					TokenType: tokenv1.TokenType_TOKEN_TYPE_REFRESH_TOKEN,
					Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						Subject:   "",
						Audience:  "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						Scope:     "openid profile email offline_access",
						IssuedAt:  1,
						NotBefore: 2,
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
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &flowv1.TokenRequest_DeviceCode{
						DeviceCode: &flowv1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
					Scope: types.StringRef("openid admin"),
				},
			},
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockAuthorizationRequestReader, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator, _ *storagemock.MockAuthorizationCodeSession, sessions *storagemock.MockDeviceCodeSession, tokens *storagemock.MockToken) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&clientv1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
				}, nil)
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&sessionv1.DeviceCodeSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: 200,
					Status:    sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED,
					Subject:   types.StringRef("user1"),
				}, nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo", nil)
				tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(nil)
			},
			wantErr: false,
			want: &flowv1.TokenResponse{
				Error: nil,
				AccessToken: &tokenv1.Token{
					TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						IssuedAt:  1,
						NotBefore: 2,
						ExpiresAt: 3601,
						ClientId:  "s6BhdRkqt3",
						Subject:   "user1",
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
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeRefreshToken,
					Grant: &flowv1.TokenRequest_RefreshToken{
						RefreshToken: &flowv1.GrantRefreshToken{
							RefreshToken: "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi",
						},
					},
				},
			},
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockAuthorizationRequestReader, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator, sessions *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockDeviceCodeSession, tokens *storagemock.MockToken) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeRefreshToken},
				}, nil)
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi").Return(&tokenv1.Token{
					Value:     "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi",
					TokenId:   "0123456789",
					TokenType: tokenv1.TokenType_TOKEN_TYPE_REFRESH_TOKEN,
					Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						Audience:  "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						Scope:     "openid profile email offline_access",
						IssuedAt:  1,
						NotBefore: 2,
						ExpiresAt: 604801,
					},
				}, nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("xtU.GvmXVrPVNqSnHjpZbEarIqOPAlfXfQpM", nil)
				tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(nil)
			},
			wantErr: false,
			want: &flowv1.TokenResponse{
				AccessToken: &tokenv1.Token{
					Value:     "xtU.GvmXVrPVNqSnHjpZbEarIqOPAlfXfQpM",
					TokenId:   "0123456789",
					TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						Audience:  "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						Scope:     "openid profile email offline_access",
						IssuedAt:  1,
						NotBefore: 2,
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
			accessTokens := tokenmock.NewMockGenerator(ctrl)
			refreshTokens := tokenmock.NewMockGenerator(ctrl)
			tokens := storagemock.NewMockToken(ctrl)
			authorizationRequests := storagemock.NewMockAuthorizationRequestReader(ctrl)
			authorizationCodeSessions := storagemock.NewMockAuthorizationCodeSession(ctrl)
			deviceCodeSessions := storagemock.NewMockDeviceCodeSession(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(clients, authorizationRequests, accessTokens, refreshTokens, authorizationCodeSessions, deviceCodeSessions, tokens)
			}

			// instantiate service
			underTest := New(accessTokens, refreshTokens, clients, authorizationRequests, authorizationCodeSessions, deviceCodeSessions, tokens, nil)

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
