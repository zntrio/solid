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
	"github.com/google/go-cmp/cmp"

	corev1 "zntr.io/solid/api/oidc/core/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/rfcerrors"
	tokenmock "zntr.io/solid/sdk/token/mock"
	"zntr.io/solid/server/storage"
	storagemock "zntr.io/solid/server/storage/mock"
)

func Test_service_refreshToken(t *testing.T) {
	type args struct {
		ctx    context.Context
		client *corev1.Client
		req    *corev1.TokenRequest
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*storagemock.MockToken, *tokenmock.MockGenerator, *tokenmock.MockGenerator)
		want    *corev1.TokenResponse
		wantErr bool
	}{
		{
			name: "nil client",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRequest{
					GrantType: oidc.GrantTypeClientCredentials,
					Grant: &corev1.TokenRequest_ClientCredentials{
						ClientCredentials: &corev1.GrantClientCredentials{},
					},
				},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "nil request",
			args: args{
				ctx:    context.Background(),
				client: &corev1.Client{},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "nil grant",
			args: args{
				ctx:    context.Background(),
				client: &corev1.Client{},
				req: &corev1.TokenRequest{
					GrantType: oidc.GrantTypeAuthorizationCode,
				},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "empty issuer",
			args: args{
				ctx:    context.Background(),
				client: &corev1.Client{},
				req: &corev1.TokenRequest{
					Issuer:    "",
					Client:    &corev1.Client{},
					GrantType: oidc.GrantTypeRefreshToken,
					Grant: &corev1.TokenRequest_RefreshToken{
						RefreshToken: &corev1.GrantRefreshToken{},
					},
				},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "invalid issuer",
			args: args{
				ctx:    context.Background(),
				client: &corev1.Client{},
				req: &corev1.TokenRequest{
					Issuer:    "foo",
					Client:    &corev1.Client{},
					GrantType: oidc.GrantTypeRefreshToken,
					Grant: &corev1.TokenRequest_RefreshToken{
						RefreshToken: &corev1.GrantRefreshToken{},
					},
				},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "empty refresh_token",
			args: args{
				ctx:    context.Background(),
				client: &corev1.Client{},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeRefreshToken,
					Grant: &corev1.TokenRequest_RefreshToken{
						RefreshToken: &corev1.GrantRefreshToken{
							RefreshToken: "",
						},
					},
				},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "client not support grant_type",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeAuthorizationCode},
				},
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
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.UnsupportedGrantType().Build(),
			},
		},
		{
			name: "refresh token not found",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeRefreshToken},
				},
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
			prepare: func(tokens *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi").Return(nil, storage.ErrNotFound)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "refresh token storage error",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeRefreshToken},
				},
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
			prepare: func(tokens *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi").Return(nil, fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "refresh token is not active",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeRefreshToken},
				},
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
			prepare: func(tokens *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi").Return(&corev1.Token{
					Value:     "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi",
					TokenId:   "0123456789",
					Status:    corev1.TokenStatus_TOKEN_STATUS_REVOKED,
					TokenType: corev1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
				}, nil)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "refresh token is not a refresh_token",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeRefreshToken},
				},
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
			prepare: func(tokens *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi").Return(&corev1.Token{
					Value:     "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi",
					TokenId:   "0123456789",
					Status:    corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
					TokenType: corev1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
				}, nil)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "refresh token doesn't have metadata",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeRefreshToken},
				},
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
			prepare: func(tokens *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi").Return(&corev1.Token{
					Value:     "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi",
					TokenId:   "0123456789",
					Status:    corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
					TokenType: corev1.TokenType_TOKEN_TYPE_REFRESH_TOKEN,
				}, nil)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "refresh token expired",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeRefreshToken},
				},
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
			prepare: func(tokens *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(100, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi").Return(&corev1.Token{
					Value:     "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi",
					TokenId:   "0123456789",
					Status:    corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
					TokenType: corev1.TokenType_TOKEN_TYPE_REFRESH_TOKEN,
					Metadata: &corev1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						Audience:  "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						Scope:     "openid profile email offline_access",
						IssuedAt:  1,
						ExpiresAt: 2,
						NotBefore: 2,
					},
				}, nil)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "refresh token / client_id mismatch",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeRefreshToken},
				},
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
			prepare: func(tokens *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi").Return(&corev1.Token{
					Value:     "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi",
					TokenId:   "0123456789",
					Status:    corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
					TokenType: corev1.TokenType_TOKEN_TYPE_REFRESH_TOKEN,
					Metadata: &corev1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						ClientId:  "123458",
						Audience:  "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						Scope:     "openid profile email offline_access",
						IssuedAt:  1,
						NotBefore: 2,
						ExpiresAt: 604801,
					},
				}, nil)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "error during accessToken generation",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeRefreshToken},
				},
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
			prepare: func(tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi").Return(&corev1.Token{
					Value:     "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi",
					TokenId:   "0123456789",
					TokenType: corev1.TokenType_TOKEN_TYPE_REFRESH_TOKEN,
					Status:    corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &corev1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						Audience:  "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						Scope:     "openid profile email offline_access",
						IssuedAt:  1,
						NotBefore: 2,
						ExpiresAt: 604801,
					},
				}, nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("", fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "empty access token value",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeRefreshToken},
				},
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
			prepare: func(tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi").Return(&corev1.Token{
					Value:     "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi",
					TokenId:   "0123456789",
					TokenType: corev1.TokenType_TOKEN_TYPE_REFRESH_TOKEN,
					Status:    corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &corev1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						Audience:  "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						Scope:     "openid profile email offline_access",
						IssuedAt:  1,
						NotBefore: 2,
						ExpiresAt: 604801,
					},
				}, nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("", nil)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "token storage error",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeRefreshToken},
				},
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
			prepare: func(tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi").Return(&corev1.Token{
					Value:     "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi",
					TokenId:   "0123456789",
					TokenType: corev1.TokenType_TOKEN_TYPE_REFRESH_TOKEN,
					Status:    corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &corev1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						Audience:  "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						Scope:     "openid profile email offline_access",
						IssuedAt:  1,
						NotBefore: 2,
						ExpiresAt: 604801,
					},
				}, nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("xtU.GvmXVrPVNqSnHjpZbEarIqOPAlfXfQpM", nil)
				tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "rt generation error",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeRefreshToken},
				},
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
			prepare: func(tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi").Return(&corev1.Token{
					Value:     "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi",
					TokenId:   "0123456789",
					TokenType: corev1.TokenType_TOKEN_TYPE_REFRESH_TOKEN,
					Status:    corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &corev1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						Audience:  "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						Scope:     "openid profile email offline_access",
						IssuedAt:  1,
						ExpiresAt: 2,
						NotBefore: 2,
					},
				}, nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("xtU.GvmXVrPVNqSnHjpZbEarIqOPAlfXfQpM", nil)
				atSave := tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(nil)
				rt.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("JHP.HscxBIrTOYZWgupVlrABwkdbhtqVFrmr", nil)
				tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(fmt.Errorf("foo")).After(atSave)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "rt revocation error",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeRefreshToken},
				},
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
			prepare: func(tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi").Return(&corev1.Token{
					Value:     "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi",
					TokenId:   "0123456789",
					TokenType: corev1.TokenType_TOKEN_TYPE_REFRESH_TOKEN,
					Status:    corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &corev1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						Audience:  "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						Scope:     "openid profile email offline_access",
						IssuedAt:  1,
						ExpiresAt: 2,
						NotBefore: 2,
					},
				}, nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("xtU.GvmXVrPVNqSnHjpZbEarIqOPAlfXfQpM", nil)
				atSave := tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(nil)
				rt.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("JHP.HscxBIrTOYZWgupVlrABwkdbhtqVFrmr", nil)
				tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(nil).After(atSave)
				tokens.EXPECT().Revoke(gomock.Any(), "http://127.0.0.1:8080", "0123456789").Return(fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "valid",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeRefreshToken},
				},
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
			prepare: func(tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi").Return(&corev1.Token{
					Value:     "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi",
					TokenId:   "0123456789",
					TokenType: corev1.TokenType_TOKEN_TYPE_REFRESH_TOKEN,
					Status:    corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &corev1.TokenMeta{
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
						NotBefore: 2,
						ExpiresAt: 3601,
					},
				},
			},
		},
		{
			name: "valid with new rt",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeRefreshToken},
				},
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
			prepare: func(tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi").Return(&corev1.Token{
					Value:     "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi",
					TokenId:   "0123456789",
					TokenType: corev1.TokenType_TOKEN_TYPE_REFRESH_TOKEN,
					Status:    corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &corev1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						Audience:  "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						Scope:     "openid profile email offline_access",
						IssuedAt:  1,
						NotBefore: 2,
						ExpiresAt: 2,
					},
				}, nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("xtU.GvmXVrPVNqSnHjpZbEarIqOPAlfXfQpM", nil)
				atSave := tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(nil)
				rt.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("JHP.HscxBIrTOYZWgupVlrABwkdbhtqVFrmr", nil)
				tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(nil).After(atSave)
				tokens.EXPECT().Revoke(gomock.Any(), "http://127.0.0.1:8080", "0123456789").Return(nil)
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
						NotBefore: 2,
						ExpiresAt: 3601,
					},
				},
				RefreshToken: &corev1.Token{
					Value:     "JHP.HscxBIrTOYZWgupVlrABwkdbhtqVFrmr",
					TokenId:   "0123456789",
					TokenType: corev1.TokenType_TOKEN_TYPE_REFRESH_TOKEN,
					Status:    corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &corev1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						Audience:  "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						Scope:     "openid profile email offline_access",
						IssuedAt:  1,
						NotBefore: 2,
						ExpiresAt: 604801,
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
			accessTokens := tokenmock.NewMockGenerator(ctrl)
			refreshTokens := tokenmock.NewMockGenerator(ctrl)
			tokens := storagemock.NewMockToken(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(tokens, accessTokens, refreshTokens)
			}

			s := &service{
				tokens:          tokens,
				accessTokenGen:  accessTokens,
				refreshTokenGen: refreshTokens,
			}
			got, err := s.refreshToken(tt.args.ctx, tt.args.client, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("service.refreshToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
				t.Errorf("service.refreshToken() res = %s", diff)
			}
		})
	}
}
