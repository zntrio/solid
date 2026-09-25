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

	"github.com/google/go-cmp/cmp"
	"go.uber.org/mock/gomock"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/rfcerrors"
	tokenmock "zntr.io/solid/sdk/token/mock"
	"zntr.io/solid/server/storage"
	storagemock "zntr.io/solid/server/storage/mock"
)

// activeSubjectToken is the canonical active subject token used by the
// token-exchange tests.
func activeSubjectToken() *tokenv1.Token {
	return &tokenv1.Token{
		Value:     "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
		TokenId:   "0123456789",
		TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
		Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
		Metadata: &tokenv1.TokenMeta{
			Issuer:    "http://127.0.0.1:8080",
			ClientId:  "s6BhdRkqt3",
			Subject:   "user-1",
			Scope:     "openid profile email",
			ExpiresAt: 3601,
		},
	}
}

func Test_service_tokenExchange(t *testing.T) {
	type args struct {
		ctx    context.Context
		client *clientv1.Client
		req    *flowv1.TokenRequest
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*storagemock.MockToken, *storagemock.MockResourceReader, *tokenmock.MockGenerator)
		want    *flowv1.TokenResponse
		wantErr bool
	}{
		{
			name: "subject_token is not active",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeTokenExchange},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeTokenExchange,
					Grant: &flowv1.TokenRequest_TokenExchange{
						TokenExchange: &flowv1.GrantTokenExchange{
							SubjectToken:     "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
							SubjectTokenType: oidc.TokenExchangeAccessTokenType,
						},
					},
				},
			},
			prepare: func(tokens *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo").Return(&tokenv1.Token{
					Value:     "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
					TokenId:   "0123456789",
					TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    tokenv1.TokenStatus_TOKEN_STATUS_REVOKED,
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						ClientId:  "s6BhdRkqt3",
						Scope:     "openid profile email",
						ExpiresAt: 3601,
					},
				}, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "subject_token is not an access token",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeTokenExchange},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeTokenExchange,
					Grant: &flowv1.TokenRequest_TokenExchange{
						TokenExchange: &flowv1.GrantTokenExchange{
							SubjectToken:     "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi",
							SubjectTokenType: oidc.TokenExchangeAccessTokenType,
						},
					},
				},
			},
			prepare: func(tokens *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi").Return(&tokenv1.Token{
					Value:     "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi",
					TokenId:   "0123456789",
					TokenType: tokenv1.TokenType_TOKEN_TYPE_REFRESH_TOKEN,
					Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						ClientId:  "s6BhdRkqt3",
						Scope:     "openid profile email",
						ExpiresAt: 3601,
					},
				}, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "requested scope exceeds subject token scope",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeTokenExchange},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Scope:     new("openid profile admin"),
					GrantType: oidc.GrantTypeTokenExchange,
					Grant: &flowv1.TokenRequest_TokenExchange{
						TokenExchange: &flowv1.GrantTokenExchange{
							SubjectToken:     "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
							SubjectTokenType: oidc.TokenExchangeAccessTokenType,
						},
					},
				},
			},
			prepare: func(tokens *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo").Return(&tokenv1.Token{
					Value:     "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
					TokenId:   "0123456789",
					TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						ClientId:  "s6BhdRkqt3",
						Scope:     "openid profile",
						ExpiresAt: 3601,
					},
				}, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidScope().Build(),
			},
		},
		{
			name: "requested scope is a subset of subject token scope",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeTokenExchange},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Scope:     new("openid profile"),
					GrantType: oidc.GrantTypeTokenExchange,
					Grant: &flowv1.TokenRequest_TokenExchange{
						TokenExchange: &flowv1.GrantTokenExchange{
							SubjectToken:     "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
							SubjectTokenType: oidc.TokenExchangeAccessTokenType,
						},
					},
				},
			},
			prepare: func(tokens *storagemock.MockToken, _ *storagemock.MockResourceReader, at *tokenmock.MockGenerator) {
				old := timeFunc
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				t.Cleanup(func() { timeFunc = old })
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo").Return(&tokenv1.Token{
					Value:     "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
					TokenId:   "0123456789",
					TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						ClientId:  "s6BhdRkqt3",
						Scope:     "openid profile email",
						ExpiresAt: 3601,
					},
				}, nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("xtU.GvmXVrPVNqSnHjpZbEarIqOPAlfXfQpM", nil)
				tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(nil)
			},
			wantErr: false,
			want: &flowv1.TokenResponse{
				Issuer:          "http://127.0.0.1:8080",
				IssuedTokenType: new(oidc.TokenExchangeAccessTokenType),
				Scope:           new("openid profile"),
				AccessToken: &tokenv1.Token{
					Value:     "xtU.GvmXVrPVNqSnHjpZbEarIqOPAlfXfQpM",
					TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						ClientId:  "s6BhdRkqt3",
						Scope:     "openid profile",
						IssuedAt:  1,
						ExpiresAt: 61,
					},
				},
			},
		},
		// -----------------------------------------------------------------
		// tokenExchange outer guards.
		{
			name: "nil grant",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeTokenExchange},
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					GrantType: oidc.GrantTypeTokenExchange,
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "authorization_details is not supported",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeTokenExchange},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType:            oidc.GrantTypeTokenExchange,
					AuthorizationDetails: []*tokenv1.AuthorizationDetail{{Type: "payment"}},
					Grant: &flowv1.TokenRequest_TokenExchange{
						TokenExchange: &flowv1.GrantTokenExchange{
							SubjectToken:     "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
							SubjectTokenType: oidc.TokenExchangeAccessTokenType,
						},
					},
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidAuthorizationDetails().Build(),
			},
		},
		{
			name: "empty subject_token_type",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeTokenExchange},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeTokenExchange,
					Grant: &flowv1.TokenRequest_TokenExchange{
						TokenExchange: &flowv1.GrantTokenExchange{
							SubjectToken: "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
						},
					},
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty subject_token",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeTokenExchange},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeTokenExchange,
					Grant: &flowv1.TokenRequest_TokenExchange{
						TokenExchange: &flowv1.GrantTokenExchange{
							SubjectTokenType: oidc.TokenExchangeAccessTokenType,
						},
					},
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "unsupported subject_token_type",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeTokenExchange},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeTokenExchange,
					Grant: &flowv1.TokenRequest_TokenExchange{
						TokenExchange: &flowv1.GrantTokenExchange{
							SubjectToken:     "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
							SubjectTokenType: "urn:ietf:params:oauth:token-type:refresh_token",
						},
					},
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		// -----------------------------------------------------------------
		// tokenExchangeAccessToken guard chain.
		{
			name: "subject token lookup: storage error",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeTokenExchange},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeTokenExchange,
					Grant: &flowv1.TokenRequest_TokenExchange{
						TokenExchange: &flowv1.GrantTokenExchange{
							SubjectToken:     "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
							SubjectTokenType: oidc.TokenExchangeAccessTokenType,
						},
					},
				},
			},
			prepare: func(tokens *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo").Return(nil, fmt.Errorf("boom"))
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "subject token lookup: not found",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeTokenExchange},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeTokenExchange,
					Grant: &flowv1.TokenRequest_TokenExchange{
						TokenExchange: &flowv1.GrantTokenExchange{
							SubjectToken:     "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
							SubjectTokenType: oidc.TokenExchangeAccessTokenType,
						},
					},
				},
			},
			prepare: func(tokens *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo").Return(nil, storage.ErrNotFound)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "subject token has nil metadata",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeTokenExchange},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeTokenExchange,
					Grant: &flowv1.TokenRequest_TokenExchange{
						TokenExchange: &flowv1.GrantTokenExchange{
							SubjectToken:     "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
							SubjectTokenType: oidc.TokenExchangeAccessTokenType,
						},
					},
				},
			},
			prepare: func(tokens *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo").Return(&tokenv1.Token{
					Value:     "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
					TokenId:   "0123456789",
					TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
				}, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "unsupported requested_token_type",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeTokenExchange},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeTokenExchange,
					Grant: &flowv1.TokenRequest_TokenExchange{
						TokenExchange: &flowv1.GrantTokenExchange{
							SubjectToken:       "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
							SubjectTokenType:   oidc.TokenExchangeAccessTokenType,
							RequestedTokenType: new("urn:ietf:params:oauth:token-type:jwt"),
						},
					},
				},
			},
			prepare: func(tokens *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo").Return(activeSubjectToken(), nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "subject token is expired",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeTokenExchange},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeTokenExchange,
					Grant: &flowv1.TokenRequest_TokenExchange{
						TokenExchange: &flowv1.GrantTokenExchange{
							SubjectToken:     "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
							SubjectTokenType: oidc.TokenExchangeAccessTokenType,
						},
					},
				},
			},
			prepare: func(tokens *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(100, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo").Return(&tokenv1.Token{
					Value:     "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
					TokenId:   "0123456789",
					TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						ClientId:  "s6BhdRkqt3",
						Scope:     "openid profile email",
						ExpiresAt: 99,
					},
				}, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "actor token is invalid",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeTokenExchange},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeTokenExchange,
					Grant: &flowv1.TokenRequest_TokenExchange{
						TokenExchange: &flowv1.GrantTokenExchange{
							SubjectToken:     "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
							SubjectTokenType: oidc.TokenExchangeAccessTokenType,
							ActorToken:       new("xtU.GvmXVrPVNqSnHjpZbEarIqOPAlfXfQpM"),
						},
					},
				},
			},
			prepare: func(tokens *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo").Return(activeSubjectToken(), nil)
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "xtU.GvmXVrPVNqSnHjpZbEarIqOPAlfXfQpM").Return(&tokenv1.Token{
					Value:     "xtU.GvmXVrPVNqSnHjpZbEarIqOPAlfXfQpM",
					TokenId:   "9876543210",
					TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    tokenv1.TokenStatus_TOKEN_STATUS_REVOKED,
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						ClientId:  "s6BhdRkqt3",
						ExpiresAt: 3601,
					},
				}, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "actor token is expired",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeTokenExchange},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeTokenExchange,
					Grant: &flowv1.TokenRequest_TokenExchange{
						TokenExchange: &flowv1.GrantTokenExchange{
							SubjectToken:     "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
							SubjectTokenType: oidc.TokenExchangeAccessTokenType,
							ActorToken:       new("xtU.GvmXVrPVNqSnHjpZbEarIqOPAlfXfQpM"),
						},
					},
				},
			},
			prepare: func(tokens *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(100, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo").Return(activeSubjectToken(), nil)
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "xtU.GvmXVrPVNqSnHjpZbEarIqOPAlfXfQpM").Return(&tokenv1.Token{
					Value:     "xtU.GvmXVrPVNqSnHjpZbEarIqOPAlfXfQpM",
					TokenId:   "9876543210",
					TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						ClientId:  "s6BhdRkqt3",
						Subject:   "actor-1",
						ExpiresAt: 99,
					},
				}, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "actor is not in may_act",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeTokenExchange},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeTokenExchange,
					Grant: &flowv1.TokenRequest_TokenExchange{
						TokenExchange: &flowv1.GrantTokenExchange{
							SubjectToken:     "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
							SubjectTokenType: oidc.TokenExchangeAccessTokenType,
							ActorToken:       new("xtU.GvmXVrPVNqSnHjpZbEarIqOPAlfXfQpM"),
						},
					},
				},
			},
			prepare: func(tokens *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				st := activeSubjectToken()
				st.MayAct = []*tokenv1.Actor{{Subject: "someone-else"}}
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo").Return(st, nil)
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "xtU.GvmXVrPVNqSnHjpZbEarIqOPAlfXfQpM").Return(&tokenv1.Token{
					Value:     "xtU.GvmXVrPVNqSnHjpZbEarIqOPAlfXfQpM",
					TokenId:   "9876543210",
					TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						ClientId:  "s6BhdRkqt3",
						Subject:   "actor-1",
						ExpiresAt: 3601,
					},
				}, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "actor in may_act succeeds and carries the act chain",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeTokenExchange},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeTokenExchange,
					Grant: &flowv1.TokenRequest_TokenExchange{
						TokenExchange: &flowv1.GrantTokenExchange{
							SubjectToken:     "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
							SubjectTokenType: oidc.TokenExchangeAccessTokenType,
							ActorToken:       new("xtU.GvmXVrPVNqSnHjpZbEarIqOPAlfXfQpM"),
						},
					},
				},
			},
			prepare: func(tokens *storagemock.MockToken, _ *storagemock.MockResourceReader, at *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				st := activeSubjectToken()
				st.MayAct = []*tokenv1.Actor{{Subject: "actor-1"}}
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo").Return(st, nil)
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "xtU.GvmXVrPVNqSnHjpZbEarIqOPAlfXfQpM").Return(&tokenv1.Token{
					Value:     "xtU.GvmXVrPVNqSnHjpZbEarIqOPAlfXfQpM",
					TokenId:   "9876543210",
					TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Actor:     []*tokenv1.Actor{{Subject: "prior-actor"}},
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						ClientId:  "s6BhdRkqt3",
						Subject:   "actor-1",
						ExpiresAt: 3601,
					},
				}, nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("ytV.HwrXWsPYOnLxkIpZbEarIqOPAlfXfQpM", nil)
				tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(nil)
			},
			wantErr: false,
			want: &flowv1.TokenResponse{
				Issuer:          "http://127.0.0.1:8080",
				IssuedTokenType: new(oidc.TokenExchangeAccessTokenType),
				AccessToken: &tokenv1.Token{
					Value:     "ytV.HwrXWsPYOnLxkIpZbEarIqOPAlfXfQpM",
					TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Actor: []*tokenv1.Actor{
						{Subject: "actor-1"},
						{Subject: "prior-actor"},
					},
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						Subject:   "user-1",
						ClientId:  "s6BhdRkqt3",
						Scope:     "openid profile email",
						IssuedAt:  1,
						ExpiresAt: 61,
					},
				},
			},
		},
		{
			name: "DPoP confirmation mismatch with key-bound subject token",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeTokenExchange},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeTokenExchange,
					Grant: &flowv1.TokenRequest_TokenExchange{
						TokenExchange: &flowv1.GrantTokenExchange{
							SubjectToken:     "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
							SubjectTokenType: oidc.TokenExchangeAccessTokenType,
						},
					},
					TokenConfirmation: nil,
				},
			},
			prepare: func(tokens *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				st := activeSubjectToken()
				st.Confirmation = &tokenv1.TokenConfirmation{Jkt: "abc"}
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo").Return(st, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "unknown audience",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeTokenExchange},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Audience:  new("https://unknown.example.com"),
					GrantType: oidc.GrantTypeTokenExchange,
					Grant: &flowv1.TokenRequest_TokenExchange{
						TokenExchange: &flowv1.GrantTokenExchange{
							SubjectToken:     "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
							SubjectTokenType: oidc.TokenExchangeAccessTokenType,
						},
					},
				},
			},
			prepare: func(tokens *storagemock.MockToken, resources *storagemock.MockResourceReader, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo").Return(activeSubjectToken(), nil)
				resources.EXPECT().GetByURI(gomock.Any(), "https://unknown.example.com").Return(nil, storage.ErrNotFound)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidTarget().Build(),
			},
		},
		{
			name: "audience resource storage error",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeTokenExchange},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Audience:  new("https://api.example.com"),
					GrantType: oidc.GrantTypeTokenExchange,
					Grant: &flowv1.TokenRequest_TokenExchange{
						TokenExchange: &flowv1.GrantTokenExchange{
							SubjectToken:     "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
							SubjectTokenType: oidc.TokenExchangeAccessTokenType,
						},
					},
				},
			},
			prepare: func(tokens *storagemock.MockToken, resources *storagemock.MockResourceReader, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo").Return(activeSubjectToken(), nil)
				resources.EXPECT().GetByURI(gomock.Any(), "https://api.example.com").Return(nil, fmt.Errorf("boom"))
			},
			wantErr: true,
			want:    &flowv1.TokenResponse{},
		},
		{
			name: "access token generation fails",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeTokenExchange},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeTokenExchange,
					Grant: &flowv1.TokenRequest_TokenExchange{
						TokenExchange: &flowv1.GrantTokenExchange{
							SubjectToken:     "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
							SubjectTokenType: oidc.TokenExchangeAccessTokenType,
						},
					},
				},
			},
			prepare: func(tokens *storagemock.MockToken, _ *storagemock.MockResourceReader, at *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo").Return(activeSubjectToken(), nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("", fmt.Errorf("boom"))
			},
			wantErr: true,
			want:    &flowv1.TokenResponse{},
		},
		{
			name: "access token generator returns empty value",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeTokenExchange},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeTokenExchange,
					Grant: &flowv1.TokenRequest_TokenExchange{
						TokenExchange: &flowv1.GrantTokenExchange{
							SubjectToken:     "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
							SubjectTokenType: oidc.TokenExchangeAccessTokenType,
						},
					},
				},
			},
			prepare: func(tokens *storagemock.MockToken, _ *storagemock.MockResourceReader, at *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo").Return(activeSubjectToken(), nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("", nil)
			},
			wantErr: true,
			want:    &flowv1.TokenResponse{},
		},
		{
			name: "token storage Create fails",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeTokenExchange},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeTokenExchange,
					Grant: &flowv1.TokenRequest_TokenExchange{
						TokenExchange: &flowv1.GrantTokenExchange{
							SubjectToken:     "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
							SubjectTokenType: oidc.TokenExchangeAccessTokenType,
						},
					},
				},
			},
			prepare: func(tokens *storagemock.MockToken, _ *storagemock.MockResourceReader, at *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo").Return(activeSubjectToken(), nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("ytV.HwrXWsPYOnLxkIpZbEarIqOPAlfXfQpM", nil)
				tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(fmt.Errorf("boom"))
			},
			wantErr: true,
			want:    &flowv1.TokenResponse{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Arm mocks
			tokens := storagemock.NewMockToken(ctrl)
			resources := storagemock.NewMockResourceReader(ctrl)
			accessTokens := tokenmock.NewMockGenerator(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(tokens, resources, accessTokens)
			}

			s := &service{
				tokens:         tokens,
				resources:      resources,
				accessTokenGen: accessTokens,
			}
			got, err := s.tokenExchange(tt.args.ctx, tt.args.client, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("service.tokenExchange() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
				t.Errorf("service.tokenExchange() res = %s", diff)
			}
		})
	}
}
