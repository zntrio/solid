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
	resourcev1 "zntr.io/solid/api/oidc/resource/v1"
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
			// The consented authorization details the exchange may carry
			// (RFC 9396 section 6: requested entries must be a subset).
			AuthorizationDetails: []*tokenv1.AuthorizationDetail{
				{Type: "mcp_tools", Locations: []string{"http://127.0.0.1:8085"}, Actions: []string{"timestamp:read"}},
			},
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
						NotBefore: 1,
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
			name: "authorization_details are carried verbatim (mocked processing)",
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
					AuthorizationDetails: []*tokenv1.AuthorizationDetail{
						{Type: "mcp_tools", Locations: []string{"http://127.0.0.1:8085"}, Actions: []string{"timestamp:read"}},
					},
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
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo").Return(activeSubjectToken(), nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("xtU.GvmXVrPVNqSnHjpZbEarIqOPAlfXfQpM", nil)
				tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(nil)
			},
			wantErr: false,
			want: &flowv1.TokenResponse{
				Issuer:          "http://127.0.0.1:8080",
				IssuedTokenType: new(oidc.TokenExchangeAccessTokenType),
				AuthorizationDetails: []*tokenv1.AuthorizationDetail{
					{Type: "mcp_tools", Locations: []string{"http://127.0.0.1:8085"}, Actions: []string{"timestamp:read"}},
				},
				AccessToken: &tokenv1.Token{
					Value:     "xtU.GvmXVrPVNqSnHjpZbEarIqOPAlfXfQpM",
					TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						ClientId:  "s6BhdRkqt3",
						Subject:   "user-1",
						Scope:     "openid profile email",
						IssuedAt:  1,
						NotBefore: 1,
						ExpiresAt: 61,
						AuthorizationDetails: []*tokenv1.AuthorizationDetail{
							{Type: "mcp_tools", Locations: []string{"http://127.0.0.1:8085"}, Actions: []string{"timestamp:read"}},
						},
					},
				},
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
						NotBefore: 1,
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

// staticDelegationPolicy is a map-backed DelegationPolicy test double.
type staticDelegationPolicy map[string][]string

func (p staticDelegationPolicy) MayRedelegate(_ context.Context, resourceURI string) ([]string, error) {
	return p[resourceURI], nil
}

// erroringDelegationPolicy fails closed for any resource.
type erroringDelegationPolicy struct{}

func (erroringDelegationPolicy) MayRedelegate(_ context.Context, _ string) ([]string, error) {
	return nil, fmt.Errorf("policy backend unavailable")
}

// hop1SubjectToken is the user's DPoP-bound token (T1 shape): consented to
// both MCP-server and backend-resource tool details, key-bound to the
// agent's proof key.
func hop1SubjectToken() *tokenv1.Token {
	st := activeSubjectToken()
	st.Confirmation = &tokenv1.TokenConfirmation{Jkt: "agent-key-jkt"}
	st.Metadata.AuthorizationDetails = []*tokenv1.AuthorizationDetail{
		{Type: "mcp_tools", Locations: []string{"http://127.0.0.1:8090"}, Actions: []string{"get_signed_timestamp"}},
		{Type: "mcp_tools", Locations: []string{"http://127.0.0.1:8085"}, Actions: []string{"timestamp:read"}},
	}
	return st
}

// hop2SubjectToken is the agent-exchanged token (T3 shape): audience
// retargeted to the MCP server, may_act listing the MCP server client,
// act chain recording the agent, still key-bound to the agent's key.
func hop2SubjectToken() *tokenv1.Token {
	return &tokenv1.Token{
		Value:        "t3.example",
		TokenType:    tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
		Status:       tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
		MayAct:       []*tokenv1.Actor{{Subject: "mcp-client"}},
		Confirmation: &tokenv1.TokenConfirmation{Jkt: "agent-key-jkt"},
		Actor:        []*tokenv1.Actor{{Subject: "s6BhdRkqt3"}},
		Metadata: &tokenv1.TokenMeta{
			Issuer:    "http://127.0.0.1:8080",
			ClientId:  "s6BhdRkqt3",
			Subject:   "user-1",
			Scope:     "openid timestamp:read",
			ExpiresAt: 3601,
			Audience:  "http://127.0.0.1:8090",
			AuthorizationDetails: []*tokenv1.AuthorizationDetail{
				{Type: "mcp_tools", Locations: []string{"http://127.0.0.1:8090"}, Actions: []string{"get_signed_timestamp"}},
				{Type: "mcp_tools", Locations: []string{"http://127.0.0.1:8085"}, Actions: []string{"timestamp:read"}},
			},
		},
	}
}

// mcpActorToken is the MCP server's client_credentials token (subject =
// its client identity).
func mcpActorToken() *tokenv1.Token {
	return &tokenv1.Token{
		Value:     "mcp-cc.example",
		TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
		Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
		Metadata: &tokenv1.TokenMeta{
			Issuer:    "http://127.0.0.1:8080",
			ClientId:  "mcp-client",
			Subject:   "mcp-client",
			ExpiresAt: 3601,
		},
	}
}

// Test_service_tokenExchangeDelegation covers the delegated re-binding
// posture: may_act issuance from the delegation policy, authorized key
// re-binding with proof of possession, and the fail-closed thief paths.
func Test_service_tokenExchangeDelegation(t *testing.T) {
	tests := []struct {
		name    string
		client  *clientv1.Client
		req     *flowv1.TokenRequest
		policy  DelegationPolicy
		prepare func(*storagemock.MockToken, *storagemock.MockResourceReader, *tokenmock.MockGenerator)
		want    *flowv1.TokenResponse
		wantErr bool
	}{
		{
			name: "hop-1 exchange mints may_act from the delegation policy",
			client: &clientv1.Client{
				ClientId:   "s6BhdRkqt3",
				GrantTypes: []string{oidc.GrantTypeTokenExchange},
			},
			req: &flowv1.TokenRequest{
				Issuer:            "http://127.0.0.1:8080",
				Client:            &clientv1.Client{ClientId: "s6BhdRkqt3"},
				Audience:          new("http://127.0.0.1:8090"),
				TokenConfirmation: &tokenv1.TokenConfirmation{Jkt: "agent-key-jkt"},
				GrantType:         oidc.GrantTypeTokenExchange,
				Grant: &flowv1.TokenRequest_TokenExchange{
					TokenExchange: &flowv1.GrantTokenExchange{
						SubjectToken:     "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
						SubjectTokenType: oidc.TokenExchangeAccessTokenType,
						ActorToken:       new("agent-cc.example"),
						ActorTokenType:   new(oidc.TokenExchangeAccessTokenType),
					},
				},
				AuthorizationDetails: []*tokenv1.AuthorizationDetail{
					{Type: "mcp_tools", Locations: []string{"http://127.0.0.1:8090"}, Actions: []string{"get_signed_timestamp"}},
					{Type: "mcp_tools", Locations: []string{"http://127.0.0.1:8085"}, Actions: []string{"timestamp:read"}},
				},
			},
			policy: staticDelegationPolicy{"http://127.0.0.1:8090": {"mcp-client"}},
			prepare: func(tokens *storagemock.MockToken, resources *storagemock.MockResourceReader, at *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo").Return(hop1SubjectToken(), nil)
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "agent-cc.example").Return(&tokenv1.Token{
					Value:     "agent-cc.example",
					TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						ClientId:  "s6BhdRkqt3",
						Subject:   "s6BhdRkqt3",
						ExpiresAt: 3601,
					},
				}, nil)
				resources.EXPECT().GetByURI(gomock.Any(), "http://127.0.0.1:8090").Return(&resourcev1.Resource{Urn: "http://127.0.0.1:8090"}, nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("t3.example", nil)
				tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(nil)
			},
			want: &flowv1.TokenResponse{
				Issuer:          "http://127.0.0.1:8080",
				IssuedTokenType: new(oidc.TokenExchangeAccessTokenType),
				AccessToken: &tokenv1.Token{
					Value:        "t3.example",
					TokenType:    tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:       tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
					MayAct:       []*tokenv1.Actor{{Subject: "mcp-client"}},
					Confirmation: &tokenv1.TokenConfirmation{Jkt: "agent-key-jkt"},
					Actor:        []*tokenv1.Actor{{Subject: "s6BhdRkqt3"}},
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						Subject:   "user-1",
						ClientId:  "s6BhdRkqt3",
						Scope:     "openid profile email",
						IssuedAt:  1,
						NotBefore: 1,
						ExpiresAt: 61,
						Audience:  "http://127.0.0.1:8090",
						AuthorizationDetails: []*tokenv1.AuthorizationDetail{
							{Type: "mcp_tools", Locations: []string{"http://127.0.0.1:8090"}, Actions: []string{"get_signed_timestamp"}},
							{Type: "mcp_tools", Locations: []string{"http://127.0.0.1:8085"}, Actions: []string{"timestamp:read"}},
						},
					},
				},
				AuthorizationDetails: []*tokenv1.AuthorizationDetail{
					{Type: "mcp_tools", Locations: []string{"http://127.0.0.1:8090"}, Actions: []string{"get_signed_timestamp"}},
					{Type: "mcp_tools", Locations: []string{"http://127.0.0.1:8085"}, Actions: []string{"timestamp:read"}},
				},
			},
		},
		{
			name: "hop-2 may_act client re-binds confirmation to its own proof key",
			client: &clientv1.Client{
				ClientId:   "mcp-client",
				GrantTypes: []string{oidc.GrantTypeTokenExchange},
			},
			req: &flowv1.TokenRequest{
				Issuer:            "http://127.0.0.1:8080",
				Client:            &clientv1.Client{ClientId: "mcp-client"},
				Audience:          new("http://127.0.0.1:8085"),
				TokenConfirmation: &tokenv1.TokenConfirmation{Jkt: "mcp-key-jkt"},
				GrantType:         oidc.GrantTypeTokenExchange,
				Grant: &flowv1.TokenRequest_TokenExchange{
					TokenExchange: &flowv1.GrantTokenExchange{
						SubjectToken:     "t3.example",
						SubjectTokenType: oidc.TokenExchangeAccessTokenType,
						ActorToken:       new("mcp-cc.example"),
						ActorTokenType:   new(oidc.TokenExchangeAccessTokenType),
					},
				},
				AuthorizationDetails: []*tokenv1.AuthorizationDetail{
					{Type: "mcp_tools", Locations: []string{"http://127.0.0.1:8085"}, Actions: []string{"timestamp:read"}},
				},
			},
			policy: staticDelegationPolicy{"http://127.0.0.1:8090": {"mcp-client"}},
			prepare: func(tokens *storagemock.MockToken, resources *storagemock.MockResourceReader, at *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "t3.example").Return(hop2SubjectToken(), nil)
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "mcp-cc.example").Return(mcpActorToken(), nil)
				resources.EXPECT().GetByURI(gomock.Any(), "http://127.0.0.1:8085").Return(&resourcev1.Resource{Urn: "http://127.0.0.1:8085"}, nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("t5.example", nil)
				tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(nil)
			},
			want: &flowv1.TokenResponse{
				Issuer:          "http://127.0.0.1:8080",
				IssuedTokenType: new(oidc.TokenExchangeAccessTokenType),
				AccessToken: &tokenv1.Token{
					Value:        "t5.example",
					TokenType:    tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:       tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Confirmation: &tokenv1.TokenConfirmation{Jkt: "mcp-key-jkt"},
					Actor: []*tokenv1.Actor{
						{Subject: "mcp-client"},
						{Subject: "s6BhdRkqt3"},
					},
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						Subject:   "user-1",
						ClientId:  "mcp-client",
						Scope:     "openid timestamp:read",
						IssuedAt:  1,
						NotBefore: 1,
						ExpiresAt: 61,
						Audience:  "http://127.0.0.1:8085",
						AuthorizationDetails: []*tokenv1.AuthorizationDetail{
							{Type: "mcp_tools", Locations: []string{"http://127.0.0.1:8085"}, Actions: []string{"timestamp:read"}},
						},
					},
				},
				AuthorizationDetails: []*tokenv1.AuthorizationDetail{
					{Type: "mcp_tools", Locations: []string{"http://127.0.0.1:8085"}, Actions: []string{"timestamp:read"}},
				},
			},
		},
		{
			name: "thief client outside may_act fails the strict confirmation path",
			client: &clientv1.Client{
				ClientId:   "attacker-client",
				GrantTypes: []string{oidc.GrantTypeTokenExchange},
			},
			req: &flowv1.TokenRequest{
				Issuer:            "http://127.0.0.1:8080",
				Client:            &clientv1.Client{ClientId: "attacker-client"},
				Audience:          new("http://127.0.0.1:8085"),
				TokenConfirmation: &tokenv1.TokenConfirmation{Jkt: "attacker-key-jkt"},
				GrantType:         oidc.GrantTypeTokenExchange,
				Grant: &flowv1.TokenRequest_TokenExchange{
					TokenExchange: &flowv1.GrantTokenExchange{
						SubjectToken:     "t3.example",
						SubjectTokenType: oidc.TokenExchangeAccessTokenType,
						ActorToken:       new("mcp-cc.example"),
						ActorTokenType:   new(oidc.TokenExchangeAccessTokenType),
					},
				},
			},
			policy: nil,
			prepare: func(tokens *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "t3.example").Return(hop2SubjectToken(), nil)
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "mcp-cc.example").Return(mcpActorToken(), nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "may_act re-delegation without DPoP proof fails closed",
			client: &clientv1.Client{
				ClientId:   "mcp-client",
				GrantTypes: []string{oidc.GrantTypeTokenExchange},
			},
			req: &flowv1.TokenRequest{
				Issuer:    "http://127.0.0.1:8080",
				Client:    &clientv1.Client{ClientId: "mcp-client"},
				Audience:  new("http://127.0.0.1:8085"),
				GrantType: oidc.GrantTypeTokenExchange,
				Grant: &flowv1.TokenRequest_TokenExchange{
					TokenExchange: &flowv1.GrantTokenExchange{
						SubjectToken:     "t3.example",
						SubjectTokenType: oidc.TokenExchangeAccessTokenType,
						ActorToken:       new("mcp-cc.example"),
						ActorTokenType:   new(oidc.TokenExchangeAccessTokenType),
					},
				},
			},
			policy: nil,
			prepare: func(tokens *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "t3.example").Return(hop2SubjectToken(), nil)
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "mcp-cc.example").Return(mcpActorToken(), nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "delegation policy error fails closed with no token minted",
			client: &clientv1.Client{
				ClientId:   "s6BhdRkqt3",
				GrantTypes: []string{oidc.GrantTypeTokenExchange},
			},
			req: &flowv1.TokenRequest{
				Issuer:    "http://127.0.0.1:8080",
				Client:    &clientv1.Client{ClientId: "s6BhdRkqt3"},
				Audience:  new("http://127.0.0.1:8090"),
				GrantType: oidc.GrantTypeTokenExchange,
				Grant: &flowv1.TokenRequest_TokenExchange{
					TokenExchange: &flowv1.GrantTokenExchange{
						SubjectToken:     "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
						SubjectTokenType: oidc.TokenExchangeAccessTokenType,
					},
				},
			},
			policy: erroringDelegationPolicy{},
			prepare: func(tokens *storagemock.MockToken, resources *storagemock.MockResourceReader, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				tokens.EXPECT().GetByValue(gomock.Any(), "http://127.0.0.1:8080", "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo").Return(activeSubjectToken(), nil)
				resources.EXPECT().GetByURI(gomock.Any(), "http://127.0.0.1:8090").Return(&resourcev1.Resource{Urn: "http://127.0.0.1:8090"}, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidTarget().Build(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			tokens := storagemock.NewMockToken(ctrl)
			resources := storagemock.NewMockResourceReader(ctrl)
			accessTokens := tokenmock.NewMockGenerator(ctrl)

			if tt.prepare != nil {
				tt.prepare(tokens, resources, accessTokens)
			}

			s := &service{
				tokens:           tokens,
				resources:        resources,
				accessTokenGen:   accessTokens,
				delegationPolicy: tt.policy,
			}
			got, err := s.tokenExchange(context.Background(), tt.client, tt.req)
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
