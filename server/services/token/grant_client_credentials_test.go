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

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/rfcerrors"
	tokenmock "zntr.io/solid/sdk/token/mock"
	storagemock "zntr.io/solid/server/storage/mock"
)

func Test_service_clientCredentials(t *testing.T) {
	type args struct {
		ctx    context.Context
		client *clientv1.Client
		req    *flowv1.TokenRequest
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*storagemock.MockToken, *tokenmock.MockGenerator)
		want    *flowv1.TokenResponse
		wantErr bool
	}{
		{
			name: "nil client",
			args: args{
				ctx: context.Background(),
				req: &flowv1.TokenRequest{
					GrantType: oidc.GrantTypeClientCredentials,
					Grant: &flowv1.TokenRequest_ClientCredentials{
						ClientCredentials: &flowv1.GrantClientCredentials{},
					},
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "nil request",
			args: args{
				ctx:    context.Background(),
				client: &clientv1.Client{},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "nil grant",
			args: args{
				ctx:    context.Background(),
				client: &clientv1.Client{},
				req:    &flowv1.TokenRequest{},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "empty issuer",
			args: args{
				ctx:    context.Background(),
				client: &clientv1.Client{},
				req: &flowv1.TokenRequest{
					Issuer: "",
					Grant: &flowv1.TokenRequest_ClientCredentials{
						ClientCredentials: &flowv1.GrantClientCredentials{},
					},
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "invalid issuer",
			args: args{
				ctx:    context.Background(),
				client: &clientv1.Client{},
				req: &flowv1.TokenRequest{
					Issuer: "123456",
					Grant: &flowv1.TokenRequest_ClientCredentials{
						ClientCredentials: &flowv1.GrantClientCredentials{},
					},
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "unsupported client type",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientType:   clientv1.ClientType_CLIENT_TYPE_PUBLIC,
					GrantTypes:   []string{oidc.GrantTypeAuthorizationCode},
					RedirectUris: []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeClientCredentials,
					Grant: &flowv1.TokenRequest_ClientCredentials{
						ClientCredentials: &flowv1.GrantClientCredentials{},
					},
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidClient().Build(),
			},
		},
		{
			name: "client not support grant_type",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientType:   clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
					GrantTypes:   []string{oidc.GrantTypeAuthorizationCode},
					RedirectUris: []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeClientCredentials,
					Grant: &flowv1.TokenRequest_ClientCredentials{
						ClientCredentials: &flowv1.GrantClientCredentials{},
					},
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.UnsupportedGrantType().Build(),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "openid: access token generation error",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientType: clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
					GrantTypes: []string{oidc.GrantTypeClientCredentials},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeClientCredentials,
					Grant: &flowv1.TokenRequest_ClientCredentials{
						ClientCredentials: &flowv1.GrantClientCredentials{},
					},
				},
			},
			prepare: func(tokens *storagemock.MockToken, at *tokenmock.MockGenerator) {
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("", fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "openid: empty access token generation",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientType: clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
					GrantTypes: []string{oidc.GrantTypeClientCredentials},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeClientCredentials,
					Grant: &flowv1.TokenRequest_ClientCredentials{
						ClientCredentials: &flowv1.GrantClientCredentials{},
					},
				},
			},
			prepare: func(tokens *storagemock.MockToken, at *tokenmock.MockGenerator) {
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("", nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "openid: access token storage error",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientType: clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
					GrantTypes: []string{oidc.GrantTypeClientCredentials},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeClientCredentials,
					Grant: &flowv1.TokenRequest_ClientCredentials{
						ClientCredentials: &flowv1.GrantClientCredentials{},
					},
				},
			},
			prepare: func(tokens *storagemock.MockToken, at *tokenmock.MockGenerator) {
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo", nil)
				tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "valid",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientType: clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
					GrantTypes: []string{oidc.GrantTypeClientCredentials},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeClientCredentials,
					Grant: &flowv1.TokenRequest_ClientCredentials{
						ClientCredentials: &flowv1.GrantClientCredentials{},
					},
				},
			},
			prepare: func(tokens *storagemock.MockToken, at *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Arm mocks
			accessTokens := tokenmock.NewMockGenerator(ctrl)
			tokens := storagemock.NewMockToken(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(tokens, accessTokens)
			}

			s := &service{
				tokens:         tokens,
				accessTokenGen: accessTokens,
			}
			got, err := s.clientCredentials(tt.args.ctx, tt.args.client, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("service.clientCredentials() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
				t.Errorf("service.clientCredentials() res = %s", diff)
			}
		})
	}
}
