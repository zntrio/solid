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
	generatormock "zntr.io/solid/pkg/sdk/generator/mock"
	"zntr.io/solid/pkg/sdk/rfcerrors"
	storagemock "zntr.io/solid/pkg/server/storage/mock"

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
)

func Test_service_clientCredentials(t *testing.T) {
	type args struct {
		ctx    context.Context
		client *corev1.Client
		req    *corev1.TokenRequest
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*storagemock.MockToken, *generatormock.MockToken)
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
				Error: rfcerrors.ServerError(""),
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
				Error: rfcerrors.ServerError(""),
			},
		},
		{
			name: "nil grant",
			args: args{
				ctx:    context.Background(),
				client: &corev1.Client{},
				req:    &corev1.TokenRequest{},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError(""),
			},
		},
		{
			name: "empty issuer",
			args: args{
				ctx:    context.Background(),
				client: &corev1.Client{},
				req: &corev1.TokenRequest{
					Issuer: "",
					Grant: &corev1.TokenRequest_ClientCredentials{
						ClientCredentials: &corev1.GrantClientCredentials{},
					},
				},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError(""),
			},
		},
		{
			name: "invalid issuer",
			args: args{
				ctx:    context.Background(),
				client: &corev1.Client{},
				req: &corev1.TokenRequest{
					Issuer: "123456",
					Grant: &corev1.TokenRequest_ClientCredentials{
						ClientCredentials: &corev1.GrantClientCredentials{},
					},
				},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError(""),
			},
		},
		{
			name: "client not support grant_type",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes:   []string{oidc.GrantTypeAuthorizationCode},
					RedirectUris: []string{"https://client.example.org/cb"},
				},
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
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.UnsupportedGrantType(""),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "openid: access token generation error",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeClientCredentials},
				},
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
			prepare: func(tokens *storagemock.MockToken, at *generatormock.MockToken) {
				at.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("", fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError(""),
			},
		},
		{
			name: "openid: empty access token generation",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeClientCredentials},
				},
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
			prepare: func(tokens *storagemock.MockToken, at *generatormock.MockToken) {
				at.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("", nil)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError(""),
			},
		},
		{
			name: "openid: access token storage error",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeClientCredentials},
				},
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
			prepare: func(tokens *storagemock.MockToken, at *generatormock.MockToken) {
				at.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo", nil)
				tokens.EXPECT().Create(gomock.Any(), gomock.Any()).Return(fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError(""),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "valid",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeClientCredentials},
				},
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
			prepare: func(tokens *storagemock.MockToken, at *generatormock.MockToken) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Arm mocks
			accessTokens := generatormock.NewMockToken(ctrl)
			idTokens := generatormock.NewMockIdentity(ctrl)
			tokens := storagemock.NewMockToken(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(tokens, accessTokens)
			}

			s := &service{
				tokens:   tokens,
				tokenGen: accessTokens,
				idGen:    idTokens,
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
