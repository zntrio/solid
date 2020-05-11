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
	"go.zenithar.org/solid/api/oidc"
	"go.zenithar.org/solid/pkg/rfcerrors"
	storagemock "go.zenithar.org/solid/pkg/storage/mock"
	tokenmock "go.zenithar.org/solid/pkg/token/mock"

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
		prepare func(*storagemock.MockSession, *tokenmock.MockAccessTokenGenerator)
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
				req: &corev1.TokenRequest{
					GrantType: oidc.GrantTypeAuthorizationCode,
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
			name: "openid: generate access token error",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeClientCredentials},
				},
				req: &corev1.TokenRequest{
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeClientCredentials,
					Grant: &corev1.TokenRequest_ClientCredentials{
						ClientCredentials: &corev1.GrantClientCredentials{},
					},
				},
			},
			prepare: func(sessions *storagemock.MockSession, at *tokenmock.MockAccessTokenGenerator) {
				at.EXPECT().Generate(gomock.Any()).Return("", fmt.Errorf("foo"))
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
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeClientCredentials,
					Grant: &corev1.TokenRequest_ClientCredentials{
						ClientCredentials: &corev1.GrantClientCredentials{},
					},
				},
			},
			prepare: func(sessions *storagemock.MockSession, at *tokenmock.MockAccessTokenGenerator) {
				at.EXPECT().Generate(gomock.Any()).Return("1/fFAGRNJru1FTz70BzhT3Zg", nil)
			},
			wantErr: false,
			want: &corev1.TokenResponse{
				Error: nil,
				Openid: &corev1.OpenIDToken{
					AccessToken: "1/fFAGRNJru1FTz70BzhT3Zg",
					ExpiresIn:   3600,
					TokenType:   "Bearer",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Arm mocks
			sessions := storagemock.NewMockSession(ctrl)
			accessTokens := tokenmock.NewMockAccessTokenGenerator(ctrl)
			idTokens := tokenmock.NewMockIDTokenGenerator(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(sessions, accessTokens)
			}

			s := &service{
				sessions:             sessions,
				accessTokenGenerator: accessTokens,
				idTokenGenerator:     idTokens,
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
