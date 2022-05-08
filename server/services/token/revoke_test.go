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

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"

	corev1 "zntr.io/solid/api/oidc/core/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/rfcerrors"
	tokenmock "zntr.io/solid/sdk/token/mock"
	"zntr.io/solid/server/storage"
	storagemock "zntr.io/solid/server/storage/mock"
)

func Test_service_Revoke(t *testing.T) {
	type args struct {
		ctx context.Context
		req *corev1.TokenRevocationRequest
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*storagemock.MockClientReader, *storagemock.MockToken)
		want    *corev1.TokenRevocationResponse
		wantErr bool
	}{
		{
			name: "nil request",
			args: args{
				ctx: context.Background(),
			},
			wantErr: true,
			want: &corev1.TokenRevocationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "nil client authentication",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRevocationRequest{},
			},
			wantErr: true,
			want: &corev1.TokenRevocationResponse{
				Error: rfcerrors.InvalidClient().Build(),
			},
		},
		{
			name: "nil token",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRevocationRequest{
					Client: &corev1.Client{},
				},
			},
			wantErr: true,
			want: &corev1.TokenRevocationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty token",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRevocationRequest{
					Client: &corev1.Client{},
					Token:  "",
				},
			},
			wantErr: true,
			want: &corev1.TokenRevocationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "client not found",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRevocationRequest{
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Token: "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
				},
			},
			prepare: func(clients *storagemock.MockClientReader, tokens *storagemock.MockToken) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(nil, storage.ErrNotFound)
			},
			wantErr: true,
			want: &corev1.TokenRevocationResponse{
				Error: rfcerrors.InvalidClient().Build(),
			},
		},
		{
			name: "client storage error",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRevocationRequest{
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Token: "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
				},
			},
			prepare: func(clients *storagemock.MockClientReader, tokens *storagemock.MockToken) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(nil, fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.TokenRevocationResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "token not found",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRevocationRequest{
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Token: "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
				},
			},
			prepare: func(clients *storagemock.MockClientReader, tokens *storagemock.MockToken) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&corev1.Client{
					GrantTypes: []string{oidc.GrantTypeClientCredentials},
				}, nil)
				tokens.EXPECT().GetByValue(gomock.Any(), "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo").Return(nil, storage.ErrNotFound)
			},
			wantErr: true,
			want:    &corev1.TokenRevocationResponse{},
		},
		{
			name: "token storage error",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRevocationRequest{
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Token: "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
				},
			},
			prepare: func(clients *storagemock.MockClientReader, tokens *storagemock.MockToken) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&corev1.Client{
					GrantTypes: []string{oidc.GrantTypeClientCredentials},
				}, nil)
				tokens.EXPECT().GetByValue(gomock.Any(), "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo").Return(nil, fmt.Errorf("foo"))
			},
			wantErr: true,
			want:    &corev1.TokenRevocationResponse{},
		},
		{
			name: "revoke storage error",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRevocationRequest{
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Token: "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
				},
			},
			prepare: func(clients *storagemock.MockClientReader, tokens *storagemock.MockToken) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&corev1.Client{}, nil)
				tokens.EXPECT().GetByValue(gomock.Any(), "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo").Return(&corev1.Token{
					Status:  corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
					TokenId: "123456789",
					Value:   "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
				}, nil)
				tokens.EXPECT().Revoke(gomock.Any(), "123456789").Return(fmt.Errorf("foo"))
			},
			wantErr: true,
			want:    &corev1.TokenRevocationResponse{},
		},
		// ---------------------------------------------------------------------
		{
			name: "valid",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRevocationRequest{
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Token: "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
				},
			},
			prepare: func(clients *storagemock.MockClientReader, tokens *storagemock.MockToken) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&corev1.Client{}, nil)
				tokens.EXPECT().GetByValue(gomock.Any(), "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo").Return(&corev1.Token{
					Status:  corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
					TokenId: "123456789",
					Value:   "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
				}, nil)
				tokens.EXPECT().Revoke(gomock.Any(), "123456789").Return(nil)
			},
			wantErr: false,
			want:    &corev1.TokenRevocationResponse{},
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
			authorizationRequests := storagemock.NewMockAuthorizationRequest(ctrl)
			authorizationCodeSessions := storagemock.NewMockAuthorizationCodeSession(ctrl)
			deviceCodeSessions := storagemock.NewMockDeviceCodeSession(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(clients, tokens)
			}

			// instantiate service
			underTest := New(accessTokens, refreshTokens, clients, authorizationRequests, authorizationCodeSessions, deviceCodeSessions, tokens, nil)

			got, err := underTest.Revoke(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("service.Revoke() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
				t.Errorf("service.Revoke() res = %s", diff)
			}
		})
	}
}
