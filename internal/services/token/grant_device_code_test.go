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
	generatormock "zntr.io/solid/pkg/generator/mock"
	"zntr.io/solid/pkg/rfcerrors"
	"zntr.io/solid/pkg/storage"
	storagemock "zntr.io/solid/pkg/storage/mock"

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
)

func Test_service_deviceCode(t *testing.T) {
	type args struct {
		ctx    context.Context
		client *corev1.Client
		req    *corev1.TokenRequest
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*storagemock.MockDeviceCodeSession, *storagemock.MockToken, *generatormock.MockToken)
		want    *corev1.TokenResponse
		wantErr bool
	}{
		{
			name: "nil client",
			args: args{
				ctx: context.Background(),
				req: &corev1.TokenRequest{
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &corev1.TokenRequest_DeviceCode{
						DeviceCode: &corev1.GrantDeviceCode{},
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
					GrantType: oidc.GrantTypeDeviceCode,
				},
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
					Issuer:    "",
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &corev1.TokenRequest_DeviceCode{
						DeviceCode: &corev1.GrantDeviceCode{},
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
					Issuer:    "foo",
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &corev1.TokenRequest_DeviceCode{
						DeviceCode: &corev1.GrantDeviceCode{},
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
					GrantTypes: []string{oidc.GrantTypeAuthorizationCode},
				},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &corev1.TokenRequest_DeviceCode{
						DeviceCode: &corev1.GrantDeviceCode{},
					},
				},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.UnsupportedGrantType(""),
			},
		},
		{
			name: "device_code is blank",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
				},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &corev1.TokenRequest_DeviceCode{
						DeviceCode: &corev1.GrantDeviceCode{
							DeviceCode: "",
						},
					},
				},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidRequest(""),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "device_code not found",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
				},
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
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *generatormock.MockToken) {
				sessions.EXPECT().Get(gomock.Any(), "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(nil, storage.ErrNotFound)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidRequest(""),
			},
		},
		{
			name: "device_code storage error",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
				},
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
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *generatormock.MockToken) {
				sessions.EXPECT().Get(gomock.Any(), "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(nil, fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError(""),
			},
		},
		{
			name: "retrieved nil session",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
				},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "foo",
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
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *generatormock.MockToken) {
				sessions.EXPECT().Get(gomock.Any(), "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(nil, nil)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError(""),
			},
		},
		{
			name: "retrieved session with nil request",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
				},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "foo",
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
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *generatormock.MockToken) {
				sessions.EXPECT().Get(gomock.Any(), "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&corev1.DeviceCodeSession{}, nil)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError(""),
			},
		},
		{
			name: "retrieved session with nil client",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
				},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "foo",
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
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *generatormock.MockToken) {
				sessions.EXPECT().Get(gomock.Any(), "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&corev1.DeviceCodeSession{
					Request: &corev1.DeviceAuthorizationRequest{},
				}, nil)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError(""),
			},
		},
		{
			name: "client_id mismatch",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
				},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "foo",
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
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *generatormock.MockToken) {
				sessions.EXPECT().Get(gomock.Any(), "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&corev1.DeviceCodeSession{
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &corev1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
				}, nil)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidRequest(""),
			},
		},
		{
			name: "session is expired",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
					ClientId:   "s6BhdRkqt3",
				},
				req: &corev1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &corev1.TokenRequest_DeviceCode{
						DeviceCode: &corev1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *generatormock.MockToken) {
				timeFunc = func() time.Time { return time.Unix(10, 0) }
				sessions.EXPECT().Get(gomock.Any(), "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&corev1.DeviceCodeSession{
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &corev1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: 0,
				}, nil)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.TokenExpired(),
			},
		},
		{
			name: "authorization pending",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
					ClientId:   "s6BhdRkqt3",
				},
				req: &corev1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &corev1.TokenRequest_DeviceCode{
						DeviceCode: &corev1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *generatormock.MockToken) {
				timeFunc = func() time.Time { return time.Unix(10, 0) }
				sessions.EXPECT().Get(gomock.Any(), "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&corev1.DeviceCodeSession{
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &corev1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: 200,
					Status:    corev1.DeviceCodeStatus_DEVICE_CODE_STATUS_AUTHORIZATION_PENDING,
				}, nil)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.AuthorizationPending(),
			},
		},
		{
			name: "session invalid status",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
					ClientId:   "s6BhdRkqt3",
				},
				req: &corev1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &corev1.TokenRequest_DeviceCode{
						DeviceCode: &corev1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *generatormock.MockToken) {
				timeFunc = func() time.Time { return time.Unix(10, 0) }
				sessions.EXPECT().Get(gomock.Any(), "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&corev1.DeviceCodeSession{
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &corev1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: 200,
					Status:    corev1.DeviceCodeStatus_DEVICE_CODE_STATUS_INVALID,
				}, nil)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidToken(),
			},
		},
		{
			name: "session validated with at generation error",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
					ClientId:   "s6BhdRkqt3",
				},
				req: &corev1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &corev1.TokenRequest_DeviceCode{
						DeviceCode: &corev1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, at *generatormock.MockToken) {
				timeFunc = func() time.Time { return time.Unix(10, 0) }
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
				at.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("", fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError(""),
			},
		},
		{
			name: "session validated with at storage error",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
					ClientId:   "s6BhdRkqt3",
				},
				req: &corev1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &corev1.TokenRequest_DeviceCode{
						DeviceCode: &corev1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, tokens *storagemock.MockToken, at *generatormock.MockToken) {
				timeFunc = func() time.Time { return time.Unix(10, 0) }
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
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
					ClientId:   "s6BhdRkqt3",
				},
				req: &corev1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &corev1.TokenRequest_DeviceCode{
						DeviceCode: &corev1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, tokens *storagemock.MockToken, at *generatormock.MockToken) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Arm mocks
			sessions := storagemock.NewMockDeviceCodeSession(ctrl)
			accessTokens := generatormock.NewMockToken(ctrl)
			tokens := storagemock.NewMockToken(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(sessions, tokens, accessTokens)
			}

			s := &service{
				deviceCodeSessions: sessions,
				tokens:             tokens,
				tokenGen:           accessTokens,
			}
			got, err := s.deviceCode(tt.args.ctx, tt.args.client, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("service.deviceCode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
				t.Errorf("service.deviceCode() res = %s", diff)
			}
		})
	}
}
