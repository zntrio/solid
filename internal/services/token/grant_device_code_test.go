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
	"google.golang.org/protobuf/types/known/wrapperspb"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/api/oidc"
	"zntr.io/solid/pkg/sdk/rfcerrors"
	tokenmock "zntr.io/solid/pkg/sdk/token/mock"
	"zntr.io/solid/pkg/server/storage"
	storagemock "zntr.io/solid/pkg/server/storage/mock"
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
		prepare func(*storagemock.MockDeviceCodeSession, *storagemock.MockToken, *tokenmock.MockGenerator, *tokenmock.MockGenerator)
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
					GrantType: oidc.GrantTypeDeviceCode,
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
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &corev1.TokenRequest_DeviceCode{
						DeviceCode: &corev1.GrantDeviceCode{},
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
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &corev1.TokenRequest_DeviceCode{
						DeviceCode: &corev1.GrantDeviceCode{},
					},
				},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
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
				Error: rfcerrors.UnsupportedGrantType().Build(),
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
				Error: rfcerrors.InvalidRequest().Build(),
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
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(nil, storage.ErrNotFound)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidRequest().Build(),
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
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(nil, fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
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
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(nil, nil)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
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
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&corev1.DeviceCodeSession{}, nil)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
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
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&corev1.DeviceCodeSession{
					Request: &corev1.DeviceAuthorizationRequest{},
				}, nil)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
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
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&corev1.DeviceCodeSession{
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
				Error: rfcerrors.InvalidRequest().Build(),
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
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(10, 0) }
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&corev1.DeviceCodeSession{
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
				Error: rfcerrors.TokenExpired().Build(),
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
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(10, 0) }
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&corev1.DeviceCodeSession{
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
				Error: rfcerrors.AuthorizationPending().Build(),
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
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(10, 0) }
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&corev1.DeviceCodeSession{
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
				Error: rfcerrors.InvalidToken().Build(),
			},
		},
		{
			name: "session validated with no subject error",
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
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(10, 0) }
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&corev1.DeviceCodeSession{
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &corev1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: 200,
					Status:    corev1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED,
					Subject:   "",
				}, nil)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
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
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(10, 0) }
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&corev1.DeviceCodeSession{
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &corev1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: 200,
					Status:    corev1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED,
					Subject:   "user-1",
				}, nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("", fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
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
			prepare: func(sessions *storagemock.MockDeviceCodeSession, tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(10, 0) }
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&corev1.DeviceCodeSession{
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &corev1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: 200,
					Status:    corev1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED,
					Subject:   "user1",
				}, nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo", nil)
				tokens.EXPECT().Create(gomock.Any(), gomock.Any()).Return(fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "refresh token storage error",
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
					Scope: &wrapperspb.StringValue{
						Value: "offline_access",
					},
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&corev1.DeviceCodeSession{
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &corev1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
						Scope: &wrapperspb.StringValue{
							Value: "offline_access",
						},
					},
					ExpiresAt: 200,
					Status:    corev1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED,
					Subject:   "user1",
					Scope:     "offline_access",
				}, nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo", nil)
				atSave := tokens.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
				rt.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi", nil)
				tokens.EXPECT().Create(gomock.Any(), gomock.Any()).Return(fmt.Errorf("error")).After(atSave)
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
			prepare: func(sessions *storagemock.MockDeviceCodeSession, tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&corev1.DeviceCodeSession{
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &corev1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: 200,
					Status:    corev1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED,
					Subject:   "user1",
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
						Subject:   "user1",
					},
					Value: "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
				},
			},
		},
		{
			name: "valid - offline_access",
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
					Scope: &wrapperspb.StringValue{
						Value: "offline_access",
					},
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&corev1.DeviceCodeSession{
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &corev1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
						Scope: &wrapperspb.StringValue{
							Value: "offline_access",
						},
					},
					ExpiresAt: 200,
					Status:    corev1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED,
					Subject:   "user1",
					Scope:     "offline_access",
				}, nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo", nil)
				atSave := tokens.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
				rt.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi", nil)
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
						Scope:     "offline_access",
						IssuedAt:  1,
						ExpiresAt: 3601,
						ClientId:  "s6BhdRkqt3",
						Subject:   "user1",
					},
					Value: "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
				},
				RefreshToken: &corev1.Token{
					TokenType: corev1.TokenType_TOKEN_TYPE_REFRESH_TOKEN,
					Status:    corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &corev1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						Scope:     "offline_access",
						IssuedAt:  1,
						ExpiresAt: 604801,
						ClientId:  "s6BhdRkqt3",
						Subject:   "user1",
					},
					Value: "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi",
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
			accessTokens := tokenmock.NewMockGenerator(ctrl)
			refreshTokens := tokenmock.NewMockGenerator(ctrl)
			tokens := storagemock.NewMockToken(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(sessions, tokens, accessTokens, refreshTokens)
			}

			s := &service{
				deviceCodeSessions: sessions,
				tokens:             tokens,
				accessTokenGen:     accessTokens,
				refreshTokenGen:    refreshTokens,
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
