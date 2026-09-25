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
	sessionv1 "zntr.io/solid/api/oidc/session/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/rfcerrors"
	tokenmock "zntr.io/solid/sdk/token/mock"
	"zntr.io/solid/server/storage"
	storagemock "zntr.io/solid/server/storage/mock"
)

func Test_service_deviceCode(t *testing.T) {
	type args struct {
		ctx    context.Context
		client *clientv1.Client
		req    *flowv1.TokenRequest
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*storagemock.MockDeviceCodeSession, *storagemock.MockToken, *tokenmock.MockGenerator, *tokenmock.MockGenerator)
		want    *flowv1.TokenResponse
		wantErr bool
	}{
		{
			name: "nil client",
			args: args{
				ctx: context.Background(),
				req: &flowv1.TokenRequest{
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &flowv1.TokenRequest_DeviceCode{
						DeviceCode: &flowv1.GrantDeviceCode{},
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
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					GrantType: oidc.GrantTypeDeviceCode,
				},
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
					Issuer:    "",
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &flowv1.TokenRequest_DeviceCode{
						DeviceCode: &flowv1.GrantDeviceCode{},
					},
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid issuer",
			args: args{
				ctx:    context.Background(),
				client: &clientv1.Client{},
				req: &flowv1.TokenRequest{
					Issuer:    "foo",
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &flowv1.TokenRequest_DeviceCode{
						DeviceCode: &flowv1.GrantDeviceCode{},
					},
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "client not support grant_type",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeAuthorizationCode},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &flowv1.TokenRequest_DeviceCode{
						DeviceCode: &flowv1.GrantDeviceCode{},
					},
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.UnauthorizedClient().Build(),
			},
		},
		{
			name: "device_code is blank",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &flowv1.TokenRequest_DeviceCode{
						DeviceCode: &flowv1.GrantDeviceCode{
							DeviceCode: "",
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
			name: "authorization_details rejected",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType:            oidc.GrantTypeDeviceCode,
					AuthorizationDetails: []*tokenv1.AuthorizationDetail{{Type: "payment"}},
					Grant: &flowv1.TokenRequest_DeviceCode{
						DeviceCode: &flowv1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
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
			name: "slowdown persist failure",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
					ClientId:   "s6BhdRkqt3",
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &flowv1.TokenRequest_DeviceCode{
						DeviceCode: &flowv1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(10, 0) }
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&sessionv1.DeviceCodeSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt:    200,
					Status:       sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_AUTHORIZATION_PENDING,
					LastPolledAt: 8,
					PollInterval: 5,
				}, nil)
				sessions.EXPECT().UpdateByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS", gomock.Any()).Return(fmt.Errorf("boom"))
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "poll timing persist failure",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
					ClientId:   "s6BhdRkqt3",
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &flowv1.TokenRequest_DeviceCode{
						DeviceCode: &flowv1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(10, 0) }
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&sessionv1.DeviceCodeSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt:    200,
					Status:       sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_AUTHORIZATION_PENDING,
					LastPolledAt: 0,
					PollInterval: 5,
				}, nil)
				sessions.EXPECT().UpdateByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS", gomock.Any()).Return(fmt.Errorf("boom"))
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "denied session",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
					ClientId:   "s6BhdRkqt3",
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &flowv1.TokenRequest_DeviceCode{
						DeviceCode: &flowv1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(10, 0) }
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&sessionv1.DeviceCodeSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: 200,
					Status:    sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_DENIED,
				}, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.AccessDenied().Build(),
			},
		},
		{
			name: "consume failure",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
					ClientId:   "s6BhdRkqt3",
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &flowv1.TokenRequest_DeviceCode{
						DeviceCode: &flowv1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(10, 0) }
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&sessionv1.DeviceCodeSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: 200,
					Status:    sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED,
					Subject:   new("user1"),
				}, nil)
				sessions.EXPECT().DeleteAndGetByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(nil, fmt.Errorf("boom"))
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "device_code not found",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
				},
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
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(nil, storage.ErrNotFound)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "device_code storage error",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
				},
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
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(nil, fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "retrieved nil session",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "foo",
					},
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &flowv1.TokenRequest_DeviceCode{
						DeviceCode: &flowv1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(nil, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "retrieved session with nil request",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "foo",
					},
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &flowv1.TokenRequest_DeviceCode{
						DeviceCode: &flowv1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&sessionv1.DeviceCodeSession{}, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "retrieved session with nil client",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "foo",
					},
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &flowv1.TokenRequest_DeviceCode{
						DeviceCode: &flowv1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&sessionv1.DeviceCodeSession{
					Request: &flowv1.DeviceAuthorizationRequest{},
				}, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "client_id mismatch",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "foo",
					},
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &flowv1.TokenRequest_DeviceCode{
						DeviceCode: &flowv1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&sessionv1.DeviceCodeSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
				}, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "session is expired",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
					ClientId:   "s6BhdRkqt3",
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &flowv1.TokenRequest_DeviceCode{
						DeviceCode: &flowv1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(10, 0) }
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&sessionv1.DeviceCodeSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: 0,
				}, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.TokenExpired().Build(),
			},
		},
		{
			name: "authorization pending",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
					ClientId:   "s6BhdRkqt3",
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &flowv1.TokenRequest_DeviceCode{
						DeviceCode: &flowv1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(10, 0) }
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&sessionv1.DeviceCodeSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: 200,
					Status:    sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_AUTHORIZATION_PENDING,
				}, nil)
				sessions.EXPECT().UpdateByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS", gomock.Any()).Return(nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.AuthorizationPending().Build(),
			},
		},
		{
			name: "session invalid status",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
					ClientId:   "s6BhdRkqt3",
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &flowv1.TokenRequest_DeviceCode{
						DeviceCode: &flowv1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(10, 0) }
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&sessionv1.DeviceCodeSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: 200,
					Status:    sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_UNKNOWN,
				}, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidToken().Build(),
			},
		},
		{
			name: "session validated with no subject error",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
					ClientId:   "s6BhdRkqt3",
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &flowv1.TokenRequest_DeviceCode{
						DeviceCode: &flowv1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(10, 0) }
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&sessionv1.DeviceCodeSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: 200,
					Status:    sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED,
					Subject:   nil,
				}, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "session validated with at generation error",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
					ClientId:   "s6BhdRkqt3",
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &flowv1.TokenRequest_DeviceCode{
						DeviceCode: &flowv1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(10, 0) }
				session := &sessionv1.DeviceCodeSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: 200,
					Status:    sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED,
					Subject:   new("user-1"),
				}
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(session, nil)
				sessions.EXPECT().DeleteAndGetByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(session, nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("", fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "session validated with at storage error",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
					ClientId:   "s6BhdRkqt3",
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &flowv1.TokenRequest_DeviceCode{
						DeviceCode: &flowv1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(10, 0) }
				session := &sessionv1.DeviceCodeSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: 200,
					Status:    sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED,
					Subject:   new("user1"),
				}
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(session, nil)
				sessions.EXPECT().DeleteAndGetByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(session, nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo", nil)
				tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "validated session already consumed (concurrent poll)",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
					ClientId:   "s6BhdRkqt3",
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &flowv1.TokenRequest_DeviceCode{
						DeviceCode: &flowv1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(10, 0) }
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(&sessionv1.DeviceCodeSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: 200,
					Status:    sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED,
					Subject:   new("user1"),
				}, nil)
				sessions.EXPECT().DeleteAndGetByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(nil, storage.ErrNotFound)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "valid",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
					ClientId:   "s6BhdRkqt3",
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &flowv1.TokenRequest_DeviceCode{
						DeviceCode: &flowv1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				session := &sessionv1.DeviceCodeSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt: 200,
					Status:    sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED,
					Subject:   new("user1"),
				}
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(session, nil)
				sessions.EXPECT().DeleteAndGetByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(session, nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo", nil)
				tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(nil)
			},
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
		{
			name: "valid - offline_access",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
					ClientId:   "s6BhdRkqt3",
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &flowv1.TokenRequest_DeviceCode{
						DeviceCode: &flowv1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
					Scope: new("openid offline_access"),
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				session := &sessionv1.DeviceCodeSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
						Scope:    new("openid offline_access"),
					},
					ExpiresAt: 200,
					Status:    sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED,
					Subject:   new("user1"),
					Scope:     new("openid offline_access"),
				}
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(session, nil)
				sessions.EXPECT().DeleteAndGetByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(session, nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo", nil)
				tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(nil)
			},
			wantErr: false,
			want: &flowv1.TokenResponse{
				Error: nil,
				// RFC 10027 section 6.1.9: the device grant never mints
				// refresh tokens; offline_access is stripped from the
				// granted scope.
				AccessToken: &tokenv1.Token{
					TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						Scope:     "openid",
						IssuedAt:  1,
						NotBefore: 2,
						ExpiresAt: 3601,
						ClientId:  "s6BhdRkqt3",
						Subject:   "user1",
					},
					Value: "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
				},
				RefreshToken: nil,
			},
		},
		{
			name: "slow_down on fast polling",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
					ClientId:   "s6BhdRkqt3",
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &flowv1.TokenRequest_DeviceCode{
						DeviceCode: &flowv1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(10, 0) }
				session := &sessionv1.DeviceCodeSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt:    200,
					Status:       sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_AUTHORIZATION_PENDING,
					LastPolledAt: 8,
					PollInterval: 5,
				}
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(session, nil)
				sessions.EXPECT().UpdateByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS", gomock.Any()).
					Do(func(_ context.Context, _, _ string, r *sessionv1.DeviceCodeSession) {
						if r.PollInterval != 10 {
							t.Errorf("persisted PollInterval = %d, want 10", r.PollInterval)
						}
					}).Return(nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.Slowdown().Build(),
			},
		},
		{
			name: "authorization pending on admissible poll",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
					ClientId:   "s6BhdRkqt3",
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &flowv1.TokenRequest_DeviceCode{
						DeviceCode: &flowv1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockDeviceCodeSession, _ *storagemock.MockToken, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(10, 0) }
				session := &sessionv1.DeviceCodeSession{
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.DeviceAuthorizationRequest{
						ClientId: "s6BhdRkqt3",
					},
					ExpiresAt:    200,
					Status:       sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_AUTHORIZATION_PENDING,
					LastPolledAt: 2,
					PollInterval: 5,
				}
				sessions.EXPECT().GetByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS").Return(session, nil)
				sessions.EXPECT().UpdateByDeviceCode(gomock.Any(), "http://127.0.0.1:8080", "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS", gomock.Any()).Return(nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.AuthorizationPending().Build(),
			},
		},
		{
			name: "dpop-bound client without proof",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes:            []string{oidc.GrantTypeDeviceCode},
					ClientId:              "s6BhdRkqt3",
					DpopBoundAccessTokens: true,
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					GrantType: oidc.GrantTypeDeviceCode,
					Grant: &flowv1.TokenRequest_DeviceCode{
						DeviceCode: &flowv1.GrantDeviceCode{
							ClientId:   "s6BhdRkqt3",
							DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
						},
					},
					TokenConfirmation: nil,
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidRequest().Build(),
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
