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

package device

import (
	"context"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	corev1 "zntr.io/solid/api/oidc/core/v1"
	"zntr.io/solid/oidc"
	generatormock "zntr.io/solid/sdk/generator/mock"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/types"
	"zntr.io/solid/server/storage"
	storagemock "zntr.io/solid/server/storage/mock"
)

var cmpOpts = []cmp.Option{cmpopts.IgnoreUnexported(wrappers.StringValue{}), cmpopts.IgnoreUnexported(corev1.DeviceAuthorizationRequest{}), cmpopts.IgnoreUnexported(corev1.DeviceAuthorizationResponse{}), cmpopts.IgnoreUnexported(corev1.Error{})}

func Test_service_Device(t *testing.T) {
	type args struct {
		ctx context.Context
		req *corev1.DeviceAuthorizationRequest
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*storagemock.MockClientReader, *storagemock.MockDeviceCodeSession, *generatormock.MockDeviceCode, *generatormock.MockDeviceUserCode)
		want    *corev1.DeviceAuthorizationResponse
		wantErr bool
	}{
		{
			name: "nil request",
			args: args{
				ctx: context.Background(),
				req: nil,
			},
			wantErr: true,
			want: &corev1.DeviceAuthorizationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty request",
			args: args{
				ctx: context.Background(),
				req: &corev1.DeviceAuthorizationRequest{},
			},
			wantErr: true,
			want: &corev1.DeviceAuthorizationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty issuer",
			args: args{
				ctx: context.Background(),
				req: &corev1.DeviceAuthorizationRequest{
					Issuer: "",
				},
			},
			wantErr: true,
			want: &corev1.DeviceAuthorizationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty client id",
			args: args{
				ctx: context.Background(),
				req: &corev1.DeviceAuthorizationRequest{
					Issuer:   "https://honest.as.example.com",
					ClientId: "",
				},
			},
			wantErr: true,
			want: &corev1.DeviceAuthorizationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "client not found",
			args: args{
				ctx: context.Background(),
				req: &corev1.DeviceAuthorizationRequest{
					Issuer:   "https://honest.as.example.com",
					ClientId: "s6BhdRkqt3",
				},
			},
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockDeviceCodeSession, _ *generatormock.MockDeviceCode, _ *generatormock.MockDeviceUserCode) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(nil, storage.ErrNotFound)
			},
			wantErr: true,
			want: &corev1.DeviceAuthorizationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "client storage error",
			args: args{
				ctx: context.Background(),
				req: &corev1.DeviceAuthorizationRequest{
					Issuer:   "https://honest.as.example.com",
					ClientId: "s6BhdRkqt3",
				},
			},
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockDeviceCodeSession, _ *generatormock.MockDeviceCode, _ *generatormock.MockDeviceUserCode) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(nil, fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.DeviceAuthorizationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "client nil error",
			args: args{
				ctx: context.Background(),
				req: &corev1.DeviceAuthorizationRequest{
					Issuer:   "https://honest.as.example.com",
					ClientId: "s6BhdRkqt3",
				},
			},
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockDeviceCodeSession, _ *generatormock.MockDeviceCode, _ *generatormock.MockDeviceUserCode) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(nil, nil)
			},
			wantErr: true,
			want: &corev1.DeviceAuthorizationResponse{
				Error: rfcerrors.InvalidClient().Build(),
			},
		},
		{
			name: "grant type not supported",
			args: args{
				ctx: context.Background(),
				req: &corev1.DeviceAuthorizationRequest{
					Issuer:   "https://honest.as.example.com",
					ClientId: "s6BhdRkqt3",
				},
			},
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockDeviceCodeSession, _ *generatormock.MockDeviceCode, _ *generatormock.MockDeviceUserCode) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&corev1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeAuthorizationCode},
				}, nil)
			},
			wantErr: true,
			want: &corev1.DeviceAuthorizationResponse{
				Error: rfcerrors.UnsupportedGrantType().Build(),
			},
		},
		{
			name: "device code session registration error",
			args: args{
				ctx: context.Background(),
				req: &corev1.DeviceAuthorizationRequest{
					Issuer:   "https://honest.as.example.com",
					ClientId: "s6BhdRkqt3",
				},
			},
			prepare: func(clients *storagemock.MockClientReader, deviceCodes *storagemock.MockDeviceCodeSession, mdc *generatormock.MockDeviceCode, mduc *generatormock.MockDeviceUserCode) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&corev1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
				}, nil)
				mdc.EXPECT().Generate(gomock.Any(), "https://honest.as.example.com").Return("GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS", nil)
				mduc.EXPECT().Generate(gomock.Any(), "https://honest.as.example.com").Return("WDJB-MJHT", nil)
				deviceCodes.EXPECT().Register(gomock.Any(), "https://honest.as.example.com", "WDJB-MJHT", gomock.Any()).Return(uint64(60), fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.DeviceAuthorizationResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "valid",
			args: args{
				ctx: context.Background(),
				req: &corev1.DeviceAuthorizationRequest{
					Issuer:   "https://honest.as.example.com",
					ClientId: "s6BhdRkqt3",
					Scope:    types.StringRef("openid admin"),
				},
			},
			prepare: func(clients *storagemock.MockClientReader, deviceCodes *storagemock.MockDeviceCodeSession, mdc *generatormock.MockDeviceCode, mduc *generatormock.MockDeviceUserCode) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&corev1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
				}, nil)
				mdc.EXPECT().Generate(gomock.Any(), "https://honest.as.example.com").Return("GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS", nil)
				mduc.EXPECT().Generate(gomock.Any(), "https://honest.as.example.com").Return("WDJB-MJHT", nil)
				deviceCodes.EXPECT().Register(gomock.Any(), "https://honest.as.example.com", "WDJB-MJHT", gomock.Any()).Return(uint64(120), nil)
			},
			wantErr: false,
			want: &corev1.DeviceAuthorizationResponse{
				Issuer:     "https://honest.as.example.com",
				DeviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
				UserCode:   "WDJB-MJHT",
				ExpiresIn:  120,
				Interval:   5,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Arm mocks
			clients := storagemock.NewMockClientReader(ctrl)
			deviceCodeSessions := storagemock.NewMockDeviceCodeSession(ctrl)
			deviceCodes := generatormock.NewMockDeviceCode(ctrl)
			userCodes := generatormock.NewMockDeviceUserCode(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(clients, deviceCodeSessions, deviceCodes, userCodes)
			}

			// Prepare service
			underTest := New(clients, deviceCodeSessions, deviceCodes, userCodes)

			// Do the request
			got, err := underTest.Authorize(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("service.Device() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
				t.Errorf("service.Device() res =%s", diff)
			}
		})
	}
}
