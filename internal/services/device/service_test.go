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

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/api/oidc"
	"zntr.io/solid/pkg/generator"
	"zntr.io/solid/pkg/rfcerrors"
	"zntr.io/solid/pkg/storage"
	storagemock "zntr.io/solid/pkg/storage/mock"
)

var (
	cmpOpts = []cmp.Option{
		cmpopts.IgnoreUnexported(wrappers.StringValue{}),
		cmpopts.IgnoreUnexported(corev1.DeviceAuthorizationRequest{}),
		cmpopts.IgnoreUnexported(corev1.DeviceAuthorizationResponse{}),
		cmpopts.IgnoreUnexported(corev1.Error{}),
	}
)

func Test_service_Device(t *testing.T) {
	type fields struct {
		clients            storage.ClientReader
		deviceCodeSessions storage.DeviceCodeSessionWriter
		userCodeGen        generator.DeviceUserCode
	}
	type args struct {
		ctx context.Context
		req *corev1.DeviceAuthorizationRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		prepare func(*storagemock.MockClientReader, *storagemock.MockDeviceCodeSessionWriter)
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
				Error: rfcerrors.InvalidRequest(""),
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
				Error: rfcerrors.InvalidRequest(""),
			},
		},
		{
			name: "empty client id",
			args: args{
				ctx: context.Background(),
				req: &corev1.DeviceAuthorizationRequest{
					ClientId: "",
				},
			},
			wantErr: true,
			want: &corev1.DeviceAuthorizationResponse{
				Error: rfcerrors.InvalidRequest(""),
			},
		},
		{
			name: "client not found",
			args: args{
				ctx: context.Background(),
				req: &corev1.DeviceAuthorizationRequest{
					ClientId: "s6BhdRkqt3",
				},
			},
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockDeviceCodeSessionWriter) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(nil, storage.ErrNotFound)
			},
			wantErr: true,
			want: &corev1.DeviceAuthorizationResponse{
				Error: rfcerrors.InvalidRequest(""),
			},
		},
		{
			name: "client storage error",
			args: args{
				ctx: context.Background(),
				req: &corev1.DeviceAuthorizationRequest{
					ClientId: "s6BhdRkqt3",
				},
			},
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockDeviceCodeSessionWriter) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(nil, fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.DeviceAuthorizationResponse{
				Error: rfcerrors.InvalidRequest(""),
			},
		},
		{
			name: "grant type not supported",
			args: args{
				ctx: context.Background(),
				req: &corev1.DeviceAuthorizationRequest{
					ClientId: "s6BhdRkqt3",
				},
			},
			prepare: func(clients *storagemock.MockClientReader, _ *storagemock.MockDeviceCodeSessionWriter) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&corev1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeAuthorizationCode},
				}, nil)
			},
			wantErr: true,
			want: &corev1.DeviceAuthorizationResponse{
				Error: rfcerrors.UnsupportedGrantType(""),
			},
		},
		{
			name: "device code session registration error",
			args: args{
				ctx: context.Background(),
				req: &corev1.DeviceAuthorizationRequest{
					ClientId: "s6BhdRkqt3",
				},
			},
			prepare: func(clients *storagemock.MockClientReader, deviceCodes *storagemock.MockDeviceCodeSessionWriter) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&corev1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
				}, nil)
				deviceCodes.EXPECT().Register(gomock.Any(), gomock.Any()).Return("", "", uint64(60), fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.DeviceAuthorizationResponse{
				Error: rfcerrors.ServerError(""),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "valid",
			args: args{
				ctx: context.Background(),
				req: &corev1.DeviceAuthorizationRequest{
					ClientId: "s6BhdRkqt3",
				},
			},
			prepare: func(clients *storagemock.MockClientReader, deviceCodes *storagemock.MockDeviceCodeSessionWriter) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&corev1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{oidc.GrantTypeDeviceCode},
				}, nil)
				deviceCodes.EXPECT().Register(gomock.Any(), gomock.Any()).Return("GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS", "WDJB-MJHT", uint64(120), nil)
			},
			wantErr: false,
			want: &corev1.DeviceAuthorizationResponse{
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
			deviceCodeSessions := storagemock.NewMockDeviceCodeSessionWriter(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(clients, deviceCodeSessions)
			}

			// Prepare service
			underTest := New(clients, deviceCodeSessions)

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
