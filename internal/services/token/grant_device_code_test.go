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
	"testing"

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
	"go.zenithar.org/solid/api/oidc"
	generatormock "go.zenithar.org/solid/pkg/generator/mock"
	"go.zenithar.org/solid/pkg/rfcerrors"
	storagemock "go.zenithar.org/solid/pkg/storage/mock"

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
			name: "client not support grant_type",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes: []string{oidc.GrantTypeAuthorizationCode},
				},
				req: &corev1.TokenRequest{
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
