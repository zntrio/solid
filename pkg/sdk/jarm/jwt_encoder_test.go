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

package jarm

import (
	"context"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	jwtmock "zntr.io/solid/pkg/sdk/jwt/mock"
	"zntr.io/solid/pkg/sdk/rfcerrors"
)

func Test_jwtEncoder_Encode(t *testing.T) {
	type args struct {
		ctx    context.Context
		issuer string
		resp   *corev1.AuthorizationCodeResponse
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*jwtmock.MockSigner)
		want    string
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "issuer blank",
			args: args{
				issuer: "",
			},
			wantErr: true,
		},
		{
			name: "response nil",
			args: args{
				issuer: "https://example.com",
				resp:   nil,
			},
			wantErr: true,
		},
		{
			name: "response has error",
			args: args{
				issuer: "https://example.com",
				resp: &corev1.AuthorizationCodeResponse{
					Error: rfcerrors.AccessDenied().Build(),
				},
			},
			prepare: func(signer *jwtmock.MockSigner) {
				signer.EXPECT().Sign(gomock.Any()).Return("fake-token", nil)
			},
			wantErr: false,
			want:    "fake-token",
		},
		{
			name: "response has error with signer error",
			args: args{
				issuer: "https://example.com",
				resp: &corev1.AuthorizationCodeResponse{
					Error: rfcerrors.AccessDenied().Build(),
				},
			},
			prepare: func(signer *jwtmock.MockSigner) {
				signer.EXPECT().Sign(gomock.Any()).Return("", fmt.Errorf("foo"))
			},
			wantErr: true,
		},
		{
			name: "response client_id blank",
			args: args{
				issuer: "https://example.com",
				resp: &corev1.AuthorizationCodeResponse{
					ClientId: "",
				},
			},
			wantErr: true,
		},
		{
			name: "response code blank",
			args: args{
				issuer: "https://example.com",
				resp: &corev1.AuthorizationCodeResponse{
					ClientId: "client-12345",
					Code:     "",
				},
			},
			wantErr: true,
		},
		{
			name: "response state blank",
			args: args{
				issuer: "https://example.com",
				resp: &corev1.AuthorizationCodeResponse{
					ClientId: "client-12345",
					Code:     "AZERTYUIOP",
					State:    "",
				},
			},
			wantErr: true,
		},
		{
			name: "response expires_in zero",
			args: args{
				issuer: "https://example.com",
				resp: &corev1.AuthorizationCodeResponse{
					ClientId:  "client-12345",
					Code:      "AZERTYUIOP",
					State:     "QSDFGHJKLM",
					ExpiresIn: 0,
				},
			},
			wantErr: true,
		},
		{
			name: "response valid with signer error",
			args: args{
				issuer: "https://example.com",
				resp: &corev1.AuthorizationCodeResponse{
					ClientId:  "client-12345",
					Code:      "AZERTYUIOP",
					State:     "QSDFGHJKLM",
					ExpiresIn: 60,
				},
			},
			prepare: func(signer *jwtmock.MockSigner) {
				signer.EXPECT().Sign(gomock.Any()).Return("", fmt.Errorf("foo"))
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				issuer: "https://example.com",
				resp: &corev1.AuthorizationCodeResponse{
					ClientId:  "client-12345",
					Code:      "AZERTYUIOP",
					State:     "QSDFGHJKLM",
					ExpiresIn: 60,
				},
			},
			prepare: func(signer *jwtmock.MockSigner) {
				signer.EXPECT().Sign(gomock.Any()).Return("fake-token", nil)
			},
			wantErr: false,
			want:    "fake-token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockSigner := jwtmock.NewMockSigner(ctrl)

			// Prepare mocks
			if tt.prepare != nil {
				tt.prepare(mockSigner)
			}

			d := JWTEncoder(mockSigner)
			got, err := d.Encode(tt.args.ctx, tt.args.issuer, tt.args.resp)
			if (err != nil) != tt.wantErr {
				t.Errorf("jwtEncoder.Encode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("jwtEncoder.Encode() = %v, want %v", got, tt.want)
			}
		})
	}
}
