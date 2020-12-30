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

package token_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/pkg/sdk/token"
	tokenmock "zntr.io/solid/pkg/sdk/token/mock"
)

func Test_accessTokenGenerator_Generate(t *testing.T) {
	type args struct {
		ctx  context.Context
		jti  string
		meta *corev1.TokenMeta
		cnf  *corev1.TokenConfirmation
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*tokenmock.MockSigner)
		want    string
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name:    "blank jti",
			wantErr: true,
		},
		{
			name: "nil meta",
			args: args{
				jti: "123456789",
			},
			wantErr: true,
		},
		{
			name: "signer error",
			args: args{
				jti: "123456789",
				meta: &corev1.TokenMeta{
					Issuer:    "http://localhost:8080",
					Audience:  "azertyuiop",
					ClientId:  "789456",
					Subject:   "test",
					IssuedAt:  1,
					NotBefore: 2,
					ExpiresAt: 3601,
				},
			},
			prepare: func(s *tokenmock.MockSigner) {
				s.EXPECT().Sign(gomock.Any(), gomock.Any()).Return("", fmt.Errorf("foo"))
			},
			wantErr: true,
		},
		// ---------------------------------------------------------------------
		{
			name: "valid",
			args: args{
				jti: "123456789",
				meta: &corev1.TokenMeta{
					Issuer:    "http://localhost:8080",
					Audience:  "azertyuiop",
					ClientId:  "789456",
					Subject:   "test",
					IssuedAt:  1,
					NotBefore: 2,
					ExpiresAt: 3601,
				},
			},
			prepare: func(s *tokenmock.MockSigner) {
				s.EXPECT().Sign(gomock.Any(), gomock.Any()).Return("fake-token", nil)
			},
			wantErr: false,
			want:    "fake-token",
		},
		{
			name: "valid with confirmation",
			args: args{
				jti: "123456789",
				meta: &corev1.TokenMeta{
					Issuer:    "http://localhost:8080",
					Audience:  "azertyuiop",
					ClientId:  "789456",
					Subject:   "test",
					IssuedAt:  1,
					NotBefore: 2,
					ExpiresAt: 3601,
				},
				cnf: &corev1.TokenConfirmation{
					Jkt: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
				},
			},
			prepare: func(s *tokenmock.MockSigner) {
				s.EXPECT().Sign(gomock.Any(), gomock.Any()).Return("fake-token", nil)
			},
			wantErr: false,
			want:    "fake-token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Arm mocks
			signer := tokenmock.NewMockSigner(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(signer)
			}

			c := token.AccessToken(signer)
			got, err := c.Generate(tt.args.ctx, tt.args.jti, tt.args.meta, tt.args.cnf)
			if (err != nil) != tt.wantErr {
				t.Errorf("accessTokenGenerator.Generate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("accessTokenGenerator.Generate() = %v, want %v", got, tt.want)
			}
		})
	}
}
