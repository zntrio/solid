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

func Test_clientAssertionGenerator_Generate(t *testing.T) {
	type args struct {
		ctx context.Context
		t   *corev1.Token
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*tokenmock.MockSerializer)
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
			name: "nil token id",
			args: args{
				t: &corev1.Token{},
			},
			wantErr: true,
		},
		{
			name: "nil meta",
			args: args{
				t: &corev1.Token{TokenId: "azerty"},
			},
			wantErr: true,
		},
		{
			name: "invalid meta",
			args: args{
				t: &corev1.Token{
					TokenId:  "azerty",
					Metadata: &corev1.TokenMeta{},
				},
			},
			wantErr: true,
		},
		{
			name: "signer error",
			args: args{
				t: &corev1.Token{
					TokenId: "123456789",
					Metadata: &corev1.TokenMeta{
						Audience:  "http://localhost:8080",
						Issuer:    "client-1",
						Subject:   "client-1",
						IssuedAt:  1,
						ExpiresAt: 3601,
					},
				},
			},
			prepare: func(s *tokenmock.MockSerializer) {
				s.EXPECT().Serialize(gomock.Any(), gomock.Any()).Return("", fmt.Errorf("foo"))
			},
			wantErr: true,
		},
		// ---------------------------------------------------------------------
		{
			name: "valid",
			args: args{
				t: &corev1.Token{
					TokenId: "123456789",
					Metadata: &corev1.TokenMeta{
						Audience:  "http://localhost:8080",
						Issuer:    "client-1",
						Subject:   "client-1",
						IssuedAt:  1,
						ExpiresAt: 3601,
					},
				},
			},
			prepare: func(s *tokenmock.MockSerializer) {
				s.EXPECT().Serialize(gomock.Any(), gomock.Any()).Return("fake-token", nil)
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
			serializer := tokenmock.NewMockSerializer(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(serializer)
			}

			c := token.ClientAssertion(serializer)
			got, err := c.Generate(tt.args.ctx, tt.args.t)
			if (err != nil) != tt.wantErr {
				t.Errorf("clientAssertionGenerator.Generate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("clientAssertionGenerator.Generate() = %v, want %v", got, tt.want)
			}
		})
	}
}
