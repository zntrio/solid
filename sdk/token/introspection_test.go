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
	"time"

	"github.com/golang/mock/gomock"

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/sdk/token"
	tokenmock "zntr.io/solid/sdk/token/mock"
)

func Test_introspectionGenerator_Generate(t *testing.T) {
	type args struct {
		ctx context.Context
		t   *tokenv1.Token
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
				t: &tokenv1.Token{},
			},
			wantErr: true,
		},
		{
			name: "nil meta",
			args: args{
				t: &tokenv1.Token{TokenId: "azerty"},
			},
			wantErr: true,
		},
		{
			name: "signer error",
			args: args{
				t: &tokenv1.Token{
					TokenId: "123456789",
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://localhost:8080",
						Audience:  "azertyuiop",
						ClientId:  "789456",
						Subject:   "test",
						Scope:     "openid",
						IssuedAt:  1,
						NotBefore: 2,
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
			name: "valid - expired",
			args: args{
				t: &tokenv1.Token{
					TokenId:   "123456789",
					TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    tokenv1.TokenStatus_TOKEN_STATUS_EXPIRED,
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://localhost:8080",
						Audience:  "azertyuiop",
						ClientId:  "789456",
						Subject:   "test",
						Scope:     "openid",
						IssuedAt:  1,
						NotBefore: 2,
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
		{
			name: "valid - active",
			args: args{
				t: &tokenv1.Token{
					TokenId:   "123456789",
					TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://localhost:8080",
						Audience:  "azertyuiop",
						ClientId:  "789456",
						Subject:   "test",
						Scope:     "openid",
						IssuedAt:  uint64(time.Now().Unix()) - 1,
						NotBefore: uint64(time.Now().Unix()) - 1,
						ExpiresAt: uint64(time.Now().Unix()) + 30,
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

			c := token.Introspection(serializer)
			got, err := c.Generate(tt.args.ctx, tt.args.t)
			if (err != nil) != tt.wantErr {
				t.Errorf("introspectionGenerator.Generate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("introspectionGenerator.Generate() = %v, want %v", got, tt.want)
			}
		})
	}
}
