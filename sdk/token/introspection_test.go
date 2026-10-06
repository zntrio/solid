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

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
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
			prepare: func(s *tokenmock.MockSigner) {
				s.EXPECT().Sign(gomock.Any(), gomock.Any()).Return("", fmt.Errorf("foo"))
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
			prepare: func(s *tokenmock.MockSigner) {
				s.EXPECT().Sign(gomock.Any(), gomock.Any()).Return("fake-token", nil)
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
			serializer := tokenmock.NewMockSigner(ctrl)

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

// Test_introspectionGenerator_Generate_StepUpMembers asserts the RFC 9470
// section 6.2 acr / auth_time members are carried into the
// token_introspection claim when the metadata has them, and omitted
// otherwise.
func Test_introspectionGenerator_Generate_StepUpMembers(t *testing.T) {
	acr := "urn:solid:loa:1fa:any"
	authTime := uint64(1_700_000_000)

	newToken := func() *tokenv1.Token {
		return &tokenv1.Token{
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
		}
	}

	capture := func(t *testing.T, tok *tokenv1.Token) map[string]any {
		t.Helper()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		serializer := tokenmock.NewMockSigner(ctrl)
		var captured any
		serializer.EXPECT().Sign(gomock.Any(), gomock.Any()).Do(func(_ context.Context, claims any) {
			captured = claims
		}).Return("fake-token", nil)

		c := token.Introspection(serializer)
		_, err := c.Generate(context.Background(), tok)
		require.NoError(t, err)
		require.NotNil(t, captured)

		m, ok := captured.(map[string]any)
		require.True(t, ok)
		inner, ok := m["token_introspection"].(map[string]any)
		require.True(t, ok)
		return inner
	}

	t.Run("acr and auth_time present when metadata carries them", func(t *testing.T) {
		tok := newToken()
		tok.Metadata.Acr = &acr
		tok.Metadata.AuthTime = &authTime

		inner := capture(t, tok)
		require.Equal(t, acr, inner["acr"])
		require.Equal(t, authTime, inner["auth_time"])
	})

	t.Run("acr and auth_time omitted when metadata lacks them", func(t *testing.T) {
		inner := capture(t, newToken())
		require.NotContains(t, inner, "acr")
		require.NotContains(t, inner, "auth_time")
	})
}
