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
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/sdk/token"
	tokenmock "zntr.io/solid/sdk/token/mock"
)

func Test_accessTokenGenerator_Generate(t *testing.T) {
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
			name: "invalid meta",
			args: args{
				t: &tokenv1.Token{
					TokenId:  "azerty",
					Metadata: &tokenv1.TokenMeta{},
				},
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
			name: "valid",
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
				s.EXPECT().Serialize(gomock.Any(), gomock.Any()).Return("fake-token", nil)
			},
			wantErr: false,
			want:    "fake-token",
		},
		{
			name: "valid with confirmation",
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
					Confirmation: &tokenv1.TokenConfirmation{
						Jkt: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
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

			c := token.AccessToken(serializer)
			got, err := c.Generate(tt.args.ctx, tt.args.t)
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

// Test_accessTokenGenerator_Generate_AuthorizationDetails asserts the
// RFC 9396 section 9.1 top-level authorization_details claim is carried
// from token metadata into the serialized access token claims.
func Test_accessTokenGenerator_Generate_AuthorizationDetails(t *testing.T) {
	details := []*tokenv1.AuthorizationDetail{
		{
			Type:    "payment_initiation",
			Actions: []string{"initiate"},
		},
	}

	tok := &tokenv1.Token{
		TokenId: "123456789",
		Metadata: &tokenv1.TokenMeta{
			Issuer:               "http://localhost:8080",
			Audience:             "azertyuiop",
			ClientId:             "789456",
			Subject:              "test",
			Scope:                "openid",
			IssuedAt:             1,
			NotBefore:            2,
			ExpiresAt:            3601,
			AuthorizationDetails: details,
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	serializer := tokenmock.NewMockSerializer(ctrl)
	var captured any
	serializer.EXPECT().Serialize(gomock.Any(), gomock.Any()).Do(func(_ context.Context, claims any) {
		captured = claims
	}).Return("fake-token", nil)

	c := token.AccessToken(serializer)
	got, err := c.Generate(context.Background(), tok)
	require.NoError(t, err)
	require.Equal(t, "fake-token", got)
	require.NotNil(t, captured)

	// The claim object is the internal claims struct: authorization_details
	// must be present and equal the metadata's entries.
	v := reflect.ValueOf(captured).FieldByName("AuthorizationDetails").Interface()
	require.Equal(t, details, v)
}

// Test_accessTokenGenerator_Generate_Confirmation asserts the RFC-mandated
// confirmation wire shape (RFC 8705 section 3.1 "x5t#S256" member; RFC 9449
// "jkt") is emitted on the cnf claim: the JSON marshaler of the captured
// claims must produce the exact member names, not the proto field names.
func Test_accessTokenGenerator_Generate_Confirmation(t *testing.T) {
	tok := &tokenv1.Token{
		TokenId: "tid-1",
		Metadata: &tokenv1.TokenMeta{
			ClientId:  "client-1",
			Issuer:    "https://as.example.org",
			Subject:   "user-1",
			Audience:  "aud",
			ExpiresAt: uint64(time.Now().Add(time.Hour).Unix()),
			NotBefore: uint64(time.Now().Unix()),
			IssuedAt:  uint64(time.Now().Unix()),
			Scope:     "openid",
		},
		Confirmation: &tokenv1.TokenConfirmation{
			X5TS256: "A4DtL2JmUMhAsvJj5tKyn64SqzmuXbMrJa0n761y5v0",
			Jkt:     "test-jkt",
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	serializer := tokenmock.NewMockSerializer(ctrl)
	var captured any
	serializer.EXPECT().Serialize(gomock.Any(), gomock.Any()).Do(func(_ context.Context, claims any) {
		captured = claims
	}).Return("fake-token", nil)

	c := token.AccessToken(serializer)
	_, err := c.Generate(context.Background(), tok)
	require.NoError(t, err)

	// The cnf claim must serialize with the RFC-mandated member names.
	raw, err := json.Marshal(reflect.ValueOf(captured).FieldByName("Cnf").Interface())
	require.NoError(t, err)
	require.Contains(t, string(raw), `"x5t#S256":"A4DtL2JmUMhAsvJj5tKyn64SqzmuXbMrJa0n761y5v0"`)
	require.Contains(t, string(raw), `"jkt":"test-jkt"`)
	require.NotContains(t, string(raw), `"x5t_s256"`)
}
