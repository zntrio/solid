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
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/pkg/sdk/jwt"
	jwtmock "zntr.io/solid/pkg/sdk/jwt/mock"
	"zntr.io/solid/pkg/sdk/rfcerrors"
)

func Test_jwtDecoder_Decode(t *testing.T) {
	type fields struct {
		issuer   string
		verifier jwt.Verifier
	}
	type args struct {
		ctx      context.Context
		audience string
		response string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		prepare func(*jwtmock.MockVerifier, *jwtmock.MockToken)
		want    *corev1.AuthorizationCodeResponse
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "audience blank",
			args: args{
				audience: "",
			},
			wantErr: true,
		},
		{
			name: "response blank",
			args: args{
				audience: "https://example.com",
				response: "",
			},
			wantErr: true,
		},
		{
			name: "response parse error",
			args: args{
				audience: "https://example.com",
				response: "invalid-jwt-token",
			},
			prepare: func(verifier *jwtmock.MockVerifier, _ *jwtmock.MockToken) {
				verifier.EXPECT().Parse("invalid-jwt-token").Return(nil, fmt.Errorf("invalid token"))
			},
			wantErr: true,
		},
		{
			name: "response type error",
			args: args{
				audience: "https://example.com",
				response: "fake-token",
			},
			prepare: func(verifier *jwtmock.MockVerifier, token *jwtmock.MockToken) {
				verifier.EXPECT().Parse("fake-token").Return(token, nil)
				token.EXPECT().Type().Return("", fmt.Errorf("foo"))
			},
			wantErr: true,
		},
		{
			name: "invalid response type",
			args: args{
				audience: "https://example.com",
				response: "fake-token",
			},
			prepare: func(verifier *jwtmock.MockVerifier, token *jwtmock.MockToken) {
				verifier.EXPECT().Parse("fake-token").Return(token, nil)
				token.EXPECT().Type().Return("invalid", nil)
			},
			wantErr: true,
		},
		{
			name: "claims error",
			args: args{
				audience: "https://example.com",
				response: "fake-token",
			},
			prepare: func(verifier *jwtmock.MockVerifier, token *jwtmock.MockToken) {
				verifier.EXPECT().Parse("fake-token").Return(token, nil)
				token.EXPECT().Type().Return(HeaderType, nil)
				token.EXPECT().Claims(gomock.Any(), gomock.Any()).Return(fmt.Errorf("foo"))
			},
			wantErr: true,
		},
		{
			name: "invalid issuer",
			fields: fields{
				issuer: "https://example.com",
			},
			args: args{
				audience: "https://example.com",
				response: "fake-token",
			},
			prepare: func(verifier *jwtmock.MockVerifier, token *jwtmock.MockToken) {
				verifier.EXPECT().Parse("fake-token").Return(token, nil)
				token.EXPECT().Type().Return(HeaderType, nil)
				token.EXPECT().Claims(gomock.Any(), gomock.Any()).Do(func(key interface{}, claims interface{}) {
					switch v := claims.(type) {
					case *jwtResponseClaims:
						*v = jwtResponseClaims{
							Issuer:    "https://foo.com",
							Audience:  "https://example.com",
							Code:      "AZERTYUIOP",
							State:     "QSDFGHJKLM",
							ExpiresAt: uint64(time.Now().Add(60 * time.Second).Unix()),
						}
					}
				}).Return(nil)
			},
			wantErr: true,
			want: &corev1.AuthorizationCodeResponse{
				Error: rfcerrors.InvalidToken().Build(),
			},
		},
		{
			name: "invalid audience",
			fields: fields{
				issuer: "https://example.com",
			},
			args: args{
				audience: "https://foo.com",
				response: "fake-token",
			},
			prepare: func(verifier *jwtmock.MockVerifier, token *jwtmock.MockToken) {
				verifier.EXPECT().Parse("fake-token").Return(token, nil)
				token.EXPECT().Type().Return(HeaderType, nil)
				token.EXPECT().Claims(gomock.Any(), gomock.Any()).Do(func(key interface{}, claims interface{}) {
					switch v := claims.(type) {
					case *jwtResponseClaims:
						*v = jwtResponseClaims{
							Issuer:    "https://example.com",
							Audience:  "https://example.com",
							Code:      "AZERTYUIOP",
							State:     "QSDFGHJKLM",
							ExpiresAt: uint64(time.Now().Add(60 * time.Second).Unix()),
						}
					}
				}).Return(nil)
			},
			wantErr: true,
			want: &corev1.AuthorizationCodeResponse{
				Error: rfcerrors.InvalidToken().Build(),
			},
		},
		{
			name: "expired",
			fields: fields{
				issuer: "https://example.com",
			},
			args: args{
				audience: "https://example.com",
				response: "fake-token",
			},
			prepare: func(verifier *jwtmock.MockVerifier, token *jwtmock.MockToken) {
				verifier.EXPECT().Parse("fake-token").Return(token, nil)
				token.EXPECT().Type().Return(HeaderType, nil)
				token.EXPECT().Claims(gomock.Any(), gomock.Any()).Do(func(key interface{}, claims interface{}) {
					switch v := claims.(type) {
					case *jwtResponseClaims:
						*v = jwtResponseClaims{
							Issuer:    "https://example.com",
							Audience:  "https://example.com",
							Code:      "AZERTYUIOP",
							State:     "QSDFGHJKLM",
							ExpiresAt: uint64(time.Now().Add(-60 * time.Second).Unix()),
						}
					}
				}).Return(nil)
			},
			wantErr: true,
			want: &corev1.AuthorizationCodeResponse{
				Error: rfcerrors.InvalidToken().Build(),
			},
		},
		{
			name: "claims has error",
			fields: fields{
				issuer: "https://example.com",
			},
			args: args{
				audience: "https://example.com",
				response: "fake-token",
			},
			prepare: func(verifier *jwtmock.MockVerifier, token *jwtmock.MockToken) {
				verifier.EXPECT().Parse("fake-token").Return(token, nil)
				token.EXPECT().Type().Return(HeaderType, nil)
				token.EXPECT().Claims(gomock.Any(), gomock.Any()).Do(func(key interface{}, claims interface{}) {
					switch v := claims.(type) {
					case *jwtResponseClaims:
						*v = jwtResponseClaims{
							Error: "invalid_request",
						}
					}
				}).Return(nil)
			},
			wantErr: false,
			want: &corev1.AuthorizationCodeResponse{
				Error: &corev1.Error{
					Err: "invalid_request",
				},
			},
		},
		{
			name: "valid",
			fields: fields{
				issuer: "https://example.com",
			},
			args: args{
				audience: "https://example.com",
				response: "fake-token",
			},
			prepare: func(verifier *jwtmock.MockVerifier, token *jwtmock.MockToken) {
				verifier.EXPECT().Parse("fake-token").Return(token, nil)
				token.EXPECT().Type().Return(HeaderType, nil)
				token.EXPECT().Claims(gomock.Any(), gomock.Any()).Do(func(key interface{}, claims interface{}) {
					switch v := claims.(type) {
					case *jwtResponseClaims:
						*v = jwtResponseClaims{
							Issuer:    "https://example.com",
							Audience:  "https://example.com",
							Code:      "AZERTYUIOP",
							State:     "QSDFGHJKLM",
							ExpiresAt: uint64(time.Now().Add(60 * time.Second).Unix()),
						}
					}
				}).Return(nil)
			},
			wantErr: false,
			want: &corev1.AuthorizationCodeResponse{
				Code:  "AZERTYUIOP",
				State: "QSDFGHJKLM",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockVerifier := jwtmock.NewMockVerifier(ctrl)
			mockToken := jwtmock.NewMockToken(ctrl)

			// Prepare mocks
			if tt.prepare != nil {
				tt.prepare(mockVerifier, mockToken)
			}

			d := JWTDecoder(tt.fields.issuer, mockVerifier)
			got, err := d.Decode(tt.args.ctx, tt.args.audience, tt.args.response)
			if (err != nil) != tt.wantErr {
				t.Errorf("jwtDecoder.Decode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("jwtDecoder.Decode() = %v, want %v", got, tt.want)
			}
		})
	}
}
