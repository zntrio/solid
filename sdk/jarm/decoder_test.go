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

	corev1 "zntr.io/solid/api/oidc/core/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/token"
	tokenmock "zntr.io/solid/sdk/token/mock"
)

func Test_jwtDecoder_Decode(t *testing.T) {
	type fields struct {
		issuer   string
		verifier token.Verifier
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
		prepare func(*tokenmock.MockVerifier, *tokenmock.MockToken)
		want    *flowv1.AuthorizeResponse
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
			prepare: func(verifier *tokenmock.MockVerifier, _ *tokenmock.MockToken) {
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
			prepare: func(verifier *tokenmock.MockVerifier, token *tokenmock.MockToken) {
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
			prepare: func(verifier *tokenmock.MockVerifier, token *tokenmock.MockToken) {
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
			prepare: func(verifier *tokenmock.MockVerifier, token *tokenmock.MockToken) {
				verifier.EXPECT().Parse("fake-token").Return(token, nil)
				token.EXPECT().Type().Return(HeaderType, nil)
				verifier.EXPECT().Claims(gomock.Any(), gomock.Any(), gomock.Any()).Return(fmt.Errorf("foo"))
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
			prepare: func(verifier *tokenmock.MockVerifier, token *tokenmock.MockToken) {
				verifier.EXPECT().Parse("fake-token").Return(token, nil)
				token.EXPECT().Type().Return(HeaderType, nil)
				verifier.EXPECT().Claims(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(ctx any, key any, claims any) {
					switch v := claims.(type) {
					case *responseClaims:
						*v = responseClaims{
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
			want: &flowv1.AuthorizeResponse{
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
			prepare: func(verifier *tokenmock.MockVerifier, token *tokenmock.MockToken) {
				verifier.EXPECT().Parse("fake-token").Return(token, nil)
				token.EXPECT().Type().Return(HeaderType, nil)
				verifier.EXPECT().Claims(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(ctx any, key any, claims any) {
					switch v := claims.(type) {
					case *responseClaims:
						*v = responseClaims{
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
			want: &flowv1.AuthorizeResponse{
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
			prepare: func(verifier *tokenmock.MockVerifier, token *tokenmock.MockToken) {
				verifier.EXPECT().Parse("fake-token").Return(token, nil)
				token.EXPECT().Type().Return(HeaderType, nil)
				verifier.EXPECT().Claims(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(ctx any, key any, claims any) {
					switch v := claims.(type) {
					case *responseClaims:
						*v = responseClaims{
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
			want: &flowv1.AuthorizeResponse{
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
			prepare: func(verifier *tokenmock.MockVerifier, token *tokenmock.MockToken) {
				verifier.EXPECT().Parse("fake-token").Return(token, nil)
				token.EXPECT().Type().Return(HeaderType, nil)
				verifier.EXPECT().Claims(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(ctx any, key any, claims any) {
					switch v := claims.(type) {
					case *responseClaims:
						*v = responseClaims{
							Error: "invalid_request",
						}
					}
				}).Return(nil)
			},
			wantErr: false,
			want: &flowv1.AuthorizeResponse{
				Error: &corev1.Error{
					Err: "invalid_request",
				},
			},
		},
		{
			name: "valid",
			fields: fields{
				issuer: "https://accounts.example.com",
			},
			args: args{
				audience: "s6BhdRkqt3",
				response: "fake-token",
			},
			prepare: func(verifier *tokenmock.MockVerifier, token *tokenmock.MockToken) {
				verifier.EXPECT().Parse("fake-token").Return(token, nil)
				token.EXPECT().Type().Return(HeaderType, nil)
				verifier.EXPECT().Claims(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(ctx any, key any, claims any) {
					switch v := claims.(type) {
					case *responseClaims:
						*v = responseClaims{
							Issuer:    "https://accounts.example.com",
							Audience:  "s6BhdRkqt3",
							Code:      "PyyFaux2o7Q0YfXBU32jhw.5FXSQpvr8akv9CeRDSd0QA",
							State:     "S8NJ7uqk5fY4EjNvP_G_FtyJu6pUsvH9jsYni9dMAJw",
							ExpiresAt: uint64(time.Now().Add(60 * time.Second).Unix()),
						}
					}
				}).Return(nil)
			},
			wantErr: false,
			want: &flowv1.AuthorizeResponse{
				Code:   "PyyFaux2o7Q0YfXBU32jhw.5FXSQpvr8akv9CeRDSd0QA",
				State:  "S8NJ7uqk5fY4EjNvP_G_FtyJu6pUsvH9jsYni9dMAJw",
				Issuer: "https://accounts.example.com",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockVerifier := tokenmock.NewMockVerifier(ctrl)
			mockToken := tokenmock.NewMockToken(ctrl)

			// Prepare mocks
			if tt.prepare != nil {
				tt.prepare(mockVerifier, mockToken)
			}

			d := Decoder(tt.fields.issuer, mockVerifier)
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
