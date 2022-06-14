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

package dpop

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/golang/mock/gomock"

	"zntr.io/solid/sdk/token"
	tokenmock "zntr.io/solid/sdk/token/mock"
	"zntr.io/solid/sdk/types"
	storagemock "zntr.io/solid/server/storage/mock"
)

func Test_defaultVerifier_Verify(t *testing.T) {
	type args struct {
		ctx   context.Context
		htm   string
		htu   string
		proof string
		opts  []Option
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*storagemock.MockDPoP, *tokenmock.MockVerifier, *tokenmock.MockToken)
		want    string
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "htm is blank",
			args: args{
				htm: "",
			},
			wantErr: true,
		},
		{
			name: "htu is blank",
			args: args{
				htm: http.MethodGet,
				htu: "",
			},
			wantErr: true,
		},
		{
			name: "proof is blank",
			args: args{
				htm:   http.MethodGet,
				htu:   "https://server.com/resource",
				proof: "",
			},
			wantErr: true,
		},
		{
			name: "htu is invalid",
			args: args{
				htm:   http.MethodGet,
				htu:   "http//server.com/resource",
				proof: "fake-proof",
			},
			wantErr: true,
		},
		{
			name: "htm is invalid",
			args: args{
				htm:   "POUET",
				htu:   "https://server.com/resource",
				proof: "fake-proof",
			},
			wantErr: true,
		},
		{
			name: "proof is syntaxically invalid",
			args: args{
				htm:   http.MethodGet,
				htu:   "https://server.com/resource",
				proof: "fake-proof",
			},
			prepare: func(_ *storagemock.MockDPoP, verifier *tokenmock.MockVerifier, _ *tokenmock.MockToken) {
				verifier.EXPECT().Parse("fake-proof").Return(nil, fmt.Errorf("foo"))
			},
			wantErr: true,
		},
		{
			name: "token is nil",
			args: args{
				htm:   http.MethodGet,
				htu:   "https://server.com/resource",
				proof: "fake-proof",
			},
			prepare: func(_ *storagemock.MockDPoP, verifier *tokenmock.MockVerifier, _ *tokenmock.MockToken) {
				verifier.EXPECT().Parse("fake-proof").Return(nil, nil)
			},
			wantErr: true,
		},
		{
			name: "invalid token headers",
			args: args{
				htm:   http.MethodGet,
				htu:   "https://server.com/resource",
				proof: "fake-proof",
			},
			prepare: func(_ *storagemock.MockDPoP, verifier *tokenmock.MockVerifier, token *tokenmock.MockToken) {
				token.EXPECT().Type().Return("", fmt.Errorf("foo"))
				verifier.EXPECT().Parse("fake-proof").Return(token, nil)
			},
			wantErr: true,
		},
		{
			name: "unable to extract claims",
			args: args{
				htm:   http.MethodGet,
				htu:   "https://server.com/resource",
				proof: "fake-proof",
			},
			prepare: func(_ *storagemock.MockDPoP, verifier *tokenmock.MockVerifier, token *tokenmock.MockToken) {
				token.EXPECT().Type().Return(HeaderType, nil)
				token.EXPECT().PublicKey().Return(&struct{}{}, nil).Times(2)
				token.EXPECT().Claims(gomock.Any(), gomock.Any()).Return(fmt.Errorf("foo"))
				verifier.EXPECT().Parse("fake-proof").Return(token, nil)
			},
			wantErr: true,
		},
		{
			name: "unable to validate claims",
			args: args{
				htm:   http.MethodGet,
				htu:   "https://server.com/resource",
				proof: "fake-proof",
			},
			prepare: func(_ *storagemock.MockDPoP, verifier *tokenmock.MockVerifier, token *tokenmock.MockToken) {
				token.EXPECT().Type().Return(HeaderType, nil)
				token.EXPECT().PublicKey().Return(&struct{}{}, nil).Times(2)
				token.EXPECT().Claims(gomock.Any(), gomock.Any()).Return(nil)
				verifier.EXPECT().Parse("fake-proof").Return(token, nil)
			},
			wantErr: true,
		},
		{
			name: "proof storage error",
			args: args{
				htm:   http.MethodGet,
				htu:   "https://server.com/resource",
				proof: "fake-proof",
			},
			prepare: func(proofs *storagemock.MockDPoP, verifier *tokenmock.MockVerifier, token *tokenmock.MockToken) {
				verifier.EXPECT().Parse("fake-proof").Return(token, nil)
				token.EXPECT().Type().Return(HeaderType, nil)
				token.EXPECT().PublicKey().Return(&struct{}{}, nil).Times(2)
				token.EXPECT().Claims(gomock.Any(), gomock.Any()).Do(func(key any, claims any) {
					switch v := claims.(type) {
					case *proofClaims:
						*v = proofClaims{
							HTTPMethod: http.MethodGet,
							HTTPURL:    "https://server.com/resource",
							IssuedAt:   uint64(time.Now().Add(-1 * time.Second).Unix()),
							JTI:        "non-existent-jti",
						}
					}
				}).Return(nil)
				proofs.EXPECT().Exists(gomock.Any(), "oeB2o7_-r7BslYpxZtbpMhlOJIGscF82i8E5LRBUkzk").Return(false, fmt.Errorf("foo"))
			},
			wantErr: true,
		},
		{
			name: "proof found in storage",
			args: args{
				htm:   http.MethodGet,
				htu:   "https://server.com/resource",
				proof: "fake-proof",
			},
			prepare: func(proofs *storagemock.MockDPoP, verifier *tokenmock.MockVerifier, token *tokenmock.MockToken) {
				verifier.EXPECT().Parse("fake-proof").Return(token, nil)
				token.EXPECT().Type().Return(HeaderType, nil)
				token.EXPECT().PublicKey().Return(&struct{}{}, nil).Times(2)
				token.EXPECT().Claims(gomock.Any(), gomock.Any()).Do(func(key any, claims any) {
					switch v := claims.(type) {
					case *proofClaims:
						*v = proofClaims{
							HTTPMethod: http.MethodGet,
							HTTPURL:    "https://server.com/resource",
							IssuedAt:   uint64(time.Now().Add(-1 * time.Second).Unix()),
							JTI:        "non-existent-jti",
						}
					}
				}).Return(nil)
				proofs.EXPECT().Exists(gomock.Any(), "oeB2o7_-r7BslYpxZtbpMhlOJIGscF82i8E5LRBUkzk").Return(true, nil)
			},
			wantErr: true,
		},
		{
			name: "proof registration error",
			args: args{
				htm:   http.MethodGet,
				htu:   "https://server.com/resource",
				proof: "fake-proof",
			},
			prepare: func(proofs *storagemock.MockDPoP, verifier *tokenmock.MockVerifier, token *tokenmock.MockToken) {
				verifier.EXPECT().Parse("fake-proof").Return(token, nil)
				token.EXPECT().Type().Return(HeaderType, nil)
				token.EXPECT().PublicKey().Return(&struct{}{}, nil).Times(2)
				token.EXPECT().Claims(gomock.Any(), gomock.Any()).Do(func(key any, claims any) {
					switch v := claims.(type) {
					case *proofClaims:
						*v = proofClaims{
							HTTPMethod: http.MethodGet,
							HTTPURL:    "https://server.com/resource",
							IssuedAt:   uint64(time.Now().Add(-1 * time.Second).Unix()),
							JTI:        "non-existent-jti",
						}
					}
				}).Return(nil)
				proofs.EXPECT().Exists(gomock.Any(), "oeB2o7_-r7BslYpxZtbpMhlOJIGscF82i8E5LRBUkzk").Return(false, nil)
				proofs.EXPECT().Register(gomock.Any(), "oeB2o7_-r7BslYpxZtbpMhlOJIGscF82i8E5LRBUkzk").Return(fmt.Errorf("foo"))
			},
			wantErr: true,
		},
		{
			name: "confirmation generation error",
			args: args{
				htm:   http.MethodGet,
				htu:   "https://server.com/resource",
				proof: "fake-proof",
			},
			prepare: func(proofs *storagemock.MockDPoP, verifier *tokenmock.MockVerifier, token *tokenmock.MockToken) {
				verifier.EXPECT().Parse("fake-proof").Return(token, nil)
				token.EXPECT().Type().Return(HeaderType, nil)
				token.EXPECT().PublicKey().Return(&struct{}{}, nil).Times(2)
				token.EXPECT().Claims(gomock.Any(), gomock.Any()).Do(func(key any, claims any) {
					switch v := claims.(type) {
					case *proofClaims:
						*v = proofClaims{
							HTTPMethod: http.MethodGet,
							HTTPURL:    "https://server.com/resource",
							IssuedAt:   uint64(time.Now().Add(-1 * time.Second).Unix()),
							JTI:        "non-existent-jti",
						}
					}
				}).Return(nil)
				proofs.EXPECT().Exists(gomock.Any(), "oeB2o7_-r7BslYpxZtbpMhlOJIGscF82i8E5LRBUkzk").Return(false, nil)
				proofs.EXPECT().Register(gomock.Any(), "oeB2o7_-r7BslYpxZtbpMhlOJIGscF82i8E5LRBUkzk").Return(nil)
				token.EXPECT().PublicKeyThumbPrint().Return("", fmt.Errorf("foo"))
			},
			wantErr: true,
		},
		{
			name: "error with token - token not bound",
			args: args{
				htm:   http.MethodGet,
				htu:   "https://server.com/resource",
				proof: "fake-proof",
				opts: []Option{
					WithTokenValue("1234567890"),
					WithTokenConfirmation("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"),
				},
			},
			prepare: func(proofs *storagemock.MockDPoP, verifier *tokenmock.MockVerifier, token *tokenmock.MockToken) {
				verifier.EXPECT().Parse("fake-proof").Return(token, nil)
				token.EXPECT().Type().Return(HeaderType, nil)
				token.EXPECT().PublicKey().Return(&struct{}{}, nil).Times(2)
				token.EXPECT().Claims(gomock.Any(), gomock.Any()).Do(func(key any, claims any) {
					switch v := claims.(type) {
					case *proofClaims:
						*v = proofClaims{
							HTTPMethod: http.MethodGet,
							HTTPURL:    "https://server.com/resource",
							IssuedAt:   uint64(time.Now().Add(-1 * time.Second).Unix()),
							JTI:        "non-existent-jti",
						}
					}
				}).Return(nil)
				proofs.EXPECT().Exists(gomock.Any(), "oeB2o7_-r7BslYpxZtbpMhlOJIGscF82i8E5LRBUkzk").Return(false, nil)
				proofs.EXPECT().Register(gomock.Any(), "oeB2o7_-r7BslYpxZtbpMhlOJIGscF82i8E5LRBUkzk").Return(nil)
				token.EXPECT().PublicKeyThumbPrint().Return("fake-confirmation", nil)
			},
			wantErr: true,
		},
		{
			name: "error with token - token mismatch",
			args: args{
				htm:   http.MethodGet,
				htu:   "https://server.com/resource",
				proof: "fake-proof",
				opts: []Option{
					WithTokenValue("another-token"),
					WithTokenConfirmation("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"),
				},
			},
			prepare: func(proofs *storagemock.MockDPoP, verifier *tokenmock.MockVerifier, token *tokenmock.MockToken) {
				verifier.EXPECT().Parse("fake-proof").Return(token, nil)
				token.EXPECT().Type().Return(HeaderType, nil)
				token.EXPECT().PublicKey().Return(&struct{}{}, nil).Times(2)
				token.EXPECT().Claims(gomock.Any(), gomock.Any()).Do(func(key any, claims any) {
					switch v := claims.(type) {
					case *proofClaims:
						*v = proofClaims{
							HTTPMethod:      http.MethodGet,
							HTTPURL:         "https://server.com/resource",
							IssuedAt:        uint64(time.Now().Add(-1 * time.Second).Unix()),
							JTI:             "non-existent-jti",
							AccessTokenHash: types.StringRef(""),
						}
					}
				}).Return(nil)
				proofs.EXPECT().Exists(gomock.Any(), "oeB2o7_-r7BslYpxZtbpMhlOJIGscF82i8E5LRBUkzk").Return(false, nil)
				proofs.EXPECT().Register(gomock.Any(), "oeB2o7_-r7BslYpxZtbpMhlOJIGscF82i8E5LRBUkzk").Return(nil)
				token.EXPECT().PublicKeyThumbPrint().Return("fake-confirmation", nil)
			},
			wantErr: true,
		},
		{
			name: "error with token - proof mismatch",
			args: args{
				htm:   http.MethodGet,
				htu:   "https://server.com/resource",
				proof: "fake-proof",
				opts: []Option{
					WithTokenValue("1234567890"),
					WithTokenConfirmation("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"),
				},
			},
			prepare: func(proofs *storagemock.MockDPoP, verifier *tokenmock.MockVerifier, token *tokenmock.MockToken) {
				verifier.EXPECT().Parse("fake-proof").Return(token, nil)
				token.EXPECT().Type().Return(HeaderType, nil)
				token.EXPECT().PublicKey().Return(&struct{}{}, nil).Times(2)
				token.EXPECT().Claims(gomock.Any(), gomock.Any()).Do(func(key any, claims any) {
					switch v := claims.(type) {
					case *proofClaims:
						*v = proofClaims{
							HTTPMethod:      http.MethodGet,
							HTTPURL:         "https://server.com/resource",
							IssuedAt:        uint64(time.Now().Add(-1 * time.Second).Unix()),
							JTI:             "non-existent-jti",
							AccessTokenHash: types.StringRef("x3Xnt1ft5jDNCqERO9ECZhqziCnKUqZCKreChi8mhkY"),
						}
					}
				}).Return(nil)
				proofs.EXPECT().Exists(gomock.Any(), "oeB2o7_-r7BslYpxZtbpMhlOJIGscF82i8E5LRBUkzk").Return(false, nil)
				proofs.EXPECT().Register(gomock.Any(), "oeB2o7_-r7BslYpxZtbpMhlOJIGscF82i8E5LRBUkzk").Return(nil)
				token.EXPECT().PublicKeyThumbPrint().Return("fake-confirmation", nil)
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				htm:   http.MethodGet,
				htu:   "https://server.com/resource",
				proof: "fake-proof",
			},
			prepare: func(proofs *storagemock.MockDPoP, verifier *tokenmock.MockVerifier, token *tokenmock.MockToken) {
				verifier.EXPECT().Parse("fake-proof").Return(token, nil)
				token.EXPECT().Type().Return(HeaderType, nil)
				token.EXPECT().PublicKey().Return(&struct{}{}, nil).Times(2)
				token.EXPECT().Claims(gomock.Any(), gomock.Any()).Do(func(key any, claims any) {
					switch v := claims.(type) {
					case *proofClaims:
						*v = proofClaims{
							HTTPMethod: http.MethodGet,
							HTTPURL:    "https://server.com/resource",
							IssuedAt:   uint64(time.Now().Add(-1 * time.Second).Unix()),
							JTI:        "non-existent-jti",
						}
					}
				}).Return(nil)
				proofs.EXPECT().Exists(gomock.Any(), "oeB2o7_-r7BslYpxZtbpMhlOJIGscF82i8E5LRBUkzk").Return(false, nil)
				proofs.EXPECT().Register(gomock.Any(), "oeB2o7_-r7BslYpxZtbpMhlOJIGscF82i8E5LRBUkzk").Return(nil)
				token.EXPECT().PublicKeyThumbPrint().Return("fake-confirmation", nil)
			},
			wantErr: false,
			want:    "fake-confirmation",
		},
		{
			name: "valid with token",
			args: args{
				htm:   http.MethodGet,
				htu:   "https://server.com/resource",
				proof: "fake-proof",
				opts: []Option{
					WithTokenValue("1234567890"),
					WithTokenConfirmation("fake-confirmation"),
				},
			},
			prepare: func(proofs *storagemock.MockDPoP, verifier *tokenmock.MockVerifier, token *tokenmock.MockToken) {
				verifier.EXPECT().Parse("fake-proof").Return(token, nil)
				token.EXPECT().Type().Return(HeaderType, nil)
				token.EXPECT().PublicKey().Return(&struct{}{}, nil).Times(2)
				token.EXPECT().Claims(gomock.Any(), gomock.Any()).Do(func(key any, claims any) {
					switch v := claims.(type) {
					case *proofClaims:
						*v = proofClaims{
							HTTPMethod:      http.MethodGet,
							HTTPURL:         "https://server.com/resource",
							IssuedAt:        uint64(time.Now().Add(-1 * time.Second).Unix()),
							JTI:             "non-existent-jti",
							AccessTokenHash: types.StringRef("x3Xnt1ft5jDNCqERO9ECZhqziCnKUqZCKreChi8mhkY"),
						}
					}
				}).Return(nil)
				proofs.EXPECT().Exists(gomock.Any(), "oeB2o7_-r7BslYpxZtbpMhlOJIGscF82i8E5LRBUkzk").Return(false, nil)
				proofs.EXPECT().Register(gomock.Any(), "oeB2o7_-r7BslYpxZtbpMhlOJIGscF82i8E5LRBUkzk").Return(nil)
				token.EXPECT().PublicKeyThumbPrint().Return("fake-confirmation", nil)
			},
			wantErr: false,
			want:    "fake-confirmation",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockStorage := storagemock.NewMockDPoP(ctrl)
			mockVerifier := tokenmock.NewMockVerifier(ctrl)
			mockToken := tokenmock.NewMockToken(ctrl)

			// Prepare mocks
			if tt.prepare != nil {
				tt.prepare(mockStorage, mockVerifier, mockToken)
			}

			v := DefaultVerifier(mockStorage, mockVerifier)
			got, err := v.Verify(tt.args.ctx, tt.args.htm, tt.args.htu, tt.args.proof, tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("defaultVerifier.Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("defaultVerifier.Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_defaultVerifier_validateProofHeader(t *testing.T) {
	type args struct {
		token func(ctrl *gomock.Controller) token.Token
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "nil",
			args: args{
				token: func(ctrl *gomock.Controller) token.Token {
					return nil
				},
			},
			wantErr: true,
		},
		{
			name: "type error",
			args: args{
				token: func(ctrl *gomock.Controller) token.Token {
					mockToken := tokenmock.NewMockToken(ctrl)
					mockToken.EXPECT().Type().Return("", fmt.Errorf("foo"))
					return mockToken
				},
			},
			wantErr: true,
		},
		{
			name: "invalid type",
			args: args{
				token: func(ctrl *gomock.Controller) token.Token {
					mockToken := tokenmock.NewMockToken(ctrl)
					mockToken.EXPECT().Type().Return("foo", nil)
					return mockToken
				},
			},
			wantErr: true,
		},
		{
			name: "public key error",
			args: args{
				token: func(ctrl *gomock.Controller) token.Token {
					mockToken := tokenmock.NewMockToken(ctrl)
					mockToken.EXPECT().Type().Return(HeaderType, nil)
					mockToken.EXPECT().PublicKey().Return(nil, fmt.Errorf("foo"))
					return mockToken
				},
			},
			wantErr: true,
		},
		{
			name: "nil public key",
			args: args{
				token: func(ctrl *gomock.Controller) token.Token {
					mockToken := tokenmock.NewMockToken(ctrl)
					mockToken.EXPECT().Type().Return(HeaderType, nil)
					mockToken.EXPECT().PublicKey().Return(nil, nil)
					return mockToken
				},
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				token: func(ctrl *gomock.Controller) token.Token {
					mockToken := tokenmock.NewMockToken(ctrl)
					mockToken.EXPECT().Type().Return(HeaderType, nil)
					mockToken.EXPECT().PublicKey().Return(&struct{}{}, nil)
					return mockToken
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockStorage := storagemock.NewMockDPoP(ctrl)
			mockVerifier := tokenmock.NewMockVerifier(ctrl)

			v := &defaultVerifier{
				proofs:   mockStorage,
				verifier: mockVerifier,
			}
			if err := v.validateProofHeader(tt.args.token(ctrl)); (err != nil) != tt.wantErr {
				t.Errorf("defaultVerifier.validateHeader() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_defaultVerifier_extractProofClaims(t *testing.T) {
	type args struct {
		token func(ctrl *gomock.Controller) token.Token
	}
	tests := []struct {
		name    string
		args    args
		want    *proofClaims
		wantErr bool
	}{
		{
			name: "token is nil",
			args: args{
				token: func(ctrl *gomock.Controller) token.Token {
					return nil
				},
			},
			wantErr: true,
		},
		{
			name: "public key error",
			args: args{
				token: func(ctrl *gomock.Controller) token.Token {
					mockToken := tokenmock.NewMockToken(ctrl)
					mockToken.EXPECT().PublicKey().Return(nil, fmt.Errorf("foo"))
					return mockToken
				},
			},
			wantErr: true,
		},
		{
			name: "claims extraction error",
			args: args{
				token: func(ctrl *gomock.Controller) token.Token {
					mockToken := tokenmock.NewMockToken(ctrl)
					mockToken.EXPECT().PublicKey().Return(&struct{}{}, nil)
					mockToken.EXPECT().Claims(gomock.Any(), gomock.Any()).Return(fmt.Errorf("foo"))
					return mockToken
				},
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				token: func(ctrl *gomock.Controller) token.Token {
					mockToken := tokenmock.NewMockToken(ctrl)
					mockToken.EXPECT().PublicKey().Return(&struct{}{}, nil)
					mockToken.EXPECT().Claims(gomock.Any(), gomock.Any()).Return(nil)
					return mockToken
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockStorage := storagemock.NewMockDPoP(ctrl)
			mockVerifier := tokenmock.NewMockVerifier(ctrl)

			v := &defaultVerifier{
				proofs:   mockStorage,
				verifier: mockVerifier,
			}
			_, err := v.extractProofClaims(tt.args.token(ctrl))
			if (err != nil) != tt.wantErr {
				t.Errorf("defaultVerifier.extractProofClaims() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_defaultVerifier_validateProofClaims(t *testing.T) {
	type args struct {
		htm    string
		htu    string
		claims *proofClaims
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "htm blank",
			args: args{
				htm: "",
			},
			wantErr: true,
		},
		{
			name: "htu blank",
			args: args{
				htm: http.MethodPost,
				htu: "",
			},
			wantErr: true,
		},
		{
			name: "claims is nil",
			args: args{
				htm: http.MethodPost,
				htu: "https://server.com/resource",
			},
			wantErr: true,
		},
		{
			name: "http method mismatch",
			args: args{
				htm: http.MethodGet,
				htu: "https://server.com/resource",
				claims: &proofClaims{
					HTTPMethod: http.MethodPost,
				},
			},
			wantErr: true,
		},
		{
			name: "http scheme mismatch",
			args: args{
				htm: http.MethodPost,
				htu: "https://server.com/resource",
				claims: &proofClaims{
					HTTPMethod: http.MethodPost,
					HTTPURL:    "http://server.com/resource",
				},
			},
			wantErr: true,
		},
		{
			name: "expired proof",
			args: args{
				htm: http.MethodPost,
				htu: "https://server.com/resource",
				claims: &proofClaims{
					HTTPMethod: http.MethodPost,
					HTTPURL:    "https://server.com/resource",
					IssuedAt:   uint64(time.Now().Add(-24 * time.Hour).Unix()),
				},
			},
			wantErr: true,
		},
		{
			name: "future proof",
			args: args{
				htm: http.MethodPost,
				htu: "https://server.com/resource",
				claims: &proofClaims{
					HTTPMethod: http.MethodPost,
					HTTPURL:    "https://server.com/resource",
					IssuedAt:   uint64(time.Now().Add(24 * time.Hour).Unix()),
				},
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				htm: http.MethodPost,
				htu: "https://server.com/resource",
				claims: &proofClaims{
					HTTPMethod: http.MethodPost,
					HTTPURL:    "https://server.com/resource",
					IssuedAt:   uint64(time.Now().Add(-1 * time.Second).Unix()),
					JTI:        "cool",
				},
			},
			want:    "BSi1fzwnJO33tN-kAj7eslyBNql4tgXxj3Em-21kzhE",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockStorage := storagemock.NewMockDPoP(ctrl)
			mockVerifier := tokenmock.NewMockVerifier(ctrl)

			v := &defaultVerifier{
				proofs:   mockStorage,
				verifier: mockVerifier,
			}
			got, err := v.validateProofClaims(tt.args.htm, tt.args.htu, tt.args.claims)
			if (err != nil) != tt.wantErr {
				t.Errorf("defaultVerifier.validateProofClaims() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("defaultVerifier.validateProofClaims() = %v, want %v", got, tt.want)
			}
		})
	}
}
