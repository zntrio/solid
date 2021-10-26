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

package jwsreq

import (
	"context"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/api/oidc"
	"zntr.io/solid/pkg/sdk/token"
	tokenmock "zntr.io/solid/pkg/sdk/token/mock"
	"zntr.io/solid/pkg/sdk/types"
)

func Test_jwtEncoder_Encode(t *testing.T) {
	type fields struct {
		signer token.Signer
	}
	type args struct {
		ctx context.Context
		ar  *corev1.AuthorizationRequest
	}
	tests := []struct {
		name    string
		fields  fields
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
			name: "nil authorization request",
			args: args{
				ar: nil,
			},
			wantErr: true,
		},
		{
			name: "signer error",
			args: args{
				ar: &corev1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email offline_access",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
					Prompt:              types.StringRef(oidc.PromptConsent),
				},
			},
			prepare: func(signer *tokenmock.MockSigner) {
				signer.EXPECT().Sign(gomock.Any(), gomock.Any()).Return("", fmt.Errorf("foo"))
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				ar: &corev1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email offline_access",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
					Prompt:              types.StringRef(oidc.PromptConsent),
				},
			},
			prepare: func(signer *tokenmock.MockSigner) {
				signer.EXPECT().Sign(gomock.Any(), gomock.Any()).Return("fake-token", nil)
			},
			wantErr: false,
			want:    "fake-token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockSigner := tokenmock.NewMockSigner(ctrl)

			// Prepare mocks
			if tt.prepare != nil {
				tt.prepare(mockSigner)
			}

			enc := AuthorizationRequestEncoder(mockSigner)
			got, err := enc.Encode(tt.args.ctx, tt.args.ar)
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
