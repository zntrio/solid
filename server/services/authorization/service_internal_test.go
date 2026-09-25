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

package authorization

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go.uber.org/mock/gomock"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	corev1 "zntr.io/solid/api/oidc/core/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/authzdetails"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/server/storage"
	storagemock "zntr.io/solid/server/storage/mock"
)

var cmpOpts = []cmp.Option{cmpopts.IgnoreUnexported(flowv1.AuthorizationRequest{}), cmpopts.IgnoreUnexported(flowv1.AuthorizeRequest{}), cmpopts.IgnoreUnexported(flowv1.AuthorizeResponse{}), cmpopts.IgnoreUnexported(flowv1.RegistrationRequest{}), cmpopts.IgnoreUnexported(flowv1.RegistrationResponse{}), cmpopts.IgnoreUnexported(corev1.Error{})}

func Test_service_validate(t *testing.T) {
	type args struct {
		ctx context.Context
		req *flowv1.AuthorizationRequest
	}
	tests := []struct {
		name      string
		args      args
		prepare   func(*storagemock.MockClientReader)
		validator authzdetails.Validator
		want      *corev1.Error
		wantErr   bool
	}{
		{
			name: "nil",
			args: args{
				ctx: context.Background(),
				req: nil,
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest().Build(),
		},
		{
			name: "empty request",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizationRequest{},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest().Build(),
		},
		{
			name: "missing scope",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
		},
		{
			name: "missing response_type",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					Scope:               "openid profile email",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
		},
		{
			name: "missing client_id",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					RedirectUri:         "https://client.example.org/cb",
					Nonce:               "XDwbBH4MokU8BmrZ",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
		},
		{
			name: "missing redirect_uri",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
		},
		{
			name: "invalid redirect_uri",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "hi/there?",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
		},
		{
			name: "missing state",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email",
					ClientId:            "s6BhdRkqt3",
					RedirectUri:         "https://client.example.org/cb",
					Nonce:               "XDwbBH4MokU8BmrZ",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest().Build(),
		},
		{
			name: "state too short",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email",
					ClientId:            "s6BhdRkqt3",
					RedirectUri:         "https://client.example.org/cb",
					State:               "oESIiuoybVxAJ",
					Nonce:               "XDwbBH4MokU8BmrZ",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest().State("oESIiuoybVxAJ").Build(),
		},
		{
			name: "missing audience",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizationRequest{
					ResponseType:        "code",
					Scope:               "openid profile email",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
		},
		{
			name: "missing nonce",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9",
					CodeChallengeMethod: "S256",
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
		},
		{
			name: "nonce too short",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwb",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9",
					CodeChallengeMethod: "S256",
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
		},
		{
			name: "missing code_challenge",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallengeMethod: "S256",
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
		},
		{
			name: "code_challenge too short",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9",
					CodeChallengeMethod: "S256",
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
		},
		{
			name: "missing code_challenge_method",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizationRequest{
					Audience:      "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:  "code",
					Scope:         "openid profile email",
					ClientId:      "s6BhdRkqt3",
					State:         "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:         "XDwbBH4MokU8BmrZ",
					RedirectUri:   "https://client.example.org/cb",
					CodeChallenge: "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
		},
		{
			name: "unsupported code_challenge_method",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "B385",
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
		},
		{
			name: "code_challenge contains reserved characters",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8$",
					CodeChallengeMethod: "S256",
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
		},
		{
			name: "unsupported response_type",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "token",
					Scope:               "openid profile email",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
				},
			},
			wantErr: true,
			want:    rfcerrors.UnsupportedResponseType().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
		},
		{
			name: "authorization_details with failing validator",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizationRequest{
					Audience:             "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:         "code",
					Scope:                "openid profile email",
					ClientId:             "s6BhdRkqt3",
					State:                "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:                "XDwbBH4MokU8BmrZ",
					RedirectUri:          "https://client.example.org/cb",
					CodeChallenge:        "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod:  "S256",
					AuthorizationDetails: []*tokenv1.AuthorizationDetail{{Type: "payment"}},
				},
			},
			validator: authzdetails.ValidatorFunc(
				func(context.Context, []*tokenv1.AuthorizationDetail) error {
					return fmt.Errorf("unsupported authorization_details")
				},
			),
			wantErr: true,
			want:    rfcerrors.InvalidAuthorizationDetails().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
		},
		{
			name: "response_mode jwt alias expands for code",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					ResponseMode:        new(oidc.ResponseModeJWT),
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&clientv1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
					ResponseModes: []string{oidc.ResponseModeQueryJWT},
				}, nil)
			},
			wantErr: false,
			want:    nil,
		},
		{
			name: "unsupported response_mode",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					ResponseMode:        new("test"),
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
		},
		{
			name: "error client not found",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(nil, storage.ErrNotFound)
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
		},
		{
			name: "error client storage error",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(nil, fmt.Errorf("foo"))
			},
			wantErr: true,
			want:    rfcerrors.ServerError().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
		},
		{
			name: "client don't support authorization code",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&clientv1.Client{
					GrantTypes: []string{"client_credentials"},
				}, nil)
			},
			wantErr: true,
			want:    rfcerrors.UnsupportedGrantType().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
		},
		{
			name: "client don't support code response_type",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&clientv1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"id_token"},
				}, nil)
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
		},
		{
			name: "client invalid redirect_uri",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&clientv1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"http://foo.com"},
				}, nil)
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
		},
		{
			name: "client doesn't support response_mode",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
					ResponseMode:        new(oidc.ResponseModeQueryJWT),
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&clientv1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
					ResponseModes: []string{oidc.ResponseModeQuery},
				}, nil)
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
		},
		// ---------------------------------------------------------------------
		{
			name: "valid : application uri",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email offline_access",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "com.example.app:/oauth2redirect",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
					Prompt:              new(oidc.PromptConsent),
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&clientv1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"com.example.app:/oauth2redirect"},
				}, nil)
			},
			wantErr: false,
			want:    nil,
		},
		{
			name: "valid",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email offline_access",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
					Prompt:              new(oidc.PromptConsent),
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&clientv1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				}, nil)
			},
			wantErr: false,
			want:    nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Arm mocks
			authorizationRequests := storagemock.NewMockAuthorizationRequest(ctrl)
			clients := storagemock.NewMockClientReader(ctrl)
			sessions := storagemock.NewMockAuthorizationCodeSessionWriter(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(clients)
			}

			s := &service{
				clients:                   clients,
				authorizationRequests:     authorizationRequests,
				authorizationCodeSessions: sessions,
				authzDetailsValidator:     tt.validator,
			}
			got, err := s.validate(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("service.Authorize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.name == "response_mode jwt alias expands for code" && tt.args.req.ResponseMode != nil && *tt.args.req.ResponseMode != oidc.ResponseModeQueryJWT {
				t.Errorf("response_mode jwt alias must expand to %s, got %s", oidc.ResponseModeQueryJWT, *tt.args.req.ResponseMode)
			}
			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
				t.Errorf("service.Authorize() res =%s", diff)
			}
		})
	}
}

func Fuzz_service_validate(f *testing.F) {
	f.Fuzz(func(t *testing.T, seed []byte) {
		// Arm mocks
		ctrl := gomock.NewController(t)
		authorizationRequests := storagemock.NewMockAuthorizationRequest(ctrl)
		clients := storagemock.NewMockClientReader(ctrl)
		sessions := storagemock.NewMockAuthorizationCodeSessionWriter(ctrl)

		// Prepare service
		s := &service{
			clients:                   clients,
			authorizationRequests:     authorizationRequests,
			authorizationCodeSessions: sessions,
		}

		// Making sure the function never panics
		s.validate(context.Background(), fuzzFillAuthorizationRequest(seed))
	})
}
