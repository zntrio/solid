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

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
	registrationv1 "go.zenithar.org/solid/api/gen/go/oidc/registration/v1"
	"go.zenithar.org/solid/api/oidc"
	"go.zenithar.org/solid/pkg/rfcerrors"
	"go.zenithar.org/solid/pkg/storage"
	storagemock "go.zenithar.org/solid/pkg/storage/mock"

	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var (
	cmpOpts = []cmp.Option{
		cmpopts.IgnoreUnexported(wrappers.StringValue{}),
		cmpopts.IgnoreUnexported(corev1.AuthorizationRequest{}),
		cmpopts.IgnoreUnexported(corev1.AuthorizationResponse{}),
		cmpopts.IgnoreUnexported(corev1.RegistrationRequest{}),
		cmpopts.IgnoreUnexported(corev1.RegistrationResponse{}),
		cmpopts.IgnoreUnexported(corev1.Error{}),
	}
)

func Test_service_validate(t *testing.T) {
	type args struct {
		ctx context.Context
		req *corev1.AuthorizationRequest
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*storagemock.MockClientReader)
		want    *corev1.Error
		wantErr bool
	}{
		{
			name: "nil",
			args: args{
				ctx: context.Background(),
				req: nil,
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest(""),
		},
		{
			name: "empty request",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationRequest{},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest("<missing>"),
		},
		{
			name: "missing scope",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationRequest{
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
			want:    rfcerrors.InvalidRequest("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU"),
		},
		{
			name: "missing response_type",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationRequest{
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
			want:    rfcerrors.InvalidRequest("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU"),
		},
		{
			name: "missing client_id",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationRequest{
					ResponseType:        "code",
					Scope:               "openid profile email",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU"),
		},
		{
			name: "missing redirect_uri",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationRequest{
					ResponseType:        "code",
					Scope:               "openid profile email",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU"),
		},
		{
			name: "missing state",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationRequest{
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
			want:    rfcerrors.InvalidRequest("<missing>"),
		},
		{
			name: "state too short",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationRequest{
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
			want:    rfcerrors.InvalidRequest("oESIiuoybVxAJ"),
		},
		{
			name: "missing nonce",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationRequest{
					ResponseType:        "code",
					Scope:               "openid profile email",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU"),
		},
		{
			name: "nonce too short",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationRequest{
					ResponseType:        "code",
					Scope:               "openid profile email",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU"),
		},
		{
			name: "missing code_challenge",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationRequest{
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
			want:    rfcerrors.InvalidRequest("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU"),
		},
		{
			name: "code_challenge too short",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationRequest{
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
			want:    rfcerrors.InvalidRequest("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU"),
		},
		{
			name: "missing code_challenge_method",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationRequest{
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
			want:    rfcerrors.InvalidRequest("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU"),
		},
		{
			name: "unsupported code_challenge_method",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationRequest{
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
			want:    rfcerrors.InvalidRequest("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU"),
		},
		{
			name: "error client not found",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationRequest{
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
			want:    rfcerrors.InvalidRequest("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU"),
		},
		{
			name: "error client storage error",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationRequest{
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
			want:    rfcerrors.ServerError("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU"),
		},
		{
			name: "client don't support authorization code",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationRequest{
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
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&registrationv1.Client{
					GrantTypes: []string{"client_credentials"},
				}, nil)
			},
			wantErr: true,
			want:    rfcerrors.UnsupportedGrantType("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU"),
		},
		{
			name: "client don't support code response_type",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationRequest{
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
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&registrationv1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"id_token"},
				}, nil)
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU"),
		},
		{
			name: "client invalid redirect_uri",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationRequest{
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
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&registrationv1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"http://foo.com"},
				}, nil)
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU"),
		},
		// ---------------------------------------------------------------------
		{
			name: "valid",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationRequest{
					ResponseType:        "code",
					Scope:               "openid profile email offline_access",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
					Prompt:              &wrappers.StringValue{Value: "consent"},
				},
			},
			prepare: func(clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&registrationv1.Client{
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
			sessions := storagemock.NewMockSessionWriter(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(clients)
			}

			s := &service{
				clients:               clients,
				authorizationRequests: authorizationRequests,
				sessions:              sessions,
			}
			got, err := s.validate(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("service.Authorize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
				t.Errorf("service.Authorize() res =%s", diff)
			}
		})
	}
}
