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

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	fuzz "github.com/google/gofuzz"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	sessionv1 "zntr.io/solid/api/oidc/session/v1"
	"zntr.io/solid/oidc"
	generatormock "zntr.io/solid/sdk/generator/mock"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/types"
	"zntr.io/solid/server/storage"
	storagemock "zntr.io/solid/server/storage/mock"
)

func Test_service_Authorize(t *testing.T) {
	type args struct {
		ctx context.Context
		req *flowv1.AuthorizeRequest
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*storagemock.MockAuthorizationRequest, *storagemock.MockClientReader, *storagemock.MockAuthorizationCodeSessionWriter, *generatormock.MockAuthorizationCode, *generatormock.MockRequestURI)
		want    *flowv1.AuthorizeResponse
		wantErr bool
	}{
		{
			name: "nil",
			args: args{
				ctx: context.Background(),
				req: nil,
			},
			wantErr: true,
			want: &flowv1.AuthorizeResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "nil request",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizeRequest{
					Request: nil,
				},
			},
			wantErr: true,
			want: &flowv1.AuthorizeResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty issuer",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizeRequest{
					Issuer:  "",
					Subject: "foo",
					Request: &flowv1.AuthorizationRequest{
						RequestUri: types.StringRef("urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
					},
				},
			},
			wantErr: true,
			want: &flowv1.AuthorizeResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty subject",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizeRequest{
					Issuer:  "https://honest.as.example",
					Subject: "",
					Request: &flowv1.AuthorizationRequest{
						RequestUri: types.StringRef("urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
					},
				},
			},
			wantErr: true,
			want: &flowv1.AuthorizeResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "with invalid request_uri",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizeRequest{
					Issuer:  "https://honest.as.example",
					Subject: "foo",
					Request: &flowv1.AuthorizationRequest{
						RequestUri: types.StringRef("123-456-789"),
					},
				},
			},
			prepare: func(mar *storagemock.MockAuthorizationRequest, mcr *storagemock.MockClientReader, macsw *storagemock.MockAuthorizationCodeSessionWriter, mac *generatormock.MockAuthorizationCode, mru *generatormock.MockRequestURI) {
				mru.EXPECT().Validate(gomock.Any(), "https://honest.as.example", "123-456-789").Return(fmt.Errorf("test"))
			},
			wantErr: true,
			want: &flowv1.AuthorizeResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "with request_uri not found error",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizeRequest{
					Issuer:  "https://honest.as.example",
					Subject: "foo",
					Request: &flowv1.AuthorizationRequest{
						RequestUri: types.StringRef("urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
					},
				},
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, _ *storagemock.MockClientReader, _ *storagemock.MockAuthorizationCodeSessionWriter, _ *generatormock.MockAuthorizationCode, mru *generatormock.MockRequestURI) {
				mru.EXPECT().Validate(gomock.Any(), "https://honest.as.example", "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(nil)
				ar.EXPECT().Get(gomock.Any(), "https://honest.as.example", "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(nil, storage.ErrNotFound)
			},
			wantErr: true,
			want: &flowv1.AuthorizeResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "with request_uri storage error",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizeRequest{
					Issuer:  "https://honest.as.example",
					Subject: "foo",
					Request: &flowv1.AuthorizationRequest{
						RequestUri: types.StringRef("urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
					},
				},
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, _ *storagemock.MockClientReader, _ *storagemock.MockAuthorizationCodeSessionWriter, _ *generatormock.MockAuthorizationCode, mru *generatormock.MockRequestURI) {
				mru.EXPECT().Validate(gomock.Any(), "https://honest.as.example", "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(nil)
				ar.EXPECT().Get(gomock.Any(), "https://honest.as.example", "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(nil, fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &flowv1.AuthorizeResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "with request_uri exist with not found error during deletion",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizeRequest{
					Issuer:  "https://honest.as.example",
					Subject: "foo",
					Request: &flowv1.AuthorizationRequest{
						RequestUri: types.StringRef("urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
					},
				},
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, _ *storagemock.MockClientReader, _ *storagemock.MockAuthorizationCodeSessionWriter, _ *generatormock.MockAuthorizationCode, mru *generatormock.MockRequestURI) {
				mru.EXPECT().Validate(gomock.Any(), "https://honest.as.example", "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(nil)
				ar.EXPECT().Get(gomock.Any(), "https://honest.as.example", "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(&flowv1.AuthorizationRequest{}, nil)
				ar.EXPECT().Delete(gomock.Any(), "https://honest.as.example", "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(storage.ErrNotFound)
			},
			wantErr: true,
			want: &flowv1.AuthorizeResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "with request_uri exist but deletion error",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizeRequest{
					Issuer:  "https://honest.as.example",
					Subject: "foo",
					Request: &flowv1.AuthorizationRequest{
						RequestUri: types.StringRef("urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
					},
				},
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, _ *storagemock.MockClientReader, _ *storagemock.MockAuthorizationCodeSessionWriter, _ *generatormock.MockAuthorizationCode, mru *generatormock.MockRequestURI) {
				mru.EXPECT().Validate(gomock.Any(), "https://honest.as.example", "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(nil)
				ar.EXPECT().Get(gomock.Any(), "https://honest.as.example", "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(&flowv1.AuthorizationRequest{}, nil)
				ar.EXPECT().Delete(gomock.Any(), "https://honest.as.example", "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &flowv1.AuthorizeResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "authorization code generation error",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizeRequest{
					Issuer:  "https://honest.as.example",
					Subject: "foo",
					Request: &flowv1.AuthorizationRequest{
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
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, clients *storagemock.MockClientReader, sessions *storagemock.MockAuthorizationCodeSessionWriter, codes *generatormock.MockAuthorizationCode, _ *generatormock.MockRequestURI) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&clientv1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				}, nil)
				codes.EXPECT().Generate(gomock.Any(), "https://honest.as.example").Return("", fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &flowv1.AuthorizeResponse{
				Error: rfcerrors.ServerError().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
			},
		},
		{
			name: "authorization session registration error",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizeRequest{
					Issuer:  "https://honest.as.example",
					Subject: "foo",
					Request: &flowv1.AuthorizationRequest{
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
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, clients *storagemock.MockClientReader, sessions *storagemock.MockAuthorizationCodeSessionWriter, codes *generatormock.MockAuthorizationCode, _ *generatormock.MockRequestURI) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&clientv1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				}, nil)
				codes.EXPECT().Generate(gomock.Any(), "https://honest.as.example").Return("owtjMpUVdrGsn0FPPDTzC0sXWWl3btIYPQC2NGowzNVKeB35EC4RG1ZhLy2OtUT", nil)
				sessions.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(uint64(0), fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &flowv1.AuthorizeResponse{
				Error: rfcerrors.ServerError().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
			},
		},
		{
			name: "offline_access scope with nil prompt",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizeRequest{
					Issuer:  "https://honest.as.example",
					Subject: "foo",
					Request: &flowv1.AuthorizationRequest{
						Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						ResponseType:        "code",
						Scope:               "openid profile email offline_access",
						ClientId:            "s6BhdRkqt3",
						State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
						Nonce:               "XDwbBH4MokU8BmrZ",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
						CodeChallengeMethod: "S256",
						Prompt:              nil,
					},
				},
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, clients *storagemock.MockClientReader, sessions *storagemock.MockAuthorizationCodeSessionWriter, codes *generatormock.MockAuthorizationCode, _ *generatormock.MockRequestURI) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&clientv1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				}, nil)
				codes.EXPECT().Generate(gomock.Any(), "https://honest.as.example").Return("owtjMpUVdrGsn0FPPDTzC0sXWWl3btIYPQC2NGowzNVKeB35EC4RG1ZhLy2OtUT", nil)
				sessions.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any(), &sessionv1.AuthorizationCodeSession{
					Issuer:  "https://honest.as.example",
					Subject: "foo",
					Request: &flowv1.AuthorizationRequest{
						Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						ResponseType:        "code",
						Scope:               "openid profile email",
						ClientId:            "s6BhdRkqt3",
						State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
						Nonce:               "XDwbBH4MokU8BmrZ",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
						CodeChallengeMethod: "S256",
						Prompt:              nil,
					},
				}).Return(uint64(60), nil)
			},
			wantErr: false,
			want: &flowv1.AuthorizeResponse{
				Error:       nil,
				Code:        "owtjMpUVdrGsn0FPPDTzC0sXWWl3btIYPQC2NGowzNVKeB35EC4RG1ZhLy2OtUT",
				State:       "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
				RedirectUri: "https://client.example.org/cb",
				ClientId:    "s6BhdRkqt3",
				ExpiresIn:   uint64(60),
				Issuer:      "https://honest.as.example",
			},
		},
		{
			name: "offline_access scope with invalid prompt",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizeRequest{
					Issuer:  "https://honest.as.example",
					Subject: "foo",
					Request: &flowv1.AuthorizationRequest{
						Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						ResponseType:        "code",
						Scope:               "openid profile email offline_access",
						ClientId:            "s6BhdRkqt3",
						State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
						Nonce:               "XDwbBH4MokU8BmrZ",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
						CodeChallengeMethod: "S256",
						Prompt:              types.StringRef(oidc.PromptLogin),
					},
				},
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, clients *storagemock.MockClientReader, sessions *storagemock.MockAuthorizationCodeSessionWriter, codes *generatormock.MockAuthorizationCode, _ *generatormock.MockRequestURI) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&clientv1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				}, nil)
				codes.EXPECT().Generate(gomock.Any(), "https://honest.as.example").Return("owtjMpUVdrGsn0FPPDTzC0sXWWl3btIYPQC2NGowzNVKeB35EC4RG1ZhLy2OtUT", nil)
				sessions.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any(), &sessionv1.AuthorizationCodeSession{
					Issuer:  "https://honest.as.example",
					Subject: "foo",
					Request: &flowv1.AuthorizationRequest{
						Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						ResponseType:        "code",
						Scope:               "openid profile email",
						ClientId:            "s6BhdRkqt3",
						State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
						Nonce:               "XDwbBH4MokU8BmrZ",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
						CodeChallengeMethod: "S256",
						Prompt:              types.StringRef(oidc.PromptLogin),
					},
				}).Return(uint64(60), nil)
			},
			wantErr: false,
			want: &flowv1.AuthorizeResponse{
				Error:       nil,
				Code:        "owtjMpUVdrGsn0FPPDTzC0sXWWl3btIYPQC2NGowzNVKeB35EC4RG1ZhLy2OtUT",
				State:       "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
				RedirectUri: "https://client.example.org/cb",
				ClientId:    "s6BhdRkqt3",
				ExpiresIn:   uint64(60),
				Issuer:      "https://honest.as.example",
			},
		},
		{
			name: "with invalid request",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizeRequest{
					Issuer:  "https://honest.as.example",
					Subject: "foo",
					Request: &flowv1.AuthorizationRequest{
						RequestUri: types.StringRef("urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
					},
				},
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, clients *storagemock.MockClientReader, sessions *storagemock.MockAuthorizationCodeSessionWriter, _ *generatormock.MockAuthorizationCode, mru *generatormock.MockRequestURI) {
				mru.EXPECT().Validate(gomock.Any(), "https://honest.as.example", "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(nil)
				ar.EXPECT().Get(gomock.Any(), "https://honest.as.example", "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(&flowv1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email offline_access",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallengeMethod: "S256",
					Prompt:              types.StringRef(oidc.PromptConsent),
				}, nil)
				ar.EXPECT().Delete(gomock.Any(), "https://honest.as.example", "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(nil)
			},
			wantErr: true,
			want: &flowv1.AuthorizeResponse{
				Error: rfcerrors.InvalidRequest().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "with valid request_uri exist",
			args: args{
				ctx: context.Background(),
				req: &flowv1.AuthorizeRequest{
					Issuer:  "https://honest.as.example",
					Subject: "foo",
					Request: &flowv1.AuthorizationRequest{
						RequestUri: types.StringRef("urn:solid:Jny1CLd0EZAD0tNnDsmR56gVPhsKk9ac"),
					},
				},
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, clients *storagemock.MockClientReader, sessions *storagemock.MockAuthorizationCodeSessionWriter, codes *generatormock.MockAuthorizationCode, mru *generatormock.MockRequestURI) {
				mru.EXPECT().Validate(gomock.Any(), "https://honest.as.example", "urn:solid:Jny1CLd0EZAD0tNnDsmR56gVPhsKk9ac").Return(nil)
				ar.EXPECT().Get(gomock.Any(), "https://honest.as.example", "urn:solid:Jny1CLd0EZAD0tNnDsmR56gVPhsKk9ac").Return(&flowv1.AuthorizationRequest{
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
				}, nil)
				ar.EXPECT().Delete(gomock.Any(), "https://honest.as.example", "urn:solid:Jny1CLd0EZAD0tNnDsmR56gVPhsKk9ac").Return(nil)
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&clientv1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				}, nil)
				codes.EXPECT().Generate(gomock.Any(), "https://honest.as.example").Return("owtjMpUVdrGsn0FPPDTzC0sXWWl3btIYPQC2NGowzNVKeB35EC4RG1ZhLy2OtUT", nil)
				sessions.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any(), &sessionv1.AuthorizationCodeSession{
					Issuer:  "https://honest.as.example",
					Subject: "foo",
					Request: &flowv1.AuthorizationRequest{
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
				}).Return(uint64(60), nil)
			},
			wantErr: false,
			want: &flowv1.AuthorizeResponse{
				Error:       nil,
				Code:        "owtjMpUVdrGsn0FPPDTzC0sXWWl3btIYPQC2NGowzNVKeB35EC4RG1ZhLy2OtUT",
				State:       "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
				RedirectUri: "https://client.example.org/cb",
				ClientId:    "s6BhdRkqt3",
				ExpiresIn:   uint64(60),
				Issuer:      "https://honest.as.example",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Arm mocks
			authorizationRequests := storagemock.NewMockAuthorizationRequest(ctrl)
			clients := storagemock.NewMockClientReader(ctrl)
			authorizationCodeSessions := storagemock.NewMockAuthorizationCodeSessionWriter(ctrl)
			codeGenerator := generatormock.NewMockAuthorizationCode(ctrl)
			requestURIGenerator := generatormock.NewMockRequestURI(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(authorizationRequests, clients, authorizationCodeSessions, codeGenerator, requestURIGenerator)
			}

			// Prepare service
			underTest := New(clients, authorizationRequests, authorizationCodeSessions, codeGenerator, requestURIGenerator)

			// Do the request
			got, err := underTest.Authorize(tt.args.ctx, tt.args.req)
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

func Test_service_Authorize_Fuzz(t *testing.T) {
	// Arm mocks
	ctrl := gomock.NewController(t)
	authorizationRequests := storagemock.NewMockAuthorizationRequest(ctrl)
	clients := storagemock.NewMockClientReader(ctrl)
	authorizationCodeSessions := storagemock.NewMockAuthorizationCodeSessionWriter(ctrl)
	codeGenerator := generatormock.NewMockAuthorizationCode(ctrl)
	requestURIGenerator := generatormock.NewMockRequestURI(ctrl)

	requestURIGenerator.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	authorizationRequests.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(ctx context.Context, isser, requestURI string) (*flowv1.AuthorizationRequest, error) {
		f := fuzz.New()
		var ar flowv1.AuthorizationRequest
		f.Fuzz(&ar)

		return &ar, nil
	}).AnyTimes()
	authorizationRequests.EXPECT().Delete(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	// Prepare service
	underTest := New(clients, authorizationRequests, authorizationCodeSessions, codeGenerator, requestURIGenerator)

	// Making sure the function never panics
	for i := 0; i < 1000; i++ {
		f := fuzz.New()

		// Prepare arguments
		var req flowv1.AuthorizeRequest
		f.Fuzz(&req)

		// Execute
		underTest.Authorize(context.Background(), &req)
	}
}

func Test_service_Register(t *testing.T) {
	type args struct {
		ctx context.Context
		req *flowv1.RegistrationRequest
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*storagemock.MockAuthorizationRequest, *storagemock.MockClientReader, *storagemock.MockAuthorizationCodeSessionWriter, *generatormock.MockAuthorizationCode, *generatormock.MockRequestURI)
		want    *flowv1.RegistrationResponse
		wantErr bool
	}{
		{
			name: "nil request",
			args: args{
				ctx: context.Background(),
				req: nil,
			},
			wantErr: true,
			want: &flowv1.RegistrationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty request",
			args: args{
				ctx: context.Background(),
				req: &flowv1.RegistrationRequest{},
			},
			wantErr: true,
			want: &flowv1.RegistrationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty issuer",
			args: args{
				ctx: context.Background(),
				req: &flowv1.RegistrationRequest{
					Issuer: "",
				},
			},
			wantErr: true,
			want: &flowv1.RegistrationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "nil client",
			args: args{
				ctx: context.Background(),
				req: &flowv1.RegistrationRequest{
					Issuer: "https://honest.as.example",
					Client: nil,
				},
			},
			wantErr: true,
			want: &flowv1.RegistrationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "nil authorization request",
			args: args{
				ctx: context.Background(),
				req: &flowv1.RegistrationRequest{
					Issuer:               "https://honest.as.example",
					Client:               &clientv1.Client{},
					Request: nil,
				},
			},
			wantErr: true,
			want: &flowv1.RegistrationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty authorization request",
			args: args{
				ctx: context.Background(),
				req: &flowv1.RegistrationRequest{
					Issuer:               "https://honest.as.example",
					Client:               &clientv1.Client{},
					Request: &flowv1.AuthorizationRequest{},
				},
			},
			wantErr: true,
			want: &flowv1.RegistrationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "nested authorization request",
			args: args{
				ctx: context.Background(),
				req: &flowv1.RegistrationRequest{
					Issuer: "https://honest.as.example",
					Client: &clientv1.Client{},
					Request: &flowv1.AuthorizationRequest{
						RequestUri: types.StringRef("1234567890"),
					},
				},
			},
			wantErr: true,
			want: &flowv1.RegistrationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid request",
			args: args{
				ctx: context.Background(),
				req: &flowv1.RegistrationRequest{
					Issuer: "https://honest.as.example",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.AuthorizationRequest{
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
			},
			prepare: func(_ *storagemock.MockAuthorizationRequest, clients *storagemock.MockClientReader, _ *storagemock.MockAuthorizationCodeSessionWriter, _ *generatormock.MockAuthorizationCode, _ *generatormock.MockRequestURI) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&clientv1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{"client_credentials"},
				}, nil)
			},
			wantErr: true,
			want: &flowv1.RegistrationResponse{
				Error: rfcerrors.UnsupportedGrantType().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
			},
		},
		{
			name: "client_id mismatch",
			args: args{
				ctx: context.Background(),
				req: &flowv1.RegistrationRequest{
					Issuer: "https://honest.as.example",
					Client: &clientv1.Client{
						ClientId: "foooo",
					},
					Request: &flowv1.AuthorizationRequest{
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
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, clients *storagemock.MockClientReader, _ *storagemock.MockAuthorizationCodeSessionWriter, _ *generatormock.MockAuthorizationCode, _ *generatormock.MockRequestURI) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				}, nil)
			},
			wantErr: true,
			want: &flowv1.RegistrationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "error while generating uri",
			args: args{
				ctx: context.Background(),
				req: &flowv1.RegistrationRequest{
					Issuer: "https://honest.as.example",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.AuthorizationRequest{
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
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, clients *storagemock.MockClientReader, _ *storagemock.MockAuthorizationCodeSessionWriter, _ *generatormock.MockAuthorizationCode, mru *generatormock.MockRequestURI) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				}, nil)
				mru.EXPECT().Generate(gomock.Any(), "https://honest.as.example").Return("", fmt.Errorf("test"))
			},
			wantErr: true,
			want: &flowv1.RegistrationResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "error while registering the request",
			args: args{
				ctx: context.Background(),
				req: &flowv1.RegistrationRequest{
					Issuer: "https://honest.as.example",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.AuthorizationRequest{
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
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, clients *storagemock.MockClientReader, _ *storagemock.MockAuthorizationCodeSessionWriter, _ *generatormock.MockAuthorizationCode, mru *generatormock.MockRequestURI) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				}, nil)
				mru.EXPECT().Generate(gomock.Any(), "https://honest.as.example").Return("urn:solid:Jny1CLd0EZAD0tNnDsmR56gVPhsKk9ac", nil)
				ar.EXPECT().Register(gomock.Any(), "https://honest.as.example", gomock.Any(), &flowv1.AuthorizationRequest{
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
				}).Return(uint64(90), fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &flowv1.RegistrationResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "valid",
			args: args{
				ctx: context.Background(),
				req: &flowv1.RegistrationRequest{
					Issuer: "https://honest.as.example",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					Request: &flowv1.AuthorizationRequest{
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
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, clients *storagemock.MockClientReader, _ *storagemock.MockAuthorizationCodeSessionWriter, _ *generatormock.MockAuthorizationCode, mru *generatormock.MockRequestURI) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				}, nil)
				mru.EXPECT().Generate(gomock.Any(), "https://honest.as.example").Return("urn:solid:Jny1CLd0EZAD0tNnDsmR56gVPhsKk9ac", nil)
				ar.EXPECT().Register(gomock.Any(), "https://honest.as.example", gomock.Any(), &flowv1.AuthorizationRequest{
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
				}).Return(uint64(90), nil)
			},
			wantErr: false,
			want: &flowv1.RegistrationResponse{
				Error:      nil,
				ExpiresIn:  90,
				RequestUri: "urn:solid:Jny1CLd0EZAD0tNnDsmR56gVPhsKk9ac",
				Issuer:     "https://honest.as.example",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Arm mocks
			authorizationRequests := storagemock.NewMockAuthorizationRequest(ctrl)
			clients := storagemock.NewMockClientReader(ctrl)
			authorizationCodeSessions := storagemock.NewMockAuthorizationCodeSessionWriter(ctrl)
			codeGenerator := generatormock.NewMockAuthorizationCode(ctrl)
			requestUriGenerator := generatormock.NewMockRequestURI(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(authorizationRequests, clients, authorizationCodeSessions, codeGenerator, requestUriGenerator)
			}

			// Prepare service
			underTest := New(clients, authorizationRequests, authorizationCodeSessions, codeGenerator, requestUriGenerator)

			// Do the request
			got, err := underTest.Register(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("service.Register() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
				t.Errorf("service.Register() res =%s", diff)
			}
		})
	}
}

func Test_service_Register_Fuzz(t *testing.T) {
	// Arm mocks
	ctrl := gomock.NewController(t)
	authorizationRequests := storagemock.NewMockAuthorizationRequest(ctrl)
	clients := storagemock.NewMockClientReader(ctrl)
	authorizationCodeSessions := storagemock.NewMockAuthorizationCodeSessionWriter(ctrl)
	codeGenerator := generatormock.NewMockAuthorizationCode(ctrl)
	requestURIGenerator := generatormock.NewMockRequestURI(ctrl)

	// Prepare service
	underTest := New(clients, authorizationRequests, authorizationCodeSessions, codeGenerator, requestURIGenerator)

	// Making sure the function never panics
	for i := 0; i < 1000; i++ {
		f := fuzz.New()

		// Prepare arguments
		var req flowv1.RegistrationRequest
		f.Fuzz(&req)

		// Execute
		underTest.Register(context.Background(), &req)
	}
}
