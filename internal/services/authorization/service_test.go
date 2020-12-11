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

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/api/oidc"
	"zntr.io/solid/pkg/sdk/generator"
	"zntr.io/solid/pkg/sdk/rfcerrors"
	"zntr.io/solid/pkg/server/storage"
	storagemock "zntr.io/solid/pkg/server/storage/mock"

	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/google/go-cmp/cmp"
	fuzz "github.com/google/gofuzz"
)

func Test_service_Authorize(t *testing.T) {
	type fields struct {
		codeGenerator         generator.AuthorizationCode
		clients               storage.ClientReader
		authorizationRequests storage.AuthorizationRequest
	}
	type args struct {
		ctx context.Context
		req *corev1.AuthorizationCodeRequest
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*storagemock.MockAuthorizationRequest, *storagemock.MockClientReader, *storagemock.MockAuthorizationCodeSessionWriter)
		want    *corev1.AuthorizationCodeResponse
		wantErr bool
	}{
		{
			name: "nil",
			args: args{
				ctx: context.Background(),
				req: nil,
			},
			wantErr: true,
			want: &corev1.AuthorizationCodeResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "nil request",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationCodeRequest{
					AuthorizationRequest: nil,
				},
			},
			wantErr: true,
			want: &corev1.AuthorizationCodeResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty issuer",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationCodeRequest{
					Issuer:  "",
					Subject: "foo",
					AuthorizationRequest: &corev1.AuthorizationRequest{
						RequestUri: &wrappers.StringValue{
							Value: "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
						},
					},
				},
			},
			wantErr: true,
			want: &corev1.AuthorizationCodeResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty subject",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationCodeRequest{
					Issuer:  "https://honest.as.example",
					Subject: "",
					AuthorizationRequest: &corev1.AuthorizationRequest{
						RequestUri: &wrappers.StringValue{
							Value: "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
						},
					},
				},
			},
			wantErr: true,
			want: &corev1.AuthorizationCodeResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "with invalid request_uri",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationCodeRequest{
					Issuer:  "https://honest.as.example",
					Subject: "foo",
					AuthorizationRequest: &corev1.AuthorizationRequest{
						RequestUri: &wrappers.StringValue{
							Value: "123-456-789",
						},
					},
				},
			},
			wantErr: true,
			want: &corev1.AuthorizationCodeResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "with request_uri not found error",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationCodeRequest{
					Issuer:  "https://honest.as.example",
					Subject: "foo",
					AuthorizationRequest: &corev1.AuthorizationRequest{
						RequestUri: &wrappers.StringValue{
							Value: "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
						},
					},
				},
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, _ *storagemock.MockClientReader, _ *storagemock.MockAuthorizationCodeSessionWriter) {
				ar.EXPECT().Get(gomock.Any(), "https://honest.as.example", "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(nil, storage.ErrNotFound)
			},
			wantErr: true,
			want: &corev1.AuthorizationCodeResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "with request_uri storage error",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationCodeRequest{
					Issuer:  "https://honest.as.example",
					Subject: "foo",
					AuthorizationRequest: &corev1.AuthorizationRequest{
						RequestUri: &wrappers.StringValue{
							Value: "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
						},
					},
				},
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, _ *storagemock.MockClientReader, _ *storagemock.MockAuthorizationCodeSessionWriter) {
				ar.EXPECT().Get(gomock.Any(), "https://honest.as.example", "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(nil, fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.AuthorizationCodeResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "with request_uri exist with not found error during deletion",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationCodeRequest{
					Issuer:  "https://honest.as.example",
					Subject: "foo",
					AuthorizationRequest: &corev1.AuthorizationRequest{
						RequestUri: &wrappers.StringValue{
							Value: "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
						},
					},
				},
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, _ *storagemock.MockClientReader, _ *storagemock.MockAuthorizationCodeSessionWriter) {
				ar.EXPECT().Get(gomock.Any(), "https://honest.as.example", "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(&corev1.AuthorizationRequest{}, nil)
				ar.EXPECT().Delete(gomock.Any(), "https://honest.as.example", "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(storage.ErrNotFound)
			},
			wantErr: true,
			want: &corev1.AuthorizationCodeResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "with request_uri exist but deletion error",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationCodeRequest{
					Issuer:  "https://honest.as.example",
					Subject: "foo",
					AuthorizationRequest: &corev1.AuthorizationRequest{
						RequestUri: &wrappers.StringValue{
							Value: "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
						},
					},
				},
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, _ *storagemock.MockClientReader, _ *storagemock.MockAuthorizationCodeSessionWriter) {
				ar.EXPECT().Get(gomock.Any(), "https://honest.as.example", "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(&corev1.AuthorizationRequest{}, nil)
				ar.EXPECT().Delete(gomock.Any(), "https://honest.as.example", "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.AuthorizationCodeResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "authorization session registration error",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationCodeRequest{
					Issuer:  "https://honest.as.example",
					Subject: "foo",
					AuthorizationRequest: &corev1.AuthorizationRequest{
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
			prepare: func(ar *storagemock.MockAuthorizationRequest, clients *storagemock.MockClientReader, sessions *storagemock.MockAuthorizationCodeSessionWriter) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&corev1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				}, nil)
				sessions.EXPECT().Register(gomock.Any(), gomock.Any()).Return("", uint64(0), fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.AuthorizationCodeResponse{
				Error: rfcerrors.ServerError().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
			},
		},
		{
			name: "offline_access scope with nil prompt",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationCodeRequest{
					Issuer:  "https://honest.as.example",
					Subject: "foo",
					AuthorizationRequest: &corev1.AuthorizationRequest{
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
			prepare: func(ar *storagemock.MockAuthorizationRequest, clients *storagemock.MockClientReader, sessions *storagemock.MockAuthorizationCodeSessionWriter) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&corev1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				}, nil)
				sessions.EXPECT().Register(gomock.Any(), &corev1.AuthorizationCodeSession{
					Issuer:  "https://honest.as.example",
					Subject: "foo",
					Request: &corev1.AuthorizationRequest{
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
				}).Return("1234567891234567890", uint64(60), nil)
			},
			wantErr: false,
			want: &corev1.AuthorizationCodeResponse{
				Error:       nil,
				Code:        "1234567891234567890",
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
				req: &corev1.AuthorizationCodeRequest{
					Issuer:  "https://honest.as.example",
					Subject: "foo",
					AuthorizationRequest: &corev1.AuthorizationRequest{
						Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						ResponseType:        "code",
						Scope:               "openid profile email offline_access",
						ClientId:            "s6BhdRkqt3",
						State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
						Nonce:               "XDwbBH4MokU8BmrZ",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
						CodeChallengeMethod: "S256",
						Prompt: &wrappers.StringValue{
							Value: "login",
						},
					},
				},
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, clients *storagemock.MockClientReader, sessions *storagemock.MockAuthorizationCodeSessionWriter) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&corev1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				}, nil)
				sessions.EXPECT().Register(gomock.Any(), &corev1.AuthorizationCodeSession{
					Issuer:  "https://honest.as.example",
					Subject: "foo",
					Request: &corev1.AuthorizationRequest{
						Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						ResponseType:        "code",
						Scope:               "openid profile email",
						ClientId:            "s6BhdRkqt3",
						State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
						Nonce:               "XDwbBH4MokU8BmrZ",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
						CodeChallengeMethod: "S256",
						Prompt: &wrappers.StringValue{
							Value: "login",
						},
					},
				}).Return("1234567891234567890", uint64(60), nil)
			},
			wantErr: false,
			want: &corev1.AuthorizationCodeResponse{
				Error:       nil,
				Code:        "1234567891234567890",
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
				req: &corev1.AuthorizationCodeRequest{
					Issuer:  "https://honest.as.example",
					Subject: "foo",
					AuthorizationRequest: &corev1.AuthorizationRequest{
						RequestUri: &wrappers.StringValue{
							Value: "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
						},
					},
				},
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, clients *storagemock.MockClientReader, sessions *storagemock.MockAuthorizationCodeSessionWriter) {
				ar.EXPECT().Get(gomock.Any(), "https://honest.as.example", "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(&corev1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email offline_access",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallengeMethod: "S256",
					Prompt:              &wrappers.StringValue{Value: "consent"},
				}, nil)
				ar.EXPECT().Delete(gomock.Any(), "https://honest.as.example", "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(nil)
			},
			wantErr: true,
			want: &corev1.AuthorizationCodeResponse{
				Error: rfcerrors.InvalidRequest().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "with valid request_uri exist",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationCodeRequest{
					Issuer:  "https://honest.as.example",
					Subject: "foo",
					AuthorizationRequest: &corev1.AuthorizationRequest{
						RequestUri: &wrappers.StringValue{
							Value: "urn:solid:Jny1CLd0EZAD0tNnDsmR56gVPhsKk9ac",
						},
					},
				},
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, clients *storagemock.MockClientReader, sessions *storagemock.MockAuthorizationCodeSessionWriter) {
				ar.EXPECT().Get(gomock.Any(), "https://honest.as.example", "urn:solid:Jny1CLd0EZAD0tNnDsmR56gVPhsKk9ac").Return(&corev1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email offline_access",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
					Prompt:              &wrappers.StringValue{Value: "consent"},
				}, nil)
				ar.EXPECT().Delete(gomock.Any(), "https://honest.as.example", "urn:solid:Jny1CLd0EZAD0tNnDsmR56gVPhsKk9ac").Return(nil)
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&corev1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				}, nil)
				sessions.EXPECT().Register(gomock.Any(), &corev1.AuthorizationCodeSession{
					Issuer:  "https://honest.as.example",
					Subject: "foo",
					Request: &corev1.AuthorizationRequest{
						Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
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
				}).Return("1234567891234567890", uint64(60), nil)
			},
			wantErr: false,
			want: &corev1.AuthorizationCodeResponse{
				Error:       nil,
				Code:        "1234567891234567890",
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

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(authorizationRequests, clients, authorizationCodeSessions)
			}

			// Prepare service
			underTest := New(clients, authorizationRequests, authorizationCodeSessions)

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

	// Prepare service
	underTest := New(clients, authorizationRequests, authorizationCodeSessions)

	// Making sure the function never panics
	for i := 0; i < 1000; i++ {
		f := fuzz.New()

		// Prepare arguments
		var req corev1.AuthorizationCodeRequest
		f.Fuzz(&req)

		// Execute
		underTest.Authorize(context.Background(), &req)
	}
}

func Test_service_Register(t *testing.T) {
	type args struct {
		ctx context.Context
		req *corev1.RegistrationRequest
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*storagemock.MockAuthorizationRequest, *storagemock.MockClientReader, *storagemock.MockAuthorizationCodeSessionWriter)
		want    *corev1.RegistrationResponse
		wantErr bool
	}{
		{
			name: "nil request",
			args: args{
				ctx: context.Background(),
				req: nil,
			},
			wantErr: true,
			want: &corev1.RegistrationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty request",
			args: args{
				ctx: context.Background(),
				req: &corev1.RegistrationRequest{},
			},
			wantErr: true,
			want: &corev1.RegistrationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty issuer",
			args: args{
				ctx: context.Background(),
				req: &corev1.RegistrationRequest{
					Issuer: "",
				},
			},
			wantErr: true,
			want: &corev1.RegistrationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "nil client",
			args: args{
				ctx: context.Background(),
				req: &corev1.RegistrationRequest{
					Issuer: "https://honest.as.example",
					Client: nil,
				},
			},
			wantErr: true,
			want: &corev1.RegistrationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "nil authorization request",
			args: args{
				ctx: context.Background(),
				req: &corev1.RegistrationRequest{
					Issuer:               "https://honest.as.example",
					Client:               &corev1.Client{},
					AuthorizationRequest: nil,
				},
			},
			wantErr: true,
			want: &corev1.RegistrationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "empty authorization request",
			args: args{
				ctx: context.Background(),
				req: &corev1.RegistrationRequest{
					Issuer:               "https://honest.as.example",
					Client:               &corev1.Client{},
					AuthorizationRequest: &corev1.AuthorizationRequest{},
				},
			},
			wantErr: true,
			want: &corev1.RegistrationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid request",
			args: args{
				ctx: context.Background(),
				req: &corev1.RegistrationRequest{
					Issuer: "https://honest.as.example",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					AuthorizationRequest: &corev1.AuthorizationRequest{
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
			prepare: func(_ *storagemock.MockAuthorizationRequest, clients *storagemock.MockClientReader, _ *storagemock.MockAuthorizationCodeSessionWriter) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&corev1.Client{
					ClientId:   "s6BhdRkqt3",
					GrantTypes: []string{"client_credentials"},
				}, nil)
			},
			wantErr: true,
			want: &corev1.RegistrationResponse{
				Error: rfcerrors.UnsupportedGrantType().State("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU").Build(),
			},
		},
		{
			name: "client_id mismatch",
			args: args{
				ctx: context.Background(),
				req: &corev1.RegistrationRequest{
					Issuer: "https://honest.as.example",
					Client: &corev1.Client{
						ClientId: "foooo",
					},
					AuthorizationRequest: &corev1.AuthorizationRequest{
						Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
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
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, clients *storagemock.MockClientReader, _ *storagemock.MockAuthorizationCodeSessionWriter) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&corev1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				}, nil)
			},
			wantErr: true,
			want: &corev1.RegistrationResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "error while registering the request",
			args: args{
				ctx: context.Background(),
				req: &corev1.RegistrationRequest{
					Issuer: "https://honest.as.example",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					AuthorizationRequest: &corev1.AuthorizationRequest{
						Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
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
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, clients *storagemock.MockClientReader, _ *storagemock.MockAuthorizationCodeSessionWriter) {
				ar.EXPECT().Register(gomock.Any(), "https://honest.as.example", &corev1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email offline_access",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
					Prompt:              &wrappers.StringValue{Value: "consent"},
				}).Return("", uint64(90), fmt.Errorf("foo"))
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&corev1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				}, nil)
			},
			wantErr: true,
			want: &corev1.RegistrationResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "valid",
			args: args{
				ctx: context.Background(),
				req: &corev1.RegistrationRequest{
					Issuer: "https://honest.as.example",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					AuthorizationRequest: &corev1.AuthorizationRequest{
						Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
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
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, clients *storagemock.MockClientReader, _ *storagemock.MockAuthorizationCodeSessionWriter) {
				ar.EXPECT().Register(gomock.Any(), "https://honest.as.example", &corev1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email offline_access",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
					Prompt:              &wrappers.StringValue{Value: "consent"},
				}).Return("123-456-789", uint64(90), nil)
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&corev1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				}, nil)
			},
			wantErr: false,
			want: &corev1.RegistrationResponse{
				Error:      nil,
				ExpiresIn:  90,
				RequestUri: "123-456-789",
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

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(authorizationRequests, clients, authorizationCodeSessions)
			}

			// Prepare service
			underTest := New(clients, authorizationRequests, authorizationCodeSessions)

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

	// Prepare service
	underTest := New(clients, authorizationRequests, authorizationCodeSessions)

	// Making sure the function never panics
	for i := 0; i < 1000; i++ {
		f := fuzz.New()

		// Prepare arguments
		var req corev1.RegistrationRequest
		f.Fuzz(&req)

		// Execute
		underTest.Register(context.Background(), &req)
	}
}
