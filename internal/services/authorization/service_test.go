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
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/google/go-cmp/cmp"
	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
	registrationv1 "go.zenithar.org/solid/api/gen/go/oidc/registration/v1"
	sessionv1 "go.zenithar.org/solid/api/gen/go/oidc/session/v1"
	"go.zenithar.org/solid/api/oidc"
	"go.zenithar.org/solid/pkg/authorization"
	"go.zenithar.org/solid/pkg/rfcerrors"
	"go.zenithar.org/solid/pkg/storage"
	storagemock "go.zenithar.org/solid/pkg/storage/mock"
)

func Test_service_Authorize(t *testing.T) {
	type fields struct {
		codeGenerator         authorization.CodeGenerator
		clients               storage.ClientReader
		authorizationRequests storage.AuthorizationRequest
	}
	type args struct {
		ctx context.Context
		req *corev1.AuthorizationRequest
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*storagemock.MockAuthorizationRequest, *storagemock.MockClientReader, *storagemock.MockSessionWriter)
		want    *corev1.AuthorizationResponse
		wantErr bool
	}{
		{
			name: "nil request",
			args: args{
				ctx: context.Background(),
				req: nil,
			},
			wantErr: true,
			want: &corev1.AuthorizationResponse{
				Error: rfcerrors.InvalidRequest(""),
			},
		},
		{
			name: "with invalid request_uri",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationRequest{
					RequestUri: &wrappers.StringValue{
						Value: "123-456-789",
					},
				},
			},
			wantErr: true,
			want: &corev1.AuthorizationResponse{
				Error: rfcerrors.InvalidRequest(""),
			},
		},
		{
			name: "with request_uri not found error",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationRequest{
					RequestUri: &wrappers.StringValue{
						Value: "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
					},
				},
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, _ *storagemock.MockClientReader, _ *storagemock.MockSessionWriter) {
				ar.EXPECT().Get(gomock.Any(), "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(nil, storage.ErrNotFound)
			},
			wantErr: true,
			want: &corev1.AuthorizationResponse{
				Error: rfcerrors.InvalidRequest(""),
			},
		},
		{
			name: "with request_uri storage error",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationRequest{
					RequestUri: &wrappers.StringValue{
						Value: "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
					},
				},
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, _ *storagemock.MockClientReader, _ *storagemock.MockSessionWriter) {
				ar.EXPECT().Get(gomock.Any(), "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(nil, fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.AuthorizationResponse{
				Error: rfcerrors.ServerError(""),
			},
		},
		{
			name: "with request_uri exist with not found error during deletion",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationRequest{
					RequestUri: &wrappers.StringValue{
						Value: "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
					},
				},
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, _ *storagemock.MockClientReader, _ *storagemock.MockSessionWriter) {
				ar.EXPECT().Get(gomock.Any(), "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(&corev1.AuthorizationRequest{}, nil)
				ar.EXPECT().Delete(gomock.Any(), "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(storage.ErrNotFound)
			},
			wantErr: true,
			want: &corev1.AuthorizationResponse{
				Error: rfcerrors.InvalidRequest(""),
			},
		},
		{
			name: "with request_uri exist but deletion error",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationRequest{
					RequestUri: &wrappers.StringValue{
						Value: "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
					},
				},
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, _ *storagemock.MockClientReader, _ *storagemock.MockSessionWriter) {
				ar.EXPECT().Get(gomock.Any(), "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(&corev1.AuthorizationRequest{}, nil)
				ar.EXPECT().Delete(gomock.Any(), "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.AuthorizationResponse{
				Error: rfcerrors.ServerError(""),
			},
		},
		{
			name: "authorization session registration error",
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
			prepare: func(ar *storagemock.MockAuthorizationRequest, clients *storagemock.MockClientReader, sessions *storagemock.MockSessionWriter) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&registrationv1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				}, nil)
				sessions.EXPECT().Register(gomock.Any(), gomock.Any()).Return("", fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.AuthorizationResponse{
				Error: rfcerrors.ServerError("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU"),
			},
		},
		{
			name: "offline_access scope with nil prompt",
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
					Prompt:              nil,
				},
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, clients *storagemock.MockClientReader, sessions *storagemock.MockSessionWriter) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&registrationv1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				}, nil)
				sessions.EXPECT().Register(gomock.Any(), &sessionv1.Session{
					Subject: "",
					Request: &corev1.AuthorizationRequest{
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
				}).Return("1234567891234567890", nil)
			},
			wantErr: false,
			want: &corev1.AuthorizationResponse{
				Error: nil,
				Code:  "1234567891234567890",
				State: "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
			},
		},
		{
			name: "offline_access scope with invalid prompt",
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
					Prompt: &wrappers.StringValue{
						Value: "login",
					},
				},
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, clients *storagemock.MockClientReader, sessions *storagemock.MockSessionWriter) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&registrationv1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				}, nil)
				sessions.EXPECT().Register(gomock.Any(), &sessionv1.Session{
					Subject: "",
					Request: &corev1.AuthorizationRequest{
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
				}).Return("1234567891234567890", nil)
			},
			wantErr: false,
			want: &corev1.AuthorizationResponse{
				Error: nil,
				Code:  "1234567891234567890",
				State: "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
			},
		},

		{
			name: "with invalid request",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationRequest{
					RequestUri: &wrappers.StringValue{
						Value: "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
					},
				},
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, clients *storagemock.MockClientReader, sessions *storagemock.MockSessionWriter) {
				ar.EXPECT().Get(gomock.Any(), "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(&corev1.AuthorizationRequest{
					ResponseType:        "code",
					Scope:               "openid profile email offline_access",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallengeMethod: "S256",
					Prompt:              &wrappers.StringValue{Value: "consent"},
				}, nil)
				ar.EXPECT().Delete(gomock.Any(), "urn:solid:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").Return(nil)
			},
			wantErr: true,
			want: &corev1.AuthorizationResponse{
				Error: rfcerrors.InvalidRequest("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU"),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "with valid request_uri exist",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationRequest{
					RequestUri: &wrappers.StringValue{
						Value: "urn:solid:Jny1CLd0EZAD0tNnDsmR56gVPhsKk9ac",
					},
				},
			},
			prepare: func(ar *storagemock.MockAuthorizationRequest, clients *storagemock.MockClientReader, sessions *storagemock.MockSessionWriter) {
				ar.EXPECT().Get(gomock.Any(), "urn:solid:Jny1CLd0EZAD0tNnDsmR56gVPhsKk9ac").Return(&corev1.AuthorizationRequest{
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
				ar.EXPECT().Delete(gomock.Any(), "urn:solid:Jny1CLd0EZAD0tNnDsmR56gVPhsKk9ac").Return(nil)
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&registrationv1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				}, nil)
				sessions.EXPECT().Register(gomock.Any(), &sessionv1.Session{
					Subject: "",
					Request: &corev1.AuthorizationRequest{
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
				}).Return("1234567891234567890", nil)
			},
			wantErr: false,
			want: &corev1.AuthorizationResponse{
				Error: nil,
				Code:  "1234567891234567890",
				State: "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
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
			sessions := storagemock.NewMockSessionWriter(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(authorizationRequests, clients, sessions)
			}

			// Prepare service
			underTest := New(clients, authorizationRequests, sessions)

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

func Test_service_Register(t *testing.T) {
	type fields struct {
		codeGenerator         authorization.CodeGenerator
		clients               storage.ClientReader
		authorizationRequests storage.AuthorizationRequest
	}
	type args struct {
		ctx context.Context
		req *corev1.RegistrationRequest
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*storagemock.MockAuthorizationRequest, *storagemock.MockClientReader, *storagemock.MockSessionWriter)
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
				Error: rfcerrors.InvalidRequest(""),
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
				Error: rfcerrors.InvalidRequest(""),
			},
		},
		{
			name: "invalid request",
			args: args{
				ctx: context.Background(),
				req: &corev1.RegistrationRequest{
					Request: &corev1.AuthorizationRequest{
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
			prepare: func(_ *storagemock.MockAuthorizationRequest, clients *storagemock.MockClientReader, _ *storagemock.MockSessionWriter) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&registrationv1.Client{
					GrantTypes: []string{"client_credentials"},
				}, nil)
			},
			wantErr: true,
			want: &corev1.RegistrationResponse{
				Error: rfcerrors.UnsupportedGrantType("oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU"),
			},
		},
		{
			name: "error while registering the request",
			args: args{
				ctx: context.Background(),
				req: &corev1.RegistrationRequest{
					Request: &corev1.AuthorizationRequest{
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
			prepare: func(ar *storagemock.MockAuthorizationRequest, clients *storagemock.MockClientReader, _ *storagemock.MockSessionWriter) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&registrationv1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				}, nil)
				ar.EXPECT().Register(gomock.Any(), &corev1.AuthorizationRequest{
					ResponseType:        "code",
					Scope:               "openid profile email offline_access",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
					Prompt:              &wrappers.StringValue{Value: "consent"},
				}).Return("", fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.RegistrationResponse{
				Error: rfcerrors.ServerError(""),
			},
		},
		{
			name: "valid",
			args: args{
				ctx: context.Background(),
				req: &corev1.RegistrationRequest{
					Request: &corev1.AuthorizationRequest{
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
			prepare: func(ar *storagemock.MockAuthorizationRequest, clients *storagemock.MockClientReader, _ *storagemock.MockSessionWriter) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&registrationv1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				}, nil)
				ar.EXPECT().Register(gomock.Any(), &corev1.AuthorizationRequest{
					ResponseType:        "code",
					Scope:               "openid profile email offline_access",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
					Prompt:              &wrappers.StringValue{Value: "consent"},
				}).Return("123-456-789", nil)
			},
			wantErr: false,
			want: &corev1.RegistrationResponse{
				Error:      nil,
				ExpiresIn:  90,
				RequestUri: "123-456-789",
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
			sessions := storagemock.NewMockSessionWriter(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(authorizationRequests, clients, sessions)
			}

			// Prepare service
			underTest := New(clients, authorizationRequests, sessions)

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
