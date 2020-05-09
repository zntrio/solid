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
	"go.zenithar.org/solid/pkg/authorization"
	authzmock "go.zenithar.org/solid/pkg/authorization/mock"
	"go.zenithar.org/solid/pkg/rfcerrors"
	"go.zenithar.org/solid/pkg/storage"
	storagemock "go.zenithar.org/solid/pkg/storage/mock"

	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/google/go-cmp/cmp"
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
		prepare func(*authzmock.MockCodeGenerator, *storagemock.MockClientReader, *storagemock.MockAuthorizationRequest)
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
			name: "with request_uri not found error",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationRequest{
					RequestUri: &wrappers.StringValue{
						Value: "123-456-789",
					},
				},
			},
			prepare: func(_ *authzmock.MockCodeGenerator, _ *storagemock.MockClientReader, ar *storagemock.MockAuthorizationRequest) {
				ar.EXPECT().GetByRequestURI(gomock.Any(), "123-456-789").Return(nil, storage.ErrNotFound)
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
						Value: "123-456-789",
					},
				},
			},
			prepare: func(_ *authzmock.MockCodeGenerator, _ *storagemock.MockClientReader, ar *storagemock.MockAuthorizationRequest) {
				ar.EXPECT().GetByRequestURI(gomock.Any(), "123-456-789").Return(nil, fmt.Errorf("foo"))
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
						Value: "123-456-789",
					},
				},
			},
			prepare: func(_ *authzmock.MockCodeGenerator, _ *storagemock.MockClientReader, ar *storagemock.MockAuthorizationRequest) {
				ar.EXPECT().GetByRequestURI(gomock.Any(), "123-456-789").Return(&corev1.AuthorizationRequest{}, nil)
				ar.EXPECT().Delete(gomock.Any(), "123-456-789").Return(storage.ErrNotFound)
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
						Value: "123-456-789",
					},
				},
			},
			prepare: func(_ *authzmock.MockCodeGenerator, _ *storagemock.MockClientReader, ar *storagemock.MockAuthorizationRequest) {
				ar.EXPECT().GetByRequestURI(gomock.Any(), "123-456-789").Return(&corev1.AuthorizationRequest{}, nil)
				ar.EXPECT().Delete(gomock.Any(), "123-456-789").Return(fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.AuthorizationResponse{
				Error: rfcerrors.ServerError(""),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "with valid request_uri exist",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthorizationRequest{
					RequestUri: &wrappers.StringValue{
						Value: "123-456-789",
					},
				},
			},
			prepare: func(cg *authzmock.MockCodeGenerator, clients *storagemock.MockClientReader, ar *storagemock.MockAuthorizationRequest) {
				ar.EXPECT().GetByRequestURI(gomock.Any(), "123-456-789").Return(&corev1.AuthorizationRequest{
					ResponseType:        "code",
					Scope:               "openid profile email offline_access",
					ClientId:            "s6BhdRkqt3",
					State:               "af0ifjsldkj",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
					Prompt:              &wrappers.StringValue{Value: "consent"},
				}, nil)
				ar.EXPECT().Delete(gomock.Any(), "123-456-789").Return(nil)
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&registrationv1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				}, nil)
				cg.EXPECT().Generate(gomock.Any()).Return("1234567891234567890", nil)
				ar.EXPECT().Register(gomock.Any(), &corev1.AuthorizationRequest{
					ResponseType:        "code",
					Scope:               "openid profile email offline_access",
					ClientId:            "s6BhdRkqt3",
					State:               "af0ifjsldkj",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
					Prompt:              &wrappers.StringValue{Value: "consent"},
				}).Return("123-146-798", nil)
			},
			wantErr: false,
			want: &corev1.AuthorizationResponse{
				Error: nil,
				Code:  "1234567891234567890",
				State: "af0ifjsldkj",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Arm mocks
			cg := authzmock.NewMockCodeGenerator(ctrl)
			clients := storagemock.NewMockClientReader(ctrl)
			authorizationRequests := storagemock.NewMockAuthorizationRequest(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(cg, clients, authorizationRequests)
			}

			// Prepare service
			underTest := New(cg, clients, authorizationRequests)

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
		prepare func(*authzmock.MockCodeGenerator, *storagemock.MockClientReader, *storagemock.MockAuthorizationRequest)
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
						State:               "af0ifjsldkj",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
						CodeChallengeMethod: "S256",
					},
				},
			},
			prepare: func(cg *authzmock.MockCodeGenerator, clients *storagemock.MockClientReader, _ *storagemock.MockAuthorizationRequest) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&registrationv1.Client{
					GrantTypes: []string{"client_credentials"},
				}, nil)
			},
			wantErr: true,
			want: &corev1.RegistrationResponse{
				Error: rfcerrors.UnsupportedGrantType("af0ifjsldkj"),
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
						State:               "af0ifjsldkj",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
						CodeChallengeMethod: "S256",
						Prompt:              &wrappers.StringValue{Value: "consent"},
					},
				},
			},
			prepare: func(cg *authzmock.MockCodeGenerator, clients *storagemock.MockClientReader, ar *storagemock.MockAuthorizationRequest) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&registrationv1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				}, nil)
				ar.EXPECT().Register(gomock.Any(), &corev1.AuthorizationRequest{
					ResponseType:        "code",
					Scope:               "openid profile email offline_access",
					ClientId:            "s6BhdRkqt3",
					State:               "af0ifjsldkj",
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
			cg := authzmock.NewMockCodeGenerator(ctrl)
			clients := storagemock.NewMockClientReader(ctrl)
			authorizationRequests := storagemock.NewMockAuthorizationRequest(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(cg, clients, authorizationRequests)
			}

			// Prepare service
			underTest := New(cg, clients, authorizationRequests)

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
