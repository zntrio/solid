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

package client

import (
	"context"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"google.golang.org/protobuf/types/known/wrapperspb"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/api/oidc"
	"zntr.io/solid/pkg/rfcerrors"
	storagemock "zntr.io/solid/pkg/storage/mock"
)

var cmpOpts = []cmp.Option{
	cmpopts.IgnoreUnexported(wrapperspb.StringValue{}),
	cmpopts.IgnoreUnexported(corev1.ClientRegistrationRequest{}),
	cmpopts.IgnoreUnexported(corev1.ClientRegistrationResponse{}),
	cmpopts.IgnoreUnexported(corev1.Client{}),
	cmpopts.IgnoreUnexported(corev1.Error{}),
}

var defaultClientRegistrationValues = &corev1.ClientMeta{
	TokenEndpointAuthMethod: &wrapperspb.StringValue{
		Value: "client_secret_basic",
	},
	GrantTypes: []string{
		oidc.GrantTypeAuthorizationCode,
	},
	ResponseTypes: []string{
		oidc.ResponseTypeCode,
	},
	Scope: &wrapperspb.StringValue{
		Value: "openid",
	},
}

func Test_service_Register(t *testing.T) {
	type args struct {
		ctx context.Context
		req *corev1.ClientRegistrationRequest
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*storagemock.MockClient)
		want    *corev1.ClientRegistrationResponse
		wantErr bool
	}{
		{
			name: "nil request",
			args: args{
				ctx: context.Background(),
				req: nil,
			},
			wantErr: true,
			want: &corev1.ClientRegistrationResponse{
				Error: rfcerrors.InvalidRequest(""),
			},
		},
		{
			name: "empty request",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{},
			},
			wantErr: true,
			want: &corev1.ClientRegistrationResponse{
				Error: rfcerrors.InvalidRequest(""),
			},
		},
		{
			name: "error during client storage registration",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{
					Metadata: &corev1.ClientMeta{
						GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
						ResponseTypes: []string{oidc.ResponseTypeCode},
						RedirectUris: []string{
							"https://client.example.org/callback",
							"https://client.example.org/callback2",
						},
						ClientName: &wrapperspb.StringValue{Value: "My Example Client"},
						ClientNameI18N: map[string]string{
							"ja-Jpan-JP": "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
							"fr-FR":      "Mon Exemple de Client",
						},
						TokenEndpointAuthMethod: &wrapperspb.StringValue{Value: oidc.AuthMethodClientSecretBasic},
						LogoUri:                 &wrapperspb.StringValue{Value: "https://client.example.org/logo.png"},
						JwkUri:                  &wrapperspb.StringValue{Value: "https://client.example.org/my_public_keys.jwks"},
					},
				},
			},
			prepare: func(clients *storagemock.MockClient) {
				clients.EXPECT().Register(gomock.Any(), gomock.Any()).Return("", fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.ClientRegistrationResponse{
				Error: rfcerrors.ServerError(""),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "valid request",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{
					Metadata: &corev1.ClientMeta{
						GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
						ResponseTypes: []string{oidc.ResponseTypeCode},
						RedirectUris: []string{
							"https://client.example.org/callback",
							"https://client.example.org/callback2",
						},
						ClientName: &wrapperspb.StringValue{Value: "My Example Client"},
						ClientNameI18N: map[string]string{
							"ja-Jpan-JP": "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
							"fr-FR":      "Mon Exemple de Client",
						},
						ClientUri:               &wrapperspb.StringValue{Value: "https://client.example.org"},
						PolicyUri:               &wrapperspb.StringValue{Value: "https://client.example.org/policy"},
						TosUri:                  &wrapperspb.StringValue{Value: "https://client.example.org/tos"},
						TokenEndpointAuthMethod: &wrapperspb.StringValue{Value: oidc.AuthMethodClientSecretBasic},
						LogoUri:                 &wrapperspb.StringValue{Value: "https://client.example.org/logo.png"},
						JwkUri:                  &wrapperspb.StringValue{Value: "https://client.example.org/my_public_keys.jwks"},
					},
				},
			},
			prepare: func(clients *storagemock.MockClient) {
				clients.EXPECT().Register(gomock.Any(), gomock.Any()).Return("12345678", nil)
			},
			wantErr: false,
			want: &corev1.ClientRegistrationResponse{
				Error: nil,
				Client: &corev1.Client{
					ClientId:   "12345678",
					ClientName: "My Example Client",
					RedirectUris: []string{
						"https://client.example.org/callback",
						"https://client.example.org/callback2",
					},
					ResponseTypes: []string{oidc.ResponseTypeCode},
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ClientUri:     "https://client.example.org",
					PolicyUri:     "https://client.example.org/policy",
					TosUri:        "https://client.example.org/tos",
					LogoUri:       "https://client.example.org/logo.png",
					JwksUri:       "https://client.example.org/my_public_keys.jwks",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Arm mocks
			clients := storagemock.NewMockClient(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(clients)
			}

			// Prepare service
			underTest := New(clients, &defaultValueProvider{})

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
