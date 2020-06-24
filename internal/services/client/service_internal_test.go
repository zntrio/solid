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
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/types/known/wrapperspb"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/api/oidc"
	"zntr.io/solid/pkg/rfcerrors"
	storagemock "zntr.io/solid/pkg/storage/mock"
)

func Test_service_validateRegistration(t *testing.T) {
	type args struct {
		ctx context.Context
		req *corev1.ClientRegistrationRequest
	}
	tests := []struct {
		name    string
		args    args
		want    *corev1.Error
		wantErr bool
	}{
		{
			name: "nil request",
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
				req: &corev1.ClientRegistrationRequest{},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest(""),
		},
		{
			name: "empty client meta",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{
					Metadata: &corev1.ClientMeta{},
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest(""),
		},
		// ---------------------------------------------------------------------
		{
			name: "all: empty token_endpoint_auth_method value",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{
					Metadata: &corev1.ClientMeta{
						TokenEndpointAuthMethod: &wrapperspb.StringValue{
							Value: "",
						},
					},
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest(""),
		},
		{
			name: "all: invalid token_endpoint_auth_method value",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{
					Metadata: &corev1.ClientMeta{
						TokenEndpointAuthMethod: &wrapperspb.StringValue{
							Value: "foo",
						},
					},
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest(""),
		},
		// ---------------------------------------------------------------------
		{
			name: "all: empty response_types value",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{
					Metadata: &corev1.ClientMeta{
						TokenEndpointAuthMethod: &wrapperspb.StringValue{
							Value: oidc.AuthMethodClientSecretBasic,
						},
						ResponseTypes: []string{},
					},
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest(""),
		},
		{
			name: "all: invalid response_types value",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{
					Metadata: &corev1.ClientMeta{
						TokenEndpointAuthMethod: &wrapperspb.StringValue{
							Value: oidc.AuthMethodClientSecretBasic,
						},
						ResponseTypes: []string{"foo"},
					},
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest(""),
		},
		// ---------------------------------------------------------------------
		{
			name: "all: empty grant_types value",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{
					Metadata: &corev1.ClientMeta{
						RedirectUris: []string{
							"http://127.0.0.1:8085/as/127.0.0.1/cb",
						},
						TokenEndpointAuthMethod: &wrapperspb.StringValue{
							Value: oidc.AuthMethodClientSecretBasic,
						},
						ResponseTypes: []string{oidc.ResponseTypeCode},
						GrantTypes:    []string{},
					},
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest(""),
		},
		{
			name: "all: invalid grant_types value",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{
					Metadata: &corev1.ClientMeta{
						RedirectUris: []string{
							"http://127.0.0.1:8085/as/127.0.0.1/cb",
						},
						TokenEndpointAuthMethod: &wrapperspb.StringValue{
							Value: oidc.AuthMethodClientSecretBasic,
						},
						ResponseTypes: []string{oidc.ResponseTypeCode},
						GrantTypes:    []string{oidc.GrantTypeAuthorizationCode, "foo"},
					},
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest(""),
		},
		{
			name: "authorization_code: empty redirect_uris",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{
					Metadata: &corev1.ClientMeta{
						TokenEndpointAuthMethod: &wrapperspb.StringValue{
							Value: oidc.AuthMethodClientSecretBasic,
						},
						ResponseTypes: []string{oidc.ResponseTypeCode},
						GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					},
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest(""),
		},
		{
			name: "authorization_code: invalid redirect_uris",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{
					Metadata: &corev1.ClientMeta{
						TokenEndpointAuthMethod: &wrapperspb.StringValue{
							Value: oidc.AuthMethodClientSecretBasic,
						},
						ResponseTypes: []string{oidc.ResponseTypeCode},
						GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
						RedirectUris: []string{
							"http://127.0.0.1:8085/as/127.0.0.1/cb",
							"",
						},
					},
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRedirectURI(),
		},
		{
			name: "authorization_code: invalid response_type",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{
					Metadata: &corev1.ClientMeta{
						TokenEndpointAuthMethod: &wrapperspb.StringValue{
							Value: oidc.AuthMethodClientSecretBasic,
						},
						ResponseTypes: []string{oidc.ResponseTypeToken},
						GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
						RedirectUris: []string{
							"http://127.0.0.1:8085/as/127.0.0.1/cb",
							"",
						},
					},
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest(""),
		},
		// ---------------------------------------------------------------------
		{
			name: "all: invalid JSON jwks value",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{
					Metadata: &corev1.ClientMeta{
						RedirectUris: []string{
							"http://127.0.0.1:8085/as/127.0.0.1/cb",
						},
						TokenEndpointAuthMethod: &wrapperspb.StringValue{
							Value: oidc.AuthMethodPrivateKeyJWT,
						},
						GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
						ResponseTypes: []string{oidc.ResponseTypeCode},
						Jwks:          []byte(`{;`),
					},
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest(""),
		},
		{
			name: "all: invalid jwks no keys",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{
					Metadata: &corev1.ClientMeta{
						RedirectUris: []string{
							"http://127.0.0.1:8085/as/127.0.0.1/cb",
						},
						TokenEndpointAuthMethod: &wrapperspb.StringValue{
							Value: oidc.AuthMethodPrivateKeyJWT,
						},
						GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
						ResponseTypes: []string{oidc.ResponseTypeCode},
						Jwks:          []byte(`{}`),
					},
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest(""),
		},
		{
			name: "all: missing jwks with private_key_jwt authentication",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{
					Metadata: &corev1.ClientMeta{
						RedirectUris: []string{
							"http://127.0.0.1:8085/as/127.0.0.1/cb",
						},
						TokenEndpointAuthMethod: &wrapperspb.StringValue{
							Value: oidc.AuthMethodPrivateKeyJWT,
						},
						GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
						ResponseTypes: []string{oidc.ResponseTypeCode},
					},
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest(""),
		},
		// ---------------------------------------------------------------------
		{
			name: "all: invalid scope",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{
					Metadata: &corev1.ClientMeta{
						RedirectUris: []string{
							"http://127.0.0.1:8085/as/127.0.0.1/cb",
						},
						TokenEndpointAuthMethod: &wrapperspb.StringValue{
							Value: oidc.AuthMethodClientSecretBasic,
						},
						GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
						ResponseTypes: []string{oidc.ResponseTypeCode},
						Scope:         &wrapperspb.StringValue{Value: "openid foo"},
					},
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest(""),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Arm mocks
			clients := storagemock.NewMockClientWriter(ctrl)

			// Prepare service
			underTest := &service{
				clients:       clients,
				valueProvider: &defaultValueProvider{},
			}

			// Do the request
			got, err := underTest.validateRegistration(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("service.validateRegistration() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
				t.Errorf("service.validateRegistration() res =%s", diff)
			}
		})
	}
}
