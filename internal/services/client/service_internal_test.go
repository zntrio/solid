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
	"github.com/google/go-cmp/cmp/cmpopts"
	"google.golang.org/protobuf/types/known/wrapperspb"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/api/oidc"
	"zntr.io/solid/pkg/profile"
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
			want:    rfcerrors.InvalidRequest().Build(),
		},
		{
			name: "empty request",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest().Build(),
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
			want:    rfcerrors.InvalidRequest().Build(),
		},
		// ---------------------------------------------------------------------
		{
			name: "all: invalid application_type value",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{
					Metadata: &corev1.ClientMeta{
						ApplicationType: &wrapperspb.StringValue{Value: "foo"},
					},
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidRequest().Description("application_type contains an invalid or unsupported value.").Build(),
		},
		{
			name: "all: missing token_endpoint_auth_method value",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{
					Metadata: &corev1.ClientMeta{
						ApplicationType: &wrapperspb.StringValue{Value: oidc.ApplicationTypeService},
					},
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidClientMetadata().Build(),
		},
		{
			name: "all: empty token_endpoint_auth_method value",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{
					Metadata: &corev1.ClientMeta{
						ApplicationType: &wrapperspb.StringValue{Value: oidc.ApplicationTypeService},
						TokenEndpointAuthMethod: &wrapperspb.StringValue{
							Value: "",
						},
					},
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidClientMetadata().Description("token_endpoint_auth_method contains an invalid or unsupported value.").Build(),
		},
		{
			name: "all: invalid token_endpoint_auth_method value",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{
					Metadata: &corev1.ClientMeta{
						ApplicationType: &wrapperspb.StringValue{Value: oidc.ApplicationTypeService},
						TokenEndpointAuthMethod: &wrapperspb.StringValue{
							Value: "foo",
						},
					},
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidClientMetadata().Description("token_endpoint_auth_method contains an invalid or unsupported value.").Build(),
		},
		{
			name: "all: unsupported token_endpoint_auth_method value for application type",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{
					Metadata: &corev1.ClientMeta{
						ApplicationType: &wrapperspb.StringValue{Value: oidc.ApplicationTypeService},
						TokenEndpointAuthMethod: &wrapperspb.StringValue{
							Value: oidc.AuthMethodClientSecretBasic,
						},
					},
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidClientMetadata().Description("token_endpoint_auth_method contains an invalid or unsupported value.").Build(),
		},
		// ---------------------------------------------------------------------
		{
			name: "all: empty response_types value",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{
					Metadata: &corev1.ClientMeta{
						ApplicationType: &wrapperspb.StringValue{Value: oidc.ApplicationTypeService},
						TokenEndpointAuthMethod: &wrapperspb.StringValue{
							Value: oidc.AuthMethodPrivateKeyJWT,
						},
						ResponseTypes: []string{},
					},
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidClientMetadata().Build(),
		},
		{
			name: "all: invalid response_types value",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{
					Metadata: &corev1.ClientMeta{
						ApplicationType: &wrapperspb.StringValue{Value: oidc.ApplicationTypeService},
						TokenEndpointAuthMethod: &wrapperspb.StringValue{
							Value: oidc.AuthMethodPrivateKeyJWT,
						},
						ResponseTypes: []string{"foo"},
					},
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidClientMetadata().Description("response_types contains an invalid or unsupported value.").Build(),
		},

		// ---------------------------------------------------------------------
		{
			name: "all: empty grant_types value",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{
					Metadata: &corev1.ClientMeta{
						ApplicationType: &wrapperspb.StringValue{Value: oidc.ApplicationTypeServerSideWeb},
						RedirectUris: []string{
							"http://127.0.0.1:8085/as/127.0.0.1/cb",
						},
						TokenEndpointAuthMethod: &wrapperspb.StringValue{
							Value: oidc.AuthMethodPrivateKeyJWT,
						},
						ResponseTypes: []string{oidc.ResponseTypeCode},
						GrantTypes:    []string{},
					},
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidClientMetadata().Build(),
		},
		{
			name: "all: invalid grant_types value",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{
					Metadata: &corev1.ClientMeta{
						ApplicationType: &wrapperspb.StringValue{Value: oidc.ApplicationTypeServerSideWeb},
						RedirectUris: []string{
							"http://127.0.0.1:8085/as/127.0.0.1/cb",
						},
						TokenEndpointAuthMethod: &wrapperspb.StringValue{
							Value: oidc.AuthMethodPrivateKeyJWT,
						},
						ResponseTypes: []string{oidc.ResponseTypeCode},
						GrantTypes:    []string{oidc.GrantTypeAuthorizationCode, "foo"},
					},
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidClientMetadata().Description("grant_types contains an invalid or unsupported value.").Build(),
		},

		{
			name: "authorization_code: empty redirect_uris",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{
					Metadata: &corev1.ClientMeta{
						ApplicationType: &wrapperspb.StringValue{Value: oidc.ApplicationTypeServerSideWeb},
						TokenEndpointAuthMethod: &wrapperspb.StringValue{
							Value: oidc.AuthMethodPrivateKeyJWT,
						},
						ResponseTypes: []string{oidc.ResponseTypeCode},
						GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					},
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidClientMetadata().Build(),
		},
		{
			name: "authorization_code: invalid redirect_uris",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{
					Metadata: &corev1.ClientMeta{
						ApplicationType: &wrapperspb.StringValue{Value: oidc.ApplicationTypeServerSideWeb},
						TokenEndpointAuthMethod: &wrapperspb.StringValue{
							Value: oidc.AuthMethodPrivateKeyJWT,
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
			want:    rfcerrors.InvalidRedirectURI().Build(),
		},
		{
			name: "authorization_code: invalid response_type",
			args: args{
				ctx: context.Background(),
				req: &corev1.ClientRegistrationRequest{
					Metadata: &corev1.ClientMeta{
						ApplicationType: &wrapperspb.StringValue{Value: oidc.ApplicationTypeServerSideWeb},
						TokenEndpointAuthMethod: &wrapperspb.StringValue{
							Value: oidc.AuthMethodPrivateKeyJWT,
						},
						ResponseTypes: []string{"foo"},
						GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
						RedirectUris: []string{
							"http://127.0.0.1:8085/as/127.0.0.1/cb",
						},
					},
				},
			},
			wantErr: true,
			want:    rfcerrors.InvalidClientMetadata().Description("response_types contains an invalid or unsupported value for authorization code flow").Build(),
		},
		/*
			{
				name: "client_credentials: invalid response_type",
				args: args{
					ctx: context.Background(),
					req: &corev1.ClientRegistrationRequest{
						Metadata: &corev1.ClientMeta{
							ApplicationType: &wrapperspb.StringValue{Value: oidc.ApplicationTypeService},
							TokenEndpointAuthMethod: &wrapperspb.StringValue{
								Value: oidc.AuthMethodClientSecretBasic,
							},
							ResponseTypes: []string{oidc.ResponseTypeCode},
							GrantTypes:    []string{oidc.GrantTypeClientCredentials},
							RedirectUris: []string{
								"http://127.0.0.1:8085/as/127.0.0.1/cb",
							},
						},
					},
				},
				wantErr: true,
				want:    rfcerrors.InvalidClientMetadata(),
			},
			{
				name: "refresh_token: invalid response_type",
				args: args{
					ctx: context.Background(),
					req: &corev1.ClientRegistrationRequest{
						Metadata: &corev1.ClientMeta{
							ApplicationType: &wrapperspb.StringValue{Value: oidc.ApplicationTypeNative},
							TokenEndpointAuthMethod: &wrapperspb.StringValue{
								Value: oidc.AuthMethodClientSecretBasic,
							},
							ResponseTypes: []string{oidc.ResponseTypeCode},
							GrantTypes:    []string{oidc.GrantTypeRefreshToken},
							RedirectUris: []string{
								"http://127.0.0.1:8085/as/127.0.0.1/cb",
							},
						},
					},
				},
				wantErr: true,
				want:    rfcerrors.InvalidClientMetadata(),
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
							Jwks:          &wrapperspb.BytesValue{Value: []byte(`{;`)},
						},
					},
				},
				wantErr: true,
				want:    rfcerrors.InvalidClientMetadata(),
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
							Jwks:          &wrapperspb.BytesValue{Value: []byte(`{;`)},
						},
					},
				},
				wantErr: true,
				want:    rfcerrors.InvalidClientMetadata(),
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
				want:    rfcerrors.InvalidClientMetadata(),
			},
			// ---------------------------------------------------------------------
			{
				name: "valid",
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
				wantErr: false,
			},*/
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Arm mocks
			clients := storagemock.NewMockClient(ctrl)

			// Prepare service
			underTest := &service{
				clients:       clients,
				serverProfile: profile.Strict(),
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
