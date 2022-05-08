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

package token

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/dchest/uniuri"
	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/api/oidc"
	"zntr.io/solid/sdk/rfcerrors"
	tokenmock "zntr.io/solid/sdk/token/mock"
	"zntr.io/solid/server/storage"
	storagemock "zntr.io/solid/server/storage/mock"
)

func Test_service_authorizationCode(t *testing.T) {
	type args struct {
		ctx    context.Context
		client *corev1.Client
		req    *corev1.TokenRequest
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*storagemock.MockAuthorizationCodeSession, *storagemock.MockToken, *tokenmock.MockGenerator, *tokenmock.MockGenerator)
		want    *corev1.TokenResponse
		wantErr bool
	}{
		{
			name: "nil request",
			args: args{
				ctx:    context.Background(),
				client: &corev1.Client{},
				req:    nil,
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "nil client",
			args: args{
				ctx:    context.Background(),
				client: nil,
				req:    &corev1.TokenRequest{},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "nil grant",
			args: args{
				ctx:    context.Background(),
				client: &corev1.Client{},
				req: &corev1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					GrantType: oidc.GrantTypeAuthorizationCode,
				},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "missing issuer",
			args: args{
				ctx:    context.Background(),
				client: &corev1.Client{},
				req: &corev1.TokenRequest{
					Issuer:    "",
					Client:    &corev1.Client{},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &corev1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &corev1.GrantAuthorizationCode{},
					},
				},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "invalid issuer",
			args: args{
				ctx:    context.Background(),
				client: &corev1.Client{},
				req: &corev1.TokenRequest{
					Issuer:    "foo",
					Client:    &corev1.Client{},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &corev1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &corev1.GrantAuthorizationCode{},
					},
				},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "client not support grant_type",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes:    []string{oidc.GrantTypeClientCredentials},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &corev1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &corev1.GrantAuthorizationCode{
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.UnsupportedGrantType().Build(),
			},
		},
		{
			name: "missing code",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &corev1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &corev1.GrantAuthorizationCode{
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "code too long",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &corev1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &corev1.GrantAuthorizationCode{
							Code:         uniuri.NewLen(1025),
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "missing code_verifier",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &corev1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &corev1.GrantAuthorizationCode{
							Code:        "1234567891234567890",
							RedirectUri: "https://client.example.org/cb",
						},
					},
				},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "code_verifier too short",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &corev1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &corev1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "foo",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "code_verifier too short",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &corev1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &corev1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: uniuri.NewLen(129),
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "missing redirect_uri",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &corev1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &corev1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
						},
					},
				},
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "authorization request not found",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &corev1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &corev1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				sessions.EXPECT().Get(gomock.Any(), "1234567891234567890").Return(nil, storage.ErrNotFound)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "authorization request storage error",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &corev1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &corev1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				sessions.EXPECT().Get(gomock.Any(), "1234567891234567890").Return(nil, fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "nil authorization request",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &corev1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &corev1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb12346",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				sessions.EXPECT().Get(gomock.Any(), "1234567891234567890").Return(&corev1.AuthorizationCodeSession{
					Request: nil,
				}, nil)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "session deletion error",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &corev1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &corev1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb12346",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				sessions.EXPECT().Get(gomock.Any(), "1234567891234567890").Return(&corev1.AuthorizationCodeSession{
					Request: &corev1.AuthorizationRequest{
						Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						ResponseType:        "code",
						Scope:               "openid profile email",
						ClientId:            "s6BhdRkqt3",
						State:               "af0ifjsldkj",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
						CodeChallengeMethod: "S256",
					},
				}, nil)
				sessions.EXPECT().Delete(gomock.Any(), "1234567891234567890").Return(fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "redirect_uri mismatch",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &corev1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &corev1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb12346",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				sessions.EXPECT().Get(gomock.Any(), "1234567891234567890").Return(&corev1.AuthorizationCodeSession{
					Request: &corev1.AuthorizationRequest{
						Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						ResponseType:        "code",
						Scope:               "openid profile email",
						ClientId:            "s6BhdRkqt3",
						State:               "af0ifjsldkj",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
						CodeChallengeMethod: "S256",
					},
				}, nil)
				sessions.EXPECT().Delete(gomock.Any(), "1234567891234567890").Return(nil)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidGrant().State("af0ifjsldkj").Build(),
			},
		},
		{
			name: "redirect_uri mismatch: client changes between request",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &corev1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &corev1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb1",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				sessions.EXPECT().Get(gomock.Any(), "1234567891234567890").Return(&corev1.AuthorizationCodeSession{
					Request: &corev1.AuthorizationRequest{
						Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						ResponseType:        "code",
						Scope:               "openid profile email",
						ClientId:            "s6BhdRkqt3",
						State:               "af0ifjsldkj",
						RedirectUri:         "https://client.example.org/cb1",
						CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
						CodeChallengeMethod: "S256",
					},
				}, nil)
				sessions.EXPECT().Delete(gomock.Any(), "1234567891234567890").Return(nil)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidGrant().State("af0ifjsldkj").Build(),
			},
		},
		{
			name: "invalid code_verifier",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &corev1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &corev1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "foofoofoofoofoofoofoofoofoofoofoofoofoofoofoo",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				sessions.EXPECT().Get(gomock.Any(), "1234567891234567890").Return(&corev1.AuthorizationCodeSession{
					Request: &corev1.AuthorizationRequest{
						Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						ResponseType:        "code",
						Scope:               "openid profile email",
						ClientId:            "s6BhdRkqt3",
						State:               "af0ifjsldkj",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
						CodeChallengeMethod: "S256",
					},
				}, nil)
				sessions.EXPECT().Delete(gomock.Any(), "1234567891234567890").Return(nil)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidGrant().State("af0ifjsldkj").Build(),
			},
		},
		{
			name: "invalid code_challenge_method",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &corev1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &corev1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				sessions.EXPECT().Get(gomock.Any(), "1234567891234567890").Return(&corev1.AuthorizationCodeSession{
					Request: &corev1.AuthorizationRequest{
						Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						ResponseType:        "code",
						Scope:               "openid profile email",
						ClientId:            "s6BhdRkqt3",
						State:               "af0ifjsldkj",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
						CodeChallengeMethod: "xxx",
					},
				}, nil)
				sessions.EXPECT().Delete(gomock.Any(), "1234567891234567890").Return(nil)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.InvalidGrant().State("af0ifjsldkj").Build(),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "openid: generate access token error",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &corev1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &corev1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				sessions.EXPECT().Get(gomock.Any(), "1234567891234567890").Return(&corev1.AuthorizationCodeSession{
					Request: &corev1.AuthorizationRequest{
						Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						ResponseType:        "code",
						Scope:               "openid profile email",
						ClientId:            "s6BhdRkqt3",
						State:               "af0ifjsldkj",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
						CodeChallengeMethod: "S256",
					},
				}, nil)
				sessions.EXPECT().Delete(gomock.Any(), "1234567891234567890").Return(nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("", fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "openid: empty generated access token",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &corev1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &corev1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				sessions.EXPECT().Get(gomock.Any(), "1234567891234567890").Return(&corev1.AuthorizationCodeSession{
					Request: &corev1.AuthorizationRequest{
						Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						ResponseType:        "code",
						Scope:               "openid profile email",
						ClientId:            "s6BhdRkqt3",
						State:               "af0ifjsldkj",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
						CodeChallengeMethod: "S256",
					},
				}, nil)
				sessions.EXPECT().Delete(gomock.Any(), "1234567891234567890").Return(nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("", nil)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "openid: access token storage error",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &corev1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &corev1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				sessions.EXPECT().Get(gomock.Any(), "1234567891234567890").Return(&corev1.AuthorizationCodeSession{
					Request: &corev1.AuthorizationRequest{
						Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						ResponseType:        "code",
						Scope:               "openid profile email",
						ClientId:            "s6BhdRkqt3",
						State:               "af0ifjsldkj",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
						CodeChallengeMethod: "S256",
					},
				}, nil)
				sessions.EXPECT().Delete(gomock.Any(), "1234567891234567890").Return(nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo", nil)
				tokens.EXPECT().Create(gomock.Any(), gomock.Any()).Return(fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "openid: generate refresh token error",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &corev1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &corev1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				sessions.EXPECT().Get(gomock.Any(), "1234567891234567890").Return(&corev1.AuthorizationCodeSession{
					Request: &corev1.AuthorizationRequest{
						Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						ResponseType:        "code",
						Scope:               "openid profile email offline_access",
						ClientId:            "s6BhdRkqt3",
						State:               "af0ifjsldkj",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
						CodeChallengeMethod: "S256",
					},
				}, nil)
				sessions.EXPECT().Delete(gomock.Any(), "1234567891234567890").Return(nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo", nil)
				tokens.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
				rt.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("", fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "openid: empty generated refresh token",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &corev1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &corev1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				sessions.EXPECT().Get(gomock.Any(), "1234567891234567890").Return(&corev1.AuthorizationCodeSession{
					Request: &corev1.AuthorizationRequest{
						Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						ResponseType:        "code",
						Scope:               "openid profile email offline_access",
						ClientId:            "s6BhdRkqt3",
						State:               "af0ifjsldkj",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
						CodeChallengeMethod: "S256",
					},
				}, nil)
				sessions.EXPECT().Delete(gomock.Any(), "1234567891234567890").Return(nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo", nil)
				tokens.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
				rt.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("", nil)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "openid: refresh token storage error",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &corev1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &corev1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				sessions.EXPECT().Get(gomock.Any(), "1234567891234567890").Return(&corev1.AuthorizationCodeSession{
					Request: &corev1.AuthorizationRequest{
						Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						ResponseType:        "code",
						Scope:               "openid profile email offline_access",
						ClientId:            "s6BhdRkqt3",
						State:               "af0ifjsldkj",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
						CodeChallengeMethod: "S256",
					},
				}, nil)
				sessions.EXPECT().Delete(gomock.Any(), "1234567891234567890").Return(nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo", nil)
				atSave := tokens.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
				rt.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi", nil)
				tokens.EXPECT().Create(gomock.Any(), gomock.Any()).Return(fmt.Errorf("foo")).After(atSave)
			},
			wantErr: true,
			want: &corev1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "openid: valid",
			args: args{
				ctx: context.Background(),
				client: &corev1.Client{
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &corev1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &corev1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &corev1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &corev1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, tokens *storagemock.MockToken, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				sessions.EXPECT().Get(gomock.Any(), "1234567891234567890").Return(&corev1.AuthorizationCodeSession{
					Request: &corev1.AuthorizationRequest{
						Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						ResponseType:        "code",
						Scope:               "openid profile email offline_access",
						ClientId:            "s6BhdRkqt3",
						State:               "af0ifjsldkj",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
						CodeChallengeMethod: "S256",
					},
				}, nil)
				sessions.EXPECT().Delete(gomock.Any(), "1234567891234567890").Return(nil)
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo", nil)
				atSave := tokens.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
				rt.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi", nil)
				tokens.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil).After(atSave)
			},
			wantErr: false,
			want: &corev1.TokenResponse{
				Error: nil,
				AccessToken: &corev1.Token{
					TokenType: corev1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &corev1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						Audience:  "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						Scope:     "openid profile email offline_access",
						IssuedAt:  1,
						NotBefore: 2,
						ExpiresAt: 3601,
					},
					Value: "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
				},
				RefreshToken: &corev1.Token{
					TokenType: corev1.TokenType_TOKEN_TYPE_REFRESH_TOKEN,
					Status:    corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &corev1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						Audience:  "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						Scope:     "openid profile email offline_access",
						IssuedAt:  1,
						NotBefore: 2,
						ExpiresAt: 604801,
					},
					Value: "LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Arm mocks
			sessions := storagemock.NewMockAuthorizationCodeSession(ctrl)
			accessTokens := tokenmock.NewMockGenerator(ctrl)
			refreshTokens := tokenmock.NewMockGenerator(ctrl)
			tokens := storagemock.NewMockToken(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(sessions, tokens, accessTokens, refreshTokens)
			}

			s := &service{
				authorizationCodeSessions: sessions,
				accessTokenGen:            accessTokens,
				refreshTokenGen:           refreshTokens,
				tokens:                    tokens,
			}
			got, err := s.authorizationCode(tt.args.ctx, tt.args.client, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("service.authorizationCode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
				t.Errorf("service.authorizationCode() res = %s", diff)
			}
		})
	}
}
