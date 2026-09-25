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

	"github.com/google/go-cmp/cmp"
	"go.uber.org/mock/gomock"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	sessionv1 "zntr.io/solid/api/oidc/session/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	random "zntr.io/solid/sdk/random"
	"zntr.io/solid/sdk/rfcerrors"
	tokenmock "zntr.io/solid/sdk/token/mock"
	"zntr.io/solid/sdk/types"
	"zntr.io/solid/server/storage"
	storagemock "zntr.io/solid/server/storage/mock"
)

func Test_service_authorizationCode(t *testing.T) {
	type args struct {
		ctx    context.Context
		client *clientv1.Client
		req    *flowv1.TokenRequest
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*storagemock.MockAuthorizationCodeSession, *storagemock.MockToken, *storagemock.MockResourceReader, *tokenmock.MockGenerator, *tokenmock.MockGenerator)
		want    *flowv1.TokenResponse
		wantErr bool
	}{
		{
			name: "nil request",
			args: args{
				ctx:    context.Background(),
				client: &clientv1.Client{},
				req:    nil,
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "nil client",
			args: args{
				ctx:    context.Background(),
				client: nil,
				req:    &flowv1.TokenRequest{},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "nil grant",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes: []string{oidc.GrantTypeAuthorizationCode},
				},
				req: &flowv1.TokenRequest{
					Issuer:    "http://127.0.0.1:8080",
					GrantType: oidc.GrantTypeAuthorizationCode,
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "missing issuer",
			args: args{
				ctx:    context.Background(),
				client: &clientv1.Client{},
				req: &flowv1.TokenRequest{
					Issuer:    "",
					Client:    &clientv1.Client{},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{},
					},
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "invalid issuer",
			args: args{
				ctx:    context.Background(),
				client: &clientv1.Client{},
				req: &flowv1.TokenRequest{
					Issuer:    "foo",
					Client:    &clientv1.Client{},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{},
					},
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidRequest().Build(),
			},
		},
		{
			name: "client not support grant_type",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					GrantTypes:    []string{oidc.GrantTypeClientCredentials},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.UnauthorizedClient().Build(),
			},
		},
		{
			name: "missing code",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "code too long",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         random.String(1025),
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "missing code_verifier",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:        "1234567891234567890",
							RedirectUri: "https://client.example.org/cb",
						},
					},
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "code_verifier too short",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "foo",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "code_verifier too short",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: random.String(129),
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "code_verifier contains reserved characters",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "bcd$efghijklmnopqrstuvwxyzabcdefghijklmn",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "missing redirect_uri",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
						},
					},
				},
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "authorization request not found",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().DeleteAndGet(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(nil, storage.ErrNotFound)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "authorization request storage error",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().DeleteAndGet(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(nil, fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "nil authorization request",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb12346",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().DeleteAndGet(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(&sessionv1.AuthorizationCodeSession{
					Request: nil,
				}, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().Build(),
			},
		},
		{
			name: "session deletion error",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb12346",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().DeleteAndGet(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(&sessionv1.AuthorizationCodeSession{
					Status: sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
					Request: &flowv1.AuthorizationRequest{
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
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				// The atomic consume replaced the Get+Delete pair; a
				// successfully consumed session failing later checks is an
				// invalid_grant, not a storage error.
				Error: rfcerrors.InvalidGrant().State("af0ifjsldkj").Build(),
			},
		},
		{
			name: "redirect_uri mismatch",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb12346",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().DeleteAndGet(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(&sessionv1.AuthorizationCodeSession{
					Status: sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
					Request: &flowv1.AuthorizationRequest{
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
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().State("af0ifjsldkj").Build(),
			},
		},
		{
			name: "redirect_uri mismatch: client changes between request",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb1",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().DeleteAndGet(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(&sessionv1.AuthorizationCodeSession{
					Status: sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
					Request: &flowv1.AuthorizationRequest{
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
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().State("af0ifjsldkj").Build(),
			},
		},
		{
			name: "session without consumed status is rejected",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb1"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb1",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().DeleteAndGet(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(&sessionv1.AuthorizationCodeSession{
					// An UNSPECIFIED session surfacing from the atomic
					// consume indicates a non-conforming storage; reject.
					Status: sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_UNSPECIFIED,
					Request: &flowv1.AuthorizationRequest{
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
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().State("af0ifjsldkj").Build(),
			},
		},
		{
			name: "client mismatch between session and token request",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "other-client",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "other-client",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().DeleteAndGet(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(&sessionv1.AuthorizationCodeSession{
					Status: sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
					Request: &flowv1.AuthorizationRequest{
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
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().State("af0ifjsldkj").Build(),
			},
		},
		{
			name: "code bound to DPoP key, no proof presented",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().DeleteAndGet(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(&sessionv1.AuthorizationCodeSession{
					Status: sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
					Confirmation: &tokenv1.TokenConfirmation{
						Jkt: "jkt1",
					},
					Request: &flowv1.AuthorizationRequest{
						ClientId:            "s6BhdRkqt3",
						State:               "af0ifjsldkj",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
						CodeChallengeMethod: "S256",
					},
				}, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().State("af0ifjsldkj").Build(),
			},
		},
		{
			name: "code DPoP key mismatch",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
							DpopJkt:      new("jkt2"),
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().DeleteAndGet(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(&sessionv1.AuthorizationCodeSession{
					Status: sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
					Confirmation: &tokenv1.TokenConfirmation{
						Jkt: "jkt1",
					},
					Request: &flowv1.AuthorizationRequest{
						ClientId:            "s6BhdRkqt3",
						State:               "af0ifjsldkj",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
						CodeChallengeMethod: "S256",
					},
				}, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().State("af0ifjsldkj").Build(),
			},
		},
		{
			name: "grant dpop_jkt present, token confirmation missing",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
							DpopJkt:      new("jkt1"),
						},
					},
					TokenConfirmation: nil,
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().DeleteAndGet(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(&sessionv1.AuthorizationCodeSession{
					Status: sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
					Request: &flowv1.AuthorizationRequest{
						ClientId:            "s6BhdRkqt3",
						State:               "af0ifjsldkj",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
						CodeChallengeMethod: "S256",
					},
				}, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().State("af0ifjsldkj").Build(),
			},
		},
		{
			name: "grant dpop_jkt mismatch with token confirmation",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
							DpopJkt:      new("jkt1"),
						},
					},
					TokenConfirmation: &tokenv1.TokenConfirmation{
						Jkt: "jkt2",
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().DeleteAndGet(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(&sessionv1.AuthorizationCodeSession{
					Status: sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
					Request: &flowv1.AuthorizationRequest{
						ClientId:            "s6BhdRkqt3",
						State:               "af0ifjsldkj",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
						CodeChallengeMethod: "S256",
					},
				}, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().State("af0ifjsldkj").Build(),
			},
		},
		{
			name: "invalid code_verifier",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "foofoofoofoofoofoofoofoofoofoofoofoofoofoofoo",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().DeleteAndGet(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(&sessionv1.AuthorizationCodeSession{
					Status: sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
					Request: &flowv1.AuthorizationRequest{
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
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().State("af0ifjsldkj").Build(),
			},
		},
		{
			name: "invalid code_challenge_method",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().DeleteAndGet(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(&sessionv1.AuthorizationCodeSession{
					Status: sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
					Request: &flowv1.AuthorizationRequest{
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
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().State("af0ifjsldkj").Build(),
			},
		},
		{
			name: "authorization_details not consented",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType:            oidc.GrantTypeAuthorizationCode,
					AuthorizationDetails: []*tokenv1.AuthorizationDetail{{Type: "payment"}},
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().DeleteAndGet(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(&sessionv1.AuthorizationCodeSession{
					Status: sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
					Request: &flowv1.AuthorizationRequest{
						ClientId:            "s6BhdRkqt3",
						State:               "af0ifjsldkj",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
						CodeChallengeMethod: "S256",
						AuthorizationDetails: []*tokenv1.AuthorizationDetail{
							{Type: "account"},
						},
					},
				}, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidAuthorizationDetails().Build(),
			},
		},
		{
			name: "resource indicator lookup storage error",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockToken, resources *storagemock.MockResourceReader, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().DeleteAndGet(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(&sessionv1.AuthorizationCodeSession{
					Status: sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
					Request: &flowv1.AuthorizationRequest{
						ClientId:            "s6BhdRkqt3",
						State:               "af0ifjsldkj",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
						CodeChallengeMethod: "S256",
						Resource:            []string{"https://res.example.com"},
					},
				}, nil)
				resources.EXPECT().GetByURI(gomock.Any(), "https://res.example.com").Return(nil, fmt.Errorf("boom"))
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().State("af0ifjsldkj").Build(),
			},
		},
		{
			name: "scope without openid returns empty response",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().DeleteAndGet(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(&sessionv1.AuthorizationCodeSession{
					Status: sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
					Request: &flowv1.AuthorizationRequest{
						ClientId:            "s6BhdRkqt3",
						State:               "af0ifjsldkj",
						Scope:               "email profile",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
						CodeChallengeMethod: "S256",
					},
				}, nil)
			},
			wantErr: false,
			want:    &flowv1.TokenResponse{},
		},
		// ---------------------------------------------------------------------
		{
			name: "openid: generate access token error",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockToken, _ *storagemock.MockResourceReader, at *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().DeleteAndGet(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(&sessionv1.AuthorizationCodeSession{
					Status: sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
					Request: &flowv1.AuthorizationRequest{
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
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("", fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "openid: empty generated access token",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockToken, _ *storagemock.MockResourceReader, at *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().DeleteAndGet(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(&sessionv1.AuthorizationCodeSession{
					Status: sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
					Request: &flowv1.AuthorizationRequest{
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
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("", nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "openid: access token storage error",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, tokens *storagemock.MockToken, _ *storagemock.MockResourceReader, at *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().DeleteAndGet(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(&sessionv1.AuthorizationCodeSession{
					Status: sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
					Request: &flowv1.AuthorizationRequest{
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
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo", nil)
				tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "openid: generate refresh token error",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, tokens *storagemock.MockToken, _ *storagemock.MockResourceReader, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				sessions.EXPECT().DeleteAndGet(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(&sessionv1.AuthorizationCodeSession{
					Status: sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
					Request: &flowv1.AuthorizationRequest{
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
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo", nil)
				tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(nil)
				rt.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("", fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "openid: empty generated refresh token",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, tokens *storagemock.MockToken, _ *storagemock.MockResourceReader, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				sessions.EXPECT().DeleteAndGet(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(&sessionv1.AuthorizationCodeSession{
					Status: sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
					Request: &flowv1.AuthorizationRequest{
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
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo", nil)
				tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(nil)
				rt.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("", nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		{
			name: "openid: refresh token storage error",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, tokens *storagemock.MockToken, _ *storagemock.MockResourceReader, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				sessions.EXPECT().DeleteAndGet(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(&sessionv1.AuthorizationCodeSession{
					Status: sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
					Request: &flowv1.AuthorizationRequest{
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
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo", nil)
				atSave := tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(nil)
				rt.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi", nil)
				tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(fmt.Errorf("foo")).After(atSave)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.ServerError().Build(),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "openid: valid",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, tokens *storagemock.MockToken, _ *storagemock.MockResourceReader, at *tokenmock.MockGenerator, rt *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				sessions.EXPECT().DeleteAndGet(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(&sessionv1.AuthorizationCodeSession{
					Status: sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
					Request: &flowv1.AuthorizationRequest{
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
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo", nil)
				atSave := tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(nil)
				rt.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("LHT.djeMMoErRAsLuXLlDYZDGdodfVLOduDi", nil)
				tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(nil).After(atSave)
			},
			wantErr: false,
			want: &flowv1.TokenResponse{
				Error: nil,
				AccessToken: &tokenv1.Token{
					TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						ClientId:  "s6BhdRkqt3",
						Audience:  "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						Scope:     "openid profile email offline_access",
						IssuedAt:  1,
						NotBefore: 2,
						ExpiresAt: 3601,
					},
					Value: "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
				},
				RefreshToken: &tokenv1.Token{
					TokenType: tokenv1.TokenType_TOKEN_TYPE_REFRESH_TOKEN,
					Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						ClientId:  "s6BhdRkqt3",
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
		{
			name: "openid: DPoP-bound code with matching key",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
							DpopJkt:      types.StringRef("0ZCat6lh5RWAddz9W0j43PFtzl6Ph2K54NfLxQXT2M8"),
						},
					},
					// Token-endpoint DPoP proof confirmation, as set by the
					// HTTP handler from the verified proof (RFC 9449 section 10).
					TokenConfirmation: &tokenv1.TokenConfirmation{
						Jkt: "0ZCat6lh5RWAddz9W0j43PFtzl6Ph2K54NfLxQXT2M8",
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, tokens *storagemock.MockToken, _ *storagemock.MockResourceReader, at *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				timeFunc = func() time.Time { return time.Unix(1, 0) }
				sessions.EXPECT().DeleteAndGet(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(&sessionv1.AuthorizationCodeSession{
					Status: sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
					Confirmation: &tokenv1.TokenConfirmation{
						Jkt: "0ZCat6lh5RWAddz9W0j43PFtzl6Ph2K54NfLxQXT2M8",
					},
					Request: &flowv1.AuthorizationRequest{
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
				at.EXPECT().Generate(gomock.Any(), gomock.Any()).Return("cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo", nil)
				tokens.EXPECT().Create(gomock.Any(), "http://127.0.0.1:8080", gomock.Any()).Return(nil)
			},
			wantErr: false,
			want: &flowv1.TokenResponse{
				Error: nil,
				AccessToken: &tokenv1.Token{
					TokenType: tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN,
					Status:    tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
					Metadata: &tokenv1.TokenMeta{
						Issuer:    "http://127.0.0.1:8080",
						ClientId:  "s6BhdRkqt3",
						Audience:  "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
						Scope:     "openid profile email",
						IssuedAt:  1,
						NotBefore: 2,
						ExpiresAt: 3601,
					},
					Confirmation: &tokenv1.TokenConfirmation{
						Jkt: "0ZCat6lh5RWAddz9W0j43PFtzl6Ph2K54NfLxQXT2M8",
					},
					Value: "cwE.HcbVtkyQCyCUfjxYvjHNODfTbVpSlmyo",
				},
			},
		},
		{
			name: "openid: DPoP-bound code with mismatched key is rejected",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
							DpopJkt:      types.StringRef("attacker-key-thumbprint-not-the-bound-one"),
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().DeleteAndGet(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(&sessionv1.AuthorizationCodeSession{
					Status: sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
					Confirmation: &tokenv1.TokenConfirmation{
						Jkt: "0ZCat6lh5RWAddz9W0j43PFtzl6Ph2K54NfLxQXT2M8",
					},
					Request: &flowv1.AuthorizationRequest{
						ClientId:            "s6BhdRkqt3",
						State:               "af0ifjsldkj",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
						CodeChallengeMethod: "S256",
					},
				}, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().State("af0ifjsldkj").Build(),
			},
		},
		{
			name: "openid: DPoP-bound code without proof confirmation is rejected",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockToken, _ *storagemock.MockResourceReader, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().DeleteAndGet(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(&sessionv1.AuthorizationCodeSession{
					Status: sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
					Confirmation: &tokenv1.TokenConfirmation{
						Jkt: "0ZCat6lh5RWAddz9W0j43PFtzl6Ph2K54NfLxQXT2M8",
					},
					Request: &flowv1.AuthorizationRequest{
						ClientId:            "s6BhdRkqt3",
						State:               "af0ifjsldkj",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
						CodeChallengeMethod: "S256",
					},
				}, nil)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidGrant().State("af0ifjsldkj").Build(),
			},
		},
		{
			name: "unknown resource indicator is rejected",
			args: args{
				ctx: context.Background(),
				client: &clientv1.Client{
					ClientId:      "s6BhdRkqt3",
					GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
					ResponseTypes: []string{"code"},
					RedirectUris:  []string{"https://client.example.org/cb"},
				},
				req: &flowv1.TokenRequest{
					Issuer: "http://127.0.0.1:8080",
					Client: &clientv1.Client{
						ClientId: "s6BhdRkqt3",
					},
					GrantType: oidc.GrantTypeAuthorizationCode,
					Grant: &flowv1.TokenRequest_AuthorizationCode{
						AuthorizationCode: &flowv1.GrantAuthorizationCode{
							Code:         "1234567891234567890",
							CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
							RedirectUri:  "https://client.example.org/cb",
						},
					},
				},
			},
			prepare: func(sessions *storagemock.MockAuthorizationCodeSession, _ *storagemock.MockToken, resources *storagemock.MockResourceReader, _ *tokenmock.MockGenerator, _ *tokenmock.MockGenerator) {
				sessions.EXPECT().DeleteAndGet(gomock.Any(), "http://127.0.0.1:8080", "1234567891234567890").Return(&sessionv1.AuthorizationCodeSession{
					Status: sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
					Request: &flowv1.AuthorizationRequest{
						ClientId:            "s6BhdRkqt3",
						State:               "af0ifjsldkj",
						RedirectUri:         "https://client.example.org/cb",
						CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
						CodeChallengeMethod: "S256",
						Resource:            []string{"urn:example:unknown-api"},
					},
				}, nil)
				resources.EXPECT().GetByURI(gomock.Any(), "urn:example:unknown-api").Return(nil, storage.ErrNotFound)
			},
			wantErr: true,
			want: &flowv1.TokenResponse{
				Error: rfcerrors.InvalidTarget().State("af0ifjsldkj").Build(),
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
			resources := storagemock.NewMockResourceReader(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(sessions, tokens, resources, accessTokens, refreshTokens)
			}

			s := &service{
				authorizationCodeSessions: sessions,
				accessTokenGen:            accessTokens,
				refreshTokenGen:           refreshTokens,
				tokens:                    tokens,
				resources:                 resources,
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
