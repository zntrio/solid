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
	"testing"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
)

func Test_messageValidator_ValidateTokenRequest(t *testing.T) {
	t.Parallel()

	mv, err := newMessageValidator()
	if err != nil {
		t.Fatalf("unable to create message validator: %v", err)
	}

	tests := []struct {
		name    string
		req     *flowv1.TokenRequest
		wantErr bool
	}{
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
		},
		{
			name:    "empty request",
			req:     &flowv1.TokenRequest{},
			wantErr: true,
		},
		{
			name: "issuer is not an uri",
			req: &flowv1.TokenRequest{
				Issuer:    "not-an-uri",
				GrantType: "client_credentials",
			},
			wantErr: true,
		},
		{
			name: "missing grant oneof",
			req: &flowv1.TokenRequest{
				Issuer:    "http://127.0.0.1:8080",
				GrantType: "client_credentials",
			},
			wantErr: true,
		},
		{
			name: "pkce verifier too short",
			req: &flowv1.TokenRequest{
				Issuer:    "http://127.0.0.1:8080",
				GrantType: "authorization_code",
				Grant: &flowv1.TokenRequest_AuthorizationCode{
					AuthorizationCode: &flowv1.GrantAuthorizationCode{
						Code:         "1234567891234567890",
						CodeVerifier: "too-short",
						RedirectUri:  "https://client.example.org/cb",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "valid client_credentials request",
			req: &flowv1.TokenRequest{
				Issuer:    "http://127.0.0.1:8080",
				Client:    &clientv1.Client{ClientId: "s6BhdRkqt3"},
				GrantType: "client_credentials",
				Grant: &flowv1.TokenRequest_ClientCredentials{
					ClientCredentials: &flowv1.GrantClientCredentials{},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := mv.ValidateTokenRequest(tt.req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateTokenRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
