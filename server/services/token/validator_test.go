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
	"testing"

	"github.com/stretchr/testify/require"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	"zntr.io/solid/oidc"
)

// Test_validateRequest_unknownGrantType pins the RFC 6749 section 5.2 error
// code for unknown grant_type strings at the second validation level (the
// first level only checks syntax, not enumeration).
func Test_validateRequest_unknownGrantType(t *testing.T) {
	for _, grantType := range []string{"password", "client_credentials_mtls", "garbage"} {
		t.Run("grant_type="+grantType, func(t *testing.T) {
			err := validateRequest(context.Background(), &flowv1.TokenRequest{
				Issuer:    "http://127.0.0.1:8080",
				GrantType: grantType,
				Client:    &clientv1.Client{ClientId: "s6BhdRkqt3"},
			})
			require.NotNil(t, err)
			require.Equal(t, "unsupported_grant_type", err.Err)
		})
	}
}

// Test_validateRequest_blankIssuer pins the invalid_request classification
// of a blank issuer at the second validation level.
func Test_validateRequest_blankIssuer(t *testing.T) {
	err := validateRequest(context.Background(), &flowv1.TokenRequest{
		Issuer:    "",
		GrantType: oidc.GrantTypeAuthorizationCode,
		Client:    &clientv1.Client{ClientId: "s6BhdRkqt3"},
		Grant: &flowv1.TokenRequest_AuthorizationCode{
			AuthorizationCode: &flowv1.GrantAuthorizationCode{},
		},
	})
	require.NotNil(t, err)
	require.Equal(t, "invalid_request", err.Err)
}

// Test_validateRequest_grantSpecificity pins the invalid_grant
// classification when a known grant_type is selected but its grant payload
// is missing.
func Test_validateRequest_grantSpecificity(t *testing.T) {
	for _, grantType := range []string{
		oidc.GrantTypeAuthorizationCode,
		oidc.GrantTypeClientCredentials,
		oidc.GrantTypeDeviceCode,
		oidc.GrantTypeRefreshToken,
		oidc.GrantTypeTokenExchange,
	} {
		t.Run("grant_type="+grantType, func(t *testing.T) {
			err := validateRequest(context.Background(), &flowv1.TokenRequest{
				Issuer:    "http://127.0.0.1:8080",
				GrantType: grantType,
				Client:    &clientv1.Client{ClientId: "s6BhdRkqt3"},
			})
			require.NotNil(t, err)
			require.Equal(t, "invalid_grant", err.Err)
		})
	}
}
