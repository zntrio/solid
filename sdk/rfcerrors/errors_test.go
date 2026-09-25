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

package rfcerrors

import (
	"testing"

	corev1 "zntr.io/solid/api/oidc/core/v1"
)

// Test builders against the normative error codes and descriptions defined
// by RFC 6749 section 5.2, RFC 8628 section 3.5, RFC 6753, and RFC 9449
// section 7.2.
func Test_builders(t *testing.T) {
	tests := []struct {
		name string
		got  *corev1.Error
		want *corev1.Error
	}{
		{
			name: "server_error",
			got:  ServerError().Build(),
			want: &corev1.Error{Err: "server_error", ErrorDescription: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request."},
		},
		{
			name: "invalid_request",
			got:  InvalidRequest().Build(),
			want: &corev1.Error{Err: "invalid_request", ErrorDescription: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."},
		},
		{
			name: "invalid_scope",
			got:  InvalidScope().Build(),
			want: &corev1.Error{Err: "invalid_scope", ErrorDescription: "The requested scope is invalid, unknown, or malformed."},
		},
		{
			name: "invalid_grant",
			got:  InvalidGrant().Build(),
			want: &corev1.Error{Err: "invalid_grant", ErrorDescription: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client."},
		},
		{
			name: "invalid_client",
			got:  InvalidClient().Build(),
			want: &corev1.Error{Err: "invalid_client", ErrorDescription: "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method)."},
		},
		{
			name: "unauthorized_client",
			got:  UnauthorizedClient().Build(),
			want: &corev1.Error{Err: "unauthorized_client", ErrorDescription: "The authenticated client is not authorized to use this authorization grant type."},
		},
		{
			name: "unsupported_grant_type",
			got:  UnsupportedGrantType().Build(),
			want: &corev1.Error{Err: "unsupported_grant_type", ErrorDescription: "The authorization grant type is not supported by the authorization server."},
		},
		{
			name: "invalid_token",
			got:  InvalidToken().Build(),
			want: &corev1.Error{Err: "invalid_token", ErrorDescription: "The access token provided is expired, revoked, malformed, or invalid for other reasons."},
		},
		{
			name: "authorization_pending",
			got:  AuthorizationPending().Build(),
			want: &corev1.Error{Err: "authorization_pending", ErrorDescription: "The authorization request is still pending as the end user hasn't yet completed the user-interaction steps."},
		},
		{
			name: "slow_down",
			got:  Slowdown().Build(),
			want: &corev1.Error{Err: "slow_down", ErrorDescription: "The authorization request is still pending and polling should continue, but the interval MUST be increased by 5 seconds for this and all subsequent requests."},
		},
		{
			name: "access_denied",
			got:  AccessDenied().Build(),
			want: &corev1.Error{Err: "access_denied", ErrorDescription: "The authorization request was denied."},
		},
		{
			name: "expired_token per RFC 8628 section 3.5",
			got:  TokenExpired().Build(),
			want: &corev1.Error{Err: "expired_token", ErrorDescription: "The 'device_code' has expired, and the device authorization session has concluded."},
		},
		{
			name: "invalid_dpop_proof per RFC 9449 section 7.2",
			got:  InvalidDPoPProof().Build(),
			want: &corev1.Error{Err: "invalid_dpop_proof", ErrorDescription: "The provided DPoP proof is expired, malformed, or invalid for other reasons."},
		},
		{
			name: "unsupported_response_type per RFC 6749 section 4.1.2.1",
			got:  UnsupportedResponseType().Build(),
			want: &corev1.Error{Err: "unsupported_response_type", ErrorDescription: "The authorization server does not support obtaining an authorization code using this method."},
		},
		{
			name: "invalid_authorization_details per RFC 9396 section 5",
			got:  InvalidAuthorizationDetails().Build(),
			want: &corev1.Error{Err: "invalid_authorization_details", ErrorDescription: "The requested authorization details are invalid, unknown, or malformed."},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got.Err != tt.want.Err {
				t.Errorf("error code = %q, want %q", tt.got.Err, tt.want.Err)
			}
			if tt.got.ErrorDescription != tt.want.ErrorDescription {
				t.Errorf("error description = %q, want %q", tt.got.ErrorDescription, tt.want.ErrorDescription)
			}
		})
	}
}
