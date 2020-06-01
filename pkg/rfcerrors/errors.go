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
	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
)

// ServerError returns a compliant `server_error` error.
func ServerError(state string) *corev1.Error {
	return &corev1.Error{
		State:            state,
		Err:              "server_error",
		ErrorDescription: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
	}
}

// InvalidRequest returns a compliant `invalid_request` error.
func InvalidRequest(state string) *corev1.Error {
	return &corev1.Error{
		State:            state,
		Err:              "invalid_request",
		ErrorDescription: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.",
	}
}

// InvalidScope returns a compliant `invalid_scope` error.
func InvalidScope(state string) *corev1.Error {
	return &corev1.Error{
		State:            state,
		Err:              "invalid_scope",
		ErrorDescription: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.",
	}
}

// InvalidGrant returns a compliant `invalid_grant` error.
func InvalidGrant(state string) *corev1.Error {
	return &corev1.Error{
		State:            state,
		Err:              "invalid_grant",
		ErrorDescription: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.",
	}
}

// InvalidClient returns a compliant `invalid_client` error.
func InvalidClient(state string) *corev1.Error {
	return &corev1.Error{
		State:            state,
		Err:              "invalid_client",
		ErrorDescription: "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).",
	}
}

// UnauthorizedClient returns a compliant `unauthorized_client` error.
func UnauthorizedClient(state string) *corev1.Error {
	return &corev1.Error{
		State:            state,
		Err:              "unauthorized_client",
		ErrorDescription: "The authenticated client is not authorized to use this authorization grant type.",
	}
}

// UnsupportedGrantType returns a compliant `unsupported_grant_type` error.
func UnsupportedGrantType(state string) *corev1.Error {
	return &corev1.Error{
		State:            state,
		Err:              "unsupported_grant_type",
		ErrorDescription: "The authorization grant type is not supported by the authorization server.",
	}
}

// InvalidToken returns a compliant `invalid_token` error.
func InvalidToken() *corev1.Error {
	return &corev1.Error{
		Err:              "invalid_token",
		ErrorDescription: "The access token provided is expired, revoked, malformed, or invalid for other reasons.",
	}
}

// AuthorizationPending returns a compliant `auhtorization_pending` error.
func AuthorizationPending() *corev1.Error {
	return &corev1.Error{
		Err:              "authorization_pending",
		ErrorDescription: "The authorization request is still pending as the end user hasn't yet completed the user-interaction steps.",
	}
}

// Slowdown returns a compliant `slow_down` error.
func Slowdown() *corev1.Error {
	return &corev1.Error{
		Err:              "slow_down",
		ErrorDescription: "The authorization request is still pending and polling should continue, but the interval MUST be increased by 5 seconds for this and all subsequent requests.",
	}
}

// AccessDenied returns a compliant `access_denied` error.
func AccessDenied() *corev1.Error {
	return &corev1.Error{
		Err:              "access_denied",
		ErrorDescription: "The authorization request was denied.",
	}
}

// TokenExpired returns a compliant `token_expired` error.
func TokenExpired() *corev1.Error {
	return &corev1.Error{
		Err:              "token_expired",
		ErrorDescription: "The 'device_code' has expired, and the device authorization session has concluded.",
	}
}

// InvalidDPoPProof returns a compliant `invalid_dpop_proof` error.
func InvalidDPoPProof() *corev1.Error {
	return &corev1.Error{
		Err:              "invalid_dpop_proof",
		ErrorDescription: "The provided DPoP proof is expired, malformed, or invalid for other reasons.",
	}
}
