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

// -----------------------------------------------------------------------------

// ServerError returns a compliant `server_error` error.
func ServerError() ErrorBuilder {
	return &defaultErrorBuilder{
		err:              "server_error",
		errorDescription: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
	}
}

// InvalidRequest returns a compliant `invalid_request` error.
func InvalidRequest() ErrorBuilder {
	return &defaultErrorBuilder{
		err:              "invalid_request",
		errorDescription: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.",
	}
}

// InvalidScope returns a compliant `invalid_scope` error.
func InvalidScope() ErrorBuilder {
	return &defaultErrorBuilder{
		err:              "invalid_scope",
		errorDescription: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.",
	}
}

// InvalidGrant returns a compliant `invalid_grant` error.
func InvalidGrant() ErrorBuilder {
	return &defaultErrorBuilder{
		err:              "invalid_grant",
		errorDescription: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.",
	}
}

// InvalidClient returns a compliant `invalid_client` error.
func InvalidClient() ErrorBuilder {
	return &defaultErrorBuilder{
		err:              "invalid_client",
		errorDescription: "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).",
	}
}

// UnauthorizedClient returns a compliant `unauthorized_client` error.
func UnauthorizedClient() ErrorBuilder {
	return &defaultErrorBuilder{
		err:              "unauthorized_client",
		errorDescription: "The authenticated client is not authorized to use this authorization grant type.",
	}
}

// UnsupportedGrantType returns a compliant `unsupported_grant_type` error.
func UnsupportedGrantType() ErrorBuilder {
	return &defaultErrorBuilder{
		err:              "unsupported_grant_type",
		errorDescription: "The authorization grant type is not supported by the authorization server.",
	}
}

// InvalidToken returns a compliant `invalid_token` error.
func InvalidToken() ErrorBuilder {
	return &defaultErrorBuilder{
		err:              "invalid_token",
		errorDescription: "The access token provided is expired, revoked, malformed, or invalid for other reasons.",
	}
}

// AuthorizationPending returns a compliant `auhtorization_pending` error.
func AuthorizationPending() ErrorBuilder {
	return &defaultErrorBuilder{
		err:              "authorization_pending",
		errorDescription: "The authorization request is still pending as the end user hasn't yet completed the user-interaction steps.",
	}
}

// Slowdown returns a compliant `slow_down` error.
func Slowdown() ErrorBuilder {
	return &defaultErrorBuilder{
		err:              "slow_down",
		errorDescription: "The authorization request is still pending and polling should continue, but the interval MUST be increased by 5 seconds for this and all subsequent requests.",
	}
}

// AccessDenied returns a compliant `access_denied` error.
func AccessDenied() ErrorBuilder {
	return &defaultErrorBuilder{
		err:              "access_denied",
		errorDescription: "The authorization request was denied.",
	}
}

// TokenExpired returns a compliant `token_expired` error.
func TokenExpired() ErrorBuilder {
	return &defaultErrorBuilder{
		err:              "token_expired",
		errorDescription: "The 'device_code' has expired, and the device authorization session has concluded.",
	}
}

// InvalidDPoPProof returns a compliant `invalid_dpop_proof` error.
func InvalidDPoPProof() ErrorBuilder {
	return &defaultErrorBuilder{
		err:              "invalid_dpop_proof",
		errorDescription: "The provided DPoP proof is expired, malformed, or invalid for other reasons.",
	}
}

// InvalidRedirectURI returns a compliant `invalid_redirect_uri` error.
// https://tools.ietf.org/html/rfc7591#section-3.2.2
func InvalidRedirectURI() ErrorBuilder {
	return &defaultErrorBuilder{
		err:              "invalid_redirect_uri",
		errorDescription: "The value of one or more redirection URIs is invalid.",
	}
}

// InvalidClientMetadata returns a compliant `invalid_client_metadata` error.
// https://tools.ietf.org/html/rfc7591#section-3.2.2
func InvalidClientMetadata() ErrorBuilder {
	return &defaultErrorBuilder{
		err:              "invalid_client_metadata",
		errorDescription: "The value of one of the client metadata fields is invalid and the server has rejected this request.",
	}
}

// InvalidSoftwareStatement returns a compliant `invalid_software_statement` error.
// https://tools.ietf.org/html/rfc7591#section-3.2.2
func InvalidSoftwareStatement() ErrorBuilder {
	return &defaultErrorBuilder{
		err:              "invalid_software_statement",
		errorDescription: "The software statement presented is invalid.",
	}
}

// UnapprovedSoftwareStatement returns a compliant `unapproved_software_statement` error.
// https://tools.ietf.org/html/rfc7591#section-3.2.2
func UnapprovedSoftwareStatement() ErrorBuilder {
	return &defaultErrorBuilder{
		err:              "unapproved_software_statement",
		errorDescription: "The software statement presented is not approved for use by this authorization server.",
	}
}

// InvalidTarget returns a compliant `invalid_target` error.
// https://tools.ietf.org/html/rfc8707#section-2
func InvalidTarget() ErrorBuilder {
	return &defaultErrorBuilder{
		err:              "invalid_target",
		errorDescription: "The requested resource is invalid, missing, unknown, or malformed.",
	}
}
