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

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/api/oidc"
	"zntr.io/solid/sdk/rfcerrors"
)

// ValidateRequest validates token request.
var validateRequest = func(ctx context.Context, req *corev1.TokenRequest) *corev1.Error {
	// Check req nullity
	if req == nil {
		return &corev1.Error{
			Err:              "invalid_request",
			ErrorDescription: "request is nil",
		}
	}

	// Validate issuer
	if req.Issuer == "" {
		return rfcerrors.ServerError().Build()
	}

	// Validate client authentication
	if req.Client == nil {
		return rfcerrors.InvalidClient().Build()
	}

	// Check assigned grant_type
	switch req.GrantType {
	case oidc.GrantTypeAuthorizationCode:
		if req.GetAuthorizationCode() == nil {
			return rfcerrors.InvalidGrant().Build()
		}
	case oidc.GrantTypeClientCredentials:
		if req.GetClientCredentials() == nil {
			return rfcerrors.InvalidGrant().Build()
		}
	case oidc.GrantTypeDeviceCode:
		if req.GetDeviceCode() == nil {
			return rfcerrors.InvalidGrant().Build()
		}
	case oidc.GrantTypeRefreshToken:
		if req.GetRefreshToken() == nil {
			return rfcerrors.InvalidGrant().Build()
		}
	case oidc.GrantTypeTokenExchange:
		if req.GetTokenExchange() == nil {
			return rfcerrors.InvalidGrant().Build()
		}
	default:
		return rfcerrors.InvalidGrant().Build()
	}

	// Return result
	return nil
}
