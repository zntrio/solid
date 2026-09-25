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
	"net/url"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/types"
)

func (s *service) clientCredentials(ctx context.Context, client *clientv1.Client, req *flowv1.TokenRequest) (*flowv1.TokenResponse, error) {
	res := &flowv1.TokenResponse{}
	grant := req.GetClientCredentials()

	// Check parameters
	if client == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to process with nil client")
	}
	if req == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to process with nil request")
	}
	if grant == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to process with nil grant")
	}

	// Check issuer syntax (RFC 6749 section 5.2: malformed client input is
	// an invalid_request, not a server fault).
	if req.Issuer == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("issuer must not be blank")
	}

	// Enforce issuer to be a valid URI
	_, err := url.ParseRequestURI(req.Issuer)
	if err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("issuer must be a valid url: %w", err)
	}

	// Ensure client type: only credentialed machine-to-machine clients may
	// use the client_credentials grant.
	switch client.ClientType {
	case clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL, clientv1.ClientType_CLIENT_TYPE_CREDENTIALED:
		// Valid
	case clientv1.ClientType_CLIENT_TYPE_UNSPECIFIED, clientv1.ClientType_CLIENT_TYPE_PUBLIC:
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client must be credentialed or confidential to use client_credential grant type")
	default:
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client must be credentialed or confidential to use client_credential grant type")
	}

	// RFC 9396: authorization_details are bound to end-user consent, which
	// the client_credentials grant has none of. Fail closed rather than
	// minting details without a consent authority.
	if len(req.AuthorizationDetails) > 0 {
		res.Error = rfcerrors.InvalidAuthorizationDetails().Build()
		return res, fmt.Errorf("authorization_details is not supported for this grant type")
	}

	// Validate client capabilities (RFC 6749 section 5.2:
	// unauthorized_client).
	if !types.StringArray(client.GrantTypes).Contains(oidc.GrantTypeClientCredentials) {
		res.Error = rfcerrors.UnauthorizedClient().Build()
		return res, fmt.Errorf("client is not authorized to use grant type '%s'", oidc.GrantTypeClientCredentials)
	}

	// Prepare token
	tokenMeta := &tokenv1.TokenMeta{
		Issuer:  req.Issuer,
		GrantId: newGrantID(),
	}
	if req.Scope != nil {
		tokenMeta.Scope = *req.Scope
	}
	if req.Audience != nil {
		tokenMeta.Audience = *req.Audience
	}

	// Generate access token
	at, err := s.generateAccessToken(ctx, client, tokenMeta, req.TokenConfirmation)
	if err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to generate access token: %w", err)
	}

	// Assign response
	res.AccessToken = at

	// No error
	return res, nil
}
