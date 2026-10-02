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
	"strings"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/types"
)

// jwtBearer handles the JWT Bearer grant (RFC 7523 section 2.1) as
// profiled by draft-ietf-oauth-identity-assertion-authz-grant-04 section
// 4.4: the assertion MUST be an ID-JAG issued by a trusted external IdP
// Authorization Server.
func (s *service) jwtBearer(ctx context.Context, client *clientv1.Client, req *flowv1.TokenRequest) (*flowv1.TokenResponse, error) {
	res := &flowv1.TokenResponse{}
	grant := req.GetJwtBearer()

	// Shared grant validation: nullity, issuer syntax, grant capability.
	publicErr, err := validateGrantPreamble(client, req, oidc.GrantTypeJWTBearer)
	if err != nil {
		res.Error = publicErr
		return res, fmt.Errorf("unable to validate jwt-bearer preamble: %w", err)
	}
	if grant == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process with nil grant")
	}

	// Sender-constrained token policy (RFC 10027 section 6.1.12 for DPoP,
	// RFC 8705 section 3 for certificate bindings).
	if errBind := enforceSenderBinding(res, client, req); errBind != nil {
		return res, errBind
	}

	// The service must be wired with an ID-JAG verifier to honor this
	// grant; fail closed otherwise.
	if s.idjagVerifier == nil {
		res.Error = rfcerrors.UnsupportedGrantType().Build()
		return res, fmt.Errorf("ID-JAG verifier is not configured on this authorization server")
	}

	// draft section 4.4.1: verify the ID-JAG (typ, signature, trusted
	// issuer, aud == local issuer, temporal validity, REQUIRED claims)
	// and its binding to this request's client authentication and DPoP
	// proof.
	claims, err := s.verifyIDJAGAssertion(ctx, client, req, grant.Assertion)
	if err != nil {
		if res.Error == nil {
			res.Error = rfcerrors.InvalidGrant().Build()
		}
		return res, err
	}

	// RFC 9396 / draft section 4.4.1: requested authorization must not
	// exceed the ID-JAG's granted authorization. The granted set rides
	// into the access token.
	meta := &tokenv1.TokenMeta{
		Issuer:   req.Issuer,
		Subject:  claims.Sub,
		Audience: claims.Aud,
		Scope:    scopeOf(claims),
		GrantId:  claims.Jti,
	}
	if len(claims.Resource) > 0 {
		meta.Audience = claims.Resource[0]
	}
	if errNarrow := s.narrowIDJAGAuthorization(req, claims, meta); errNarrow != nil {
		if res.Error == nil {
			res.Error = rfcerrors.InvalidScope().Build()
		}
		return res, errNarrow
	}

	// Generate the access token, DPoP-bound to the presented proof key
	// (solid posture: sender-constrained tokens).
	at, err := s.generateAccessToken(ctx, client, meta, req.TokenConfirmation)
	if err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to generate access token: %w", err)
	}

	// draft section 4.4.3: no refresh token is issued for an ID-JAG
	// exchange.

	// Assign response.
	res.Issuer = req.Issuer
	res.AccessToken = at
	if claims.Scope != nil && meta.Scope != *claims.Scope {
		res.Scope = &meta.Scope
	}

	// No error
	return res, nil
}

// narrowIDJAGAuthorization applies RFC 9396 section 6 and RFC 6749 section
// 3.3 narrowing to the ID-JAG authorization context: a request may narrow
// the granted scope and authorization_details but never widen them. On
// failure it assigns the protocol error to the response and returns its
// cause.
func (s *service) narrowIDJAGAuthorization(req *flowv1.TokenRequest, claims *tokenv1.IdentityAssertionJWTAuthorizationGrant, meta *tokenv1.TokenMeta) error {
	// Authorization details: a request may narrow but never widen.
	if len(req.AuthorizationDetails) > 0 {
		if err := validateAuthorizationDetailsSubset(req.AuthorizationDetails, claims.AuthorizationDetails); err != nil {
			return fmt.Errorf("requested authorization_details exceed the ID-JAG grant: %w", err)
		}
		meta.AuthorizationDetails = req.AuthorizationDetails
	} else if len(claims.AuthorizationDetails) > 0 {
		meta.AuthorizationDetails = claims.AuthorizationDetails
	}

	// Scope narrowing: a requested scope must be within the ID-JAG scope.
	if req.Scope != nil && *req.Scope != "" {
		granted := types.StringArray{}
		if claims.Scope != nil {
			granted = types.StringArray(strings.Fields(*claims.Scope))
		}
		for _, sc := range strings.Fields(*req.Scope) {
			if !granted.Contains(sc) {
				return fmt.Errorf("requested scope '%s' exceeds the ID-JAG grant", *req.Scope)
			}
		}
		meta.Scope = *req.Scope
	}
	return nil
}

// scopeOf extracts the optional ID-JAG scope claim as a plain string.
func scopeOf(claims *tokenv1.IdentityAssertionJWTAuthorizationGrant) string {
	if claims.Scope == nil {
		return ""
	}
	return *claims.Scope
}

// verifyIDJAGAssertion verifies the raw ID-JAG and its request bindings:
// profile validation (typ, signature, issuer trust, audience, temporal
// validity, REQUIRED claims), client continuity (client_id claim equals
// the authenticated client), and DPoP key binding (cnf.jkt equals the
// presented proof thumbprint). On failure the caller assigns the protocol
// error; the cause is returned here.
func (s *service) verifyIDJAGAssertion(ctx context.Context, client *clientv1.Client, req *flowv1.TokenRequest, assertion string) (*tokenv1.IdentityAssertionJWTAuthorizationGrant, error) {
	// draft section 4.4.1: profile validation of the ID-JAG.
	claims, err := s.idjagVerifier.Verify(ctx, assertion)
	if err != nil {
		return nil, fmt.Errorf("invalid ID-JAG assertion: %w", err)
	}

	// draft section 4.4.1: the client_id claim MUST identify the same
	// client as the client authentication of the request.
	if !types.SecureCompareString(claims.ClientId, client.ClientId) {
		return nil, fmt.Errorf("ID-JAG client_id claim does not match the authenticated client")
	}

	// draft section 9.8.1.2: when the ID-JAG is key-bound (cnf.jkt), the
	// DPoP proof presented with this request MUST demonstrate possession
	// of the same key.
	if claims.CnfJkt != nil && *claims.CnfJkt != "" {
		if req.TokenConfirmation == nil || !types.SecureCompareString(*claims.CnfJkt, req.TokenConfirmation.Jkt) {
			return nil, fmt.Errorf("proof of possession required: ID-JAG key binding does not match the DPoP proof")
		}
	}

	return claims, nil
}
