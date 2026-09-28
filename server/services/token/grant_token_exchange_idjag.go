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
	"errors"
	"fmt"
	"strings"
	"time"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/random"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/types"
	"zntr.io/solid/server/storage"
)

// idjagLifetime is the default ID-JAG lifetime (identity-chaining section
// 5.5: short-lived grants minimize replay exposure).
const idjagLifetime = 5 * time.Minute

// tokenExchangeIDJAG handles Token Exchange requests with
// requested_token_type=urn:ietf:params:oauth:token-type:id-jag
// (draft-ietf-oauth-identity-assertion-authz-grant-04 section 4.3).
//
//nolint:gocyclo,funlen // linear RFC-ordered validation chain; each guard is a protocol requirement
func (s *service) tokenExchangeIDJAG(ctx context.Context, client *clientv1.Client, req *flowv1.TokenRequest, res *flowv1.TokenResponse) error {
	grant := req.GetTokenExchange()

	// The IdP role requires signer, audience resolver and subject
	// resolver; fail closed when unwired.
	if s.idjagSigner == nil || s.idjagAudienceResolver == nil || s.idjagSubjectResolver == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return fmt.Errorf("ID-JAG issuance is not configured on this authorization server")
	}

	// draft section 4.3: audience is REQUIRED (the Resource AS).
	if req.Audience == nil || *req.Audience == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return fmt.Errorf("audience is required for an ID-JAG token exchange")
	}

	// draft section 4.3.3 / section 5: resolve the audience to a trusted
	// Resource Authorization Server; unknown audiences fail closed.
	target, err := s.idjagAudienceResolver.Resolve(ctx, *req.Audience)
	if err != nil || target == nil {
		res.Error = rfcerrors.InvalidTarget().Build()
		return fmt.Errorf("audience '%s' is not a trusted resource authorization server", *req.Audience)
	}

	// Validate the subject token and derive its claim context.
	var subject *SubjectTokenClaims
	switch grant.SubjectTokenType {
	case oidc.TokenExchangeRefreshTokenType:
		subject, err = s.idjagSubjectFromRefreshToken(ctx, client, req, grant.SubjectToken, res)
	case oidc.TokenExchangeIDTokenType:
		subject, err = s.idjagSubjectFromIDToken(res)
	default:
		res.Error = rfcerrors.InvalidRequest().Build()
		return fmt.Errorf("subject_token_type '%s' is not supported for ID-JAG issuance", grant.SubjectTokenType)
	}
	if err != nil {
		return err
	}
	if subject == nil {
		res.Error = rfcerrors.ServerError().Build()
		return fmt.Errorf("subject token resolution returned no claims")
	}

	// draft section 4.3.3: resolve the subject into the target Resource
	// Authorization Server's namespace (pairwise / JIT policy is
	// assembly-defined; never invented here).
	resolution, err := s.idjagSubjectResolver.Resolve(ctx, subject, target)
	if err != nil || resolution == nil || resolution.Subject == "" {
		res.Error = rfcerrors.InvalidGrant().Build()
		return fmt.Errorf("unable to resolve subject for the target resource authorization server: %w", err)
	}

	// A request may narrow but never exceed the subject token's
	// authorization context (identity-chaining section 2.5).
	grantedScope := subject.Scope
	if req.Scope != nil && *req.Scope != "" {
		granted := types.StringArray(strings.Fields(subject.Scope))
		for _, sc := range strings.Fields(*req.Scope) {
			if !granted.Contains(sc) {
				res.Error = rfcerrors.InvalidScope().Build()
				return fmt.Errorf("requested scope '%s' exceeds the subject token authorization", *req.Scope)
			}
		}
		grantedScope = *req.Scope
	}

	// RFC 9396: authorization_details are consent-bound; ID-JAG
	// issuance delegates an existing context. Fail closed rather than
	// minting details without a consent authority.
	if len(req.AuthorizationDetails) > 0 {
		res.Error = rfcerrors.InvalidAuthorizationDetails().Build()
		return fmt.Errorf("authorization_details are not supported for ID-JAG issuance in this profile iteration")
	}

	// draft section 9.8.1.1: a DPoP proof present on the exchange binds
	// the ID-JAG to that key (cnf.jkt).
	var cnfJkt string
	if req.TokenConfirmation != nil && req.TokenConfirmation.Jkt != "" {
		cnfJkt = req.TokenConfirmation.Jkt
	}

	// Assemble the ID-JAG claim set (draft section 3.1). The client_id
	// claim carries the client's identifier at the target Resource
	// Authorization Server (draft sections 3.1, 5): mappings live in the
	// client registration, resolved through the audience resolver's
	// target descriptor.
	// The client MUST be mapped at the target Resource Authorization
	// Server (draft sections 3.1, 5): the IdP vouches for the client
	// identity it mints into the grant, so an unmapped client fails
	// closed before signing.
	if targetClientID(client, target) == "" {
		res.Error = rfcerrors.InvalidGrant().Build()
		return fmt.Errorf("client '%s' has no identifier mapping at resource authorization server %q", client.ClientId, target.Issuer)
	}

	now := timeFunc()
	claims := &tokenv1.IdentityAssertionJWTAuthorizationGrant{
		Iss:      req.Issuer,
		Sub:      resolution.Subject,
		Aud:      target.Issuer,
		ClientId: targetClientID(client, target),
		Jti:      random.String(jtiLength),
		Exp:      uint64(now.Add(idjagLifetime).Unix()), //nolint:gosec // unix time is non-negative
		Iat:      uint64(now.Unix()),                    //nolint:gosec // unix time is non-negative
	}
	if grantedScope != "" {
		claims.Scope = &grantedScope
	}
	if len(req.Resource) > 0 {
		claims.Resource = req.Resource
	}
	if resolution.AuthTime > 0 {
		claims.AuthTime = &resolution.AuthTime
	}
	if resolution.ACR != "" {
		claims.Acr = &resolution.ACR
	}
	if len(resolution.AMR) > 0 {
		claims.Amr = resolution.AMR
	}
	if cnfJkt != "" {
		claims.CnfJkt = &cnfJkt
	}

	// Serialize the ID-JAG.
	raw, err := s.idjagSigner.Serialize(ctx, claims)
	if err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return fmt.Errorf("unable to serialize ID-JAG: %w", err)
	}

	// draft section 4.3.4 response: the ID-JAG rides the access_token
	// parameter with issued_token_type=id-jag; token_type is N_A.
	tokenType := oidc.IDJAGTokenType
	res.IssuedTokenType = &tokenType
	res.AccessToken = &tokenv1.Token{
		TokenType: tokenv1.TokenType_TOKEN_TYPE_UNKNOWN,
		Value:     raw,
		Metadata: &tokenv1.TokenMeta{
			Issuer:    req.Issuer,
			Subject:   claims.Sub,
			ClientId:  claims.ClientId,
			IssuedAt:  claims.Iat,
			ExpiresAt: claims.Exp,
			Scope:     grantedScope,
		},
		Status: tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
	}

	// No error
	return nil
}

// idjagSubjectFromRefreshToken validates a self-issued refresh token as
// the subject token (draft section 4.3.2) and assembles its claim context.
func (s *service) idjagSubjectFromRefreshToken(ctx context.Context, client *clientv1.Client, req *flowv1.TokenRequest, subjectToken string, res *flowv1.TokenResponse) (*SubjectTokenClaims, error) {
	rt, err := s.tokens.GetByValue(ctx, req.Issuer, subjectToken)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			res.Error = rfcerrors.InvalidRequest().Build()
		} else {
			res.Error = rfcerrors.ServerError().Build()
		}
		return nil, fmt.Errorf("unable to retrieve subject_token from storage: %w", err)
	}
	if rt.Status != tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE || rt.TokenType != tokenv1.TokenType_TOKEN_TYPE_REFRESH_TOKEN || rt.Metadata == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return nil, fmt.Errorf("subject_token is not an active refresh token")
	}
	if rt.Metadata.ExpiresAt < uint64(timeFunc().Unix()) { //nolint:gosec // unix time is non-negative
		res.Error = rfcerrors.InvalidRequest().Build()
		return nil, fmt.Errorf("subject_token is expired")
	}
	// draft section 4.3.3: the refresh token is bound to the authenticated
	// client.
	if rt.Metadata.ClientId != client.ClientId {
		res.Error = rfcerrors.InvalidRequest().Build()
		return nil, fmt.Errorf("subject_token is bound to another client")
	}

	claims := &SubjectTokenClaims{
		Subject:  rt.Metadata.Subject,
		ClientID: rt.Metadata.ClientId,
		Scope:    rt.Metadata.Scope,
	}
	if rt.Metadata.AuthTime != nil {
		claims.AuthTime = *rt.Metadata.AuthTime
	}
	if rt.Metadata.Acr != nil {
		claims.ACR = *rt.Metadata.Acr
	}
	return claims, nil
}

// idjagSubjectFromIDToken validates an ID Token as the subject token
// (draft section 4.3.1: signature via trusted issuer JWKS, aud == client).
// OIDC-core ID Token verification machinery is deferred to assemblies in
// this iteration; fail closed until a subject-assertion verifier is
// wired.
func (s *service) idjagSubjectFromIDToken(res *flowv1.TokenResponse) (*SubjectTokenClaims, error) { //nolint:unparam // claims return is deferred to the ID Token subject verifier iteration
	res.Error = rfcerrors.InvalidRequest().Build()
	return nil, fmt.Errorf("id_token subject tokens are not supported by this configuration")
}

// targetClientID resolves the client's identifier at the target Resource
// Authorization Server (draft sections 3.1, 5). An unmapped client fails
// closed: the IdP must not delegate access under an identifier it cannot
// vouch for at the target.
func targetClientID(client *clientv1.Client, target *IDJAGResourceServer) string {
	if client == nil || target == nil || target.ClientIDMapping == nil {
		return ""
	}
	return target.ClientIDMapping[client.ClientId]
}
