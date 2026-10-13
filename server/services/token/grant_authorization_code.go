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
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	sessionv1 "zntr.io/solid/api/oidc/session/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	random "zntr.io/solid/sdk/random"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/types"
	"zntr.io/solid/server/services"
	"zntr.io/solid/server/storage"
)

const (
	desiredAuthorizationCodeMaxValueLength = 1024
	desiredCodeVerifiedMinValueLength      = 43
	desiredCodeVerifiedMaxValueLength      = 128
)

//nolint:gocyclo,funlen // linear RFC-ordered validation chain; each guard is a protocol requirement
func (s *service) authorizationCode(ctx context.Context, client *clientv1.Client, req *flowv1.TokenRequest) (*flowv1.TokenResponse, error) {
	res := &flowv1.TokenResponse{}
	grant := req.GetAuthorizationCode()

	// Shared grant validation: nullity, issuer syntax, grant capability.
	publicErr, err := validateGrantPreamble(client, req, oidc.GrantTypeAuthorizationCode)
	if err != nil {
		res.Error = publicErr
		return res, err
	}
	if grant == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to process with nil grant")
	}

	// Sender-constrained token policy (RFC 10027 section 6.1.12 for DPoP,
	// RFC 8705 section 3 for certificate bindings): a client requiring
	// bound access tokens must present its confirmation with every token
	// request. Session-level dpop_jkt bindings are verified below.
	if errBind := enforceSenderBinding(res, client, req); errBind != nil {
		return res, errBind
	}

	// Validate request (draft-ietf-oauth-v2-1-16 §4.1.3): the token request
	// REQUIRES code and code_verifier; redirect_uri is no longer a parameter
	// of the authorization code grant in OAuth 2.1. When a client does send
	// it (OAuth 2.0 compatibility, §10.2), it MUST exactly match the
	// authorization-time value and the client registration.
	if grant.Code == "" || grant.CodeVerifier == "" {
		res.Error = rfcerrors.InvalidGrant().Build()
		return res, fmt.Errorf("invalid authorization request: code and code_verifier are mandatory")
	}

	// Validate code length
	if utf8.RuneCountInString(grant.Code) > desiredAuthorizationCodeMaxValueLength {
		res.Error = rfcerrors.InvalidGrant().Build()
		return res, fmt.Errorf("invalid authorization request: code is too long")
	}

	// Code verifier bounds and charset (RFC 7636 section 4.1: 43-128
	// unreserved characters) are enforced by the protovalidate
	// annotations on GrantAuthorizationCode.code_verifier.

	// Retrieve authorization request from code
	// RFC 9700 section 4.5: single-use codes are enforced with an atomic
	// consume; a concurrent double redeem gets storage.ErrNotFound.
	ar, err := s.authorizationCodeSessions.DeleteAndGet(ctx, req.Issuer, grant.Code)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			res.Error = rfcerrors.ServerError().Build()
		} else {
			res.Error = rfcerrors.InvalidGrant().Build()
		}
		return res, fmt.Errorf("unable to retrieve authorization request from code '%s': %w", grant.Code, err)
	}
	// Check if not nil
	if ar.Request == nil {
		res.Error = rfcerrors.InvalidGrant().Build()
		return res, fmt.Errorf("retrieve authorization request is invalid '%s'", grant.Code)
	}

	// Enforce the session state machine invariant: the atomic consume in
	// storage stamps the session CONSUMED; a session surfacing with any other
	// status (UNSPECIFIED, ACTIVE) indicates storage corruption or a
	// non-conforming implementation and is rejected by construction.
	if ar.Status != sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED {
		res.Error = rfcerrors.InvalidGrant().State(ar.Request.State).Build()
		return res, fmt.Errorf("invalid authorization request: consumed session status is invalid '%s'", ar.Status)
	}

	// Ensure the authorization code was issued to the client that is redeeming
	// it, as required by RFC 6749 section 4.1.3.
	if ar.Request.ClientId != client.ClientId {
		res.Error = rfcerrors.InvalidGrant().State(ar.Request.State).Build()
		return res, fmt.Errorf("invalid authorization request: code was not issued to client '%s'", client.ClientId)
	}

	// RFC 9449 section 10: when the code session is bound to a DPoP key
	// (confirmation set at authorization time — from the signed request
	// object's dpop_jkt parameter or the PAR-endpoint proof), the token
	// request MUST prove possession of that same key. The grant's dpop_jkt
	// carries the thumbprint verified from the DPoP proof at the token
	// endpoint; anything else is a proof-key swap.
	if ar.Confirmation != nil && ar.Confirmation.Jkt != "" {
		if grant.DpopJkt == nil || *grant.DpopJkt == "" {
			res.Error = rfcerrors.InvalidGrant().State(ar.Request.State).Build()
			return res, fmt.Errorf("authorization code is bound to a DPoP key but no proof confirmation was presented")
		}
		if !types.SecureCompareString(ar.Confirmation.Jkt, *grant.DpopJkt) {
			res.Error = rfcerrors.InvalidGrant().State(ar.Request.State).Build()
			return res, fmt.Errorf("DPoP key does not match the authorization code binding")
		}
	}

	// RFC 9449 section 10, token-endpoint binding: when the grant itself
	// carries a dpop_jkt (the proof thumbprint verified at the token
	// endpoint), a confirmation presented by the token request MUST match
	// that binding; a mismatch is a proof-key swap against the grant.
	if grant.DpopJkt != nil && *grant.DpopJkt != "" {
		presentedJkt := ""
		if req.TokenConfirmation != nil {
			presentedJkt = req.TokenConfirmation.Jkt
		}
		if presentedJkt == "" {
			res.Error = rfcerrors.InvalidGrant().State(ar.Request.State).Build()
			return res, fmt.Errorf("authorization grant is bound to a DPoP key but no proof confirmation was presented")
		}
		if !types.SecureCompareString(presentedJkt, *grant.DpopJkt) {
			res.Error = rfcerrors.InvalidGrant().State(ar.Request.State).Build()
			return res, fmt.Errorf("DPoP key does not match the authorization grant binding")
		}
	}

	// RFC 9700 section 4.2.4: on double redemption the code session is already
	// burned (storage.ErrNotFound above); revocation of tokens minted from the
	// grant is enforced at refresh-token family level (grant_refresh_token.go),
	// where the replayed token carries its grant identifier.

	// Validate redirectUri: only when the token request carries the
	// parameter (OAuth 2.0 compatibility, draft-ietf-oauth-v2-1-16 §10.2).
	if grant.RedirectUri != "" {
		if ar.Request.RedirectUri != grant.RedirectUri {
			res.Error = rfcerrors.InvalidGrant().State(ar.Request.State).Build()
			return res, fmt.Errorf("invalid authorization request: redirect_uri from authorization request '%s' and redemption '%s' must be identic", ar.Request.RedirectUri, grant.RedirectUri)
		}
		if !services.RedirectURIMatchesRegistered(client.RedirectUris, grant.RedirectUri) {
			res.Error = rfcerrors.InvalidGrant().State(ar.Request.State).Build()
			return res, fmt.Errorf("invalid authorization request: request_uri from request '%s' and client '%v' must be validated", grant.RedirectUri, client.RedirectUris)
		}
	}

	// Check PKCE verifier
	// https://www.rfc-editor.org/rfc/rfc7636.txt
	switch ar.Request.CodeChallengeMethod {
	case oidc.CodeChallengeMethodSha256:
		h := sha256.Sum256([]byte(grant.CodeVerifier))
		computedVerifier := base64.RawURLEncoding.EncodeToString(h[:])
		if !types.SecureCompareString(computedVerifier, ar.Request.CodeChallenge) {
			res.Error = rfcerrors.InvalidGrant().State(ar.Request.State).Build()
			return res, fmt.Errorf("unable to validate PKCE code_verifier and code_challenge for client '%s'", client.ClientId)
		}
	default:
		res.Error = rfcerrors.InvalidGrant().State(ar.Request.State).Build()
		return res, fmt.Errorf("invalid code_challenge_method in request `%s`", ar.Request.CodeChallengeMethod)
	}

	// RFC 9396 section 6: when the token request carries
	// authorization_details, every requested entry MUST match (proto
	// equality) one entry consented at authorization time; the client may
	// only narrow the granted set. When the request omits them, the AS
	// grants the full consented set (section 7: the AS determines the
	// resulting authorization_details at its discretion).
	grantedDetails := req.AuthorizationDetails
	if len(grantedDetails) == 0 {
		grantedDetails = ar.Request.AuthorizationDetails
	} else if err := validateAuthorizationDetailsSubset(req.AuthorizationDetails, ar.Request.AuthorizationDetails); err != nil {
		res.Error = rfcerrors.InvalidAuthorizationDetails().Build()
		return res, fmt.Errorf("invalid authorization request: %w", err)
	}

	// RFC 8707 section 3 (solid stronger posture): multiple resource
	// parameters are rejected with invalid_target — the RFC only
	// "encourages" a single resource, but a multi-audience bearer token
	// is valid at every listed resource and each can access all others;
	// no such trust expansion is offered here.
	if len(ar.Request.Resource) > 1 {
		res.Error = rfcerrors.InvalidTarget().State(ar.Request.State).Build()
		return res, fmt.Errorf("multiple resource indicators are not supported (RFC 8707 section 3)")
	}
	for _, resourceURI := range ar.Request.Resource {
		if _, errRes := s.resources.GetByURI(ctx, resourceURI); errRes != nil {
			if errors.Is(errRes, storage.ErrNotFound) {
				res.Error = rfcerrors.InvalidTarget().State(ar.Request.State).Build()
				return res, fmt.Errorf("unknown resource indicator '%s'", resourceURI)
			}
			res.Error = rfcerrors.ServerError().State(ar.Request.State).Build()
			return res, fmt.Errorf("unable to validate resource indicator '%s': %w", resourceURI, errRes)
		}
	}

	// RFC 8707 section 2: the audience parameter is attacker-influencable at
	// authorization time; before it reaches the minted token it MUST be
	// validated against the resource registry exactly like a resource
	// indicator — an unknown audience is an invalid_target, never a
	// verbatim copy of the request parameter.
	if len(ar.Request.Resource) == 0 && ar.Request.Audience != "" {
		if _, errAud := s.resources.GetByURI(ctx, ar.Request.Audience); errAud != nil {
			if errors.Is(errAud, storage.ErrNotFound) {
				res.Error = rfcerrors.InvalidTarget().State(ar.Request.State).Build()
				return res, fmt.Errorf("unknown audience '%s'", ar.Request.Audience)
			}
			res.Error = rfcerrors.ServerError().State(ar.Request.State).Build()
			return res, fmt.Errorf("unable to validate audience '%s': %w", ar.Request.Audience, errAud)
		}
	}

	// RFC 8707 section 2 ("The authorization server SHOULD
	// audience-restrict issued access tokens to the resource(s) indicated
	// by the resource parameter"): mintAuthorizationCodeTokens resolves the
	// effective audience — the validated resource indicator when one was
	// requested, the validated audience parameter otherwise.

	// Validate scopes
	scopes := types.StringArray(strings.Fields(ar.Request.Scope))

	// Generate OpenID tokens (AT / RT / IDT)
	if !scopes.Contains(oidc.ScopeOpenID) {
		// No OpenID scope: no token to mint.
		return res, nil
	}

	// Mint the access token for the granted scopes.
	if err := s.mintAuthorizationCodeTokens(ctx, client, req, ar, scopes, grantedDetails, res); err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, err
	}

	// No error
	return res, nil
}

// mintAuthorizationCodeTokens generates the access token — and, when the
// offline_access scope was granted with a consent prompt, the refresh
// token — for a redeemed authorization code session.
func (s *service) mintAuthorizationCodeTokens(ctx context.Context, client *clientv1.Client, req *flowv1.TokenRequest, ar *sessionv1.AuthorizationCodeSession, scopes types.StringArray, grantedDetails []*tokenv1.AuthorizationDetail, res *flowv1.TokenResponse) error {
	// RFC 9470 section 6: capture the login authentication event (nil-safe
	// when the session carries none).
	var loginACR *string
	var loginAuthTime *uint64
	if ar.AuthEvent != nil {
		loginACR, loginAuthTime = ar.AuthEvent.Acr, ar.AuthEvent.AuthTime
	}
	// RFC 8707 section 2: the effective audience resolved and validated
	// during Grant — the resource indicator when one was requested, the
	// validated audience otherwise — is what gets minted; never a
	// verbatim copy of the request parameter.
	audience := effectiveAudienceOf(ar)
	// Generate access token
	at, err := s.generateAccessToken(ctx, client, &tokenv1.TokenMeta{
		Issuer:               req.Issuer,
		Subject:              ar.Subject,
		Audience:             audience,
		Scope:                ar.Request.Scope,
		GrantId:              ar.GrantId,
		AuthorizationDetails: grantedDetails,
		// RFC 9470 section 6: propagate the login authentication event captured
		// at code issuance.
		Acr:      loginACR,
		AuthTime: loginAuthTime,
	}, req.TokenConfirmation)
	if err != nil {
		return fmt.Errorf("unable to generate access token: %w", err)
	}

	// RFC 9700 section 4.14.2 / draft-ietf-oauth-v2-1-16 section 4.3.1:
	// refresh tokens are only issued to clients registered for the
	// refresh_token grant; offline_access consent alone does not entitle
	// an unregistered client to long-lived credentials.
	if scopes.Contains(oidc.ScopeOfflineAccess) && types.StringArray(client.GrantTypes).Contains(oidc.GrantTypeRefreshToken) {
		// Generate refresh token
		rt, err := s.generateRefreshToken(ctx, client, &tokenv1.TokenMeta{
			Issuer:               req.Issuer,
			Subject:              ar.Subject,
			Audience:             audience,
			Scope:                ar.Request.Scope,
			GrantId:              ar.GrantId,
			AuthorizationDetails: grantedDetails,
			// RFC 9470 section 6: propagate the login authentication event captured
			// at code issuance.
			Acr:      loginACR,
			AuthTime: loginAuthTime,
		}, at.Confirmation)
		if err != nil {
			return fmt.Errorf("unable to generate refresh token: %w", err)
		}

		// Assign response
		res.RefreshToken = rt
	}

	// D-12.1: opt-in id_token from the code flow — selectively
	// disclosable (digests only in the token; values in the response
	// disclosures). nil generator = default posture, no id_token.
	// The spec is deliberately NOT persisted in token storage: it is a
	// one-shot authentication assertion, nothing server-side consumes
	// it, and keeping it out of the store guarantees introspection can
	// never surface its disclosures.
	if s.idTokenGen != nil {
		now := timeFunc()
		idt := &tokenv1.Token{
			TokenType: tokenv1.TokenType_TOKEN_TYPE_ID_TOKEN,
			TokenId:   random.String(jtiLength),
			Metadata: &tokenv1.TokenMeta{
				Issuer:    req.Issuer,
				Subject:   ar.Subject, // already pairwise-encoded at authorization time
				ClientId:  client.ClientId,
				IssuedAt:  uint64(now.Unix()),                    //nolint:gosec // unix time is non-negative
				NotBefore: uint64(now.Unix() + 1),                //nolint:gosec // unix time is non-negative
				ExpiresAt: uint64(now.Add(1 * time.Hour).Unix()), //nolint:gosec // unix time is non-negative
				Scope:     ar.Request.Scope,
				// OIDC Core section 2: aud of an id_token is the client_id.
				Audience: client.ClientId,
				GrantId:  ar.GrantId,
				// RFC 9470 section 6: propagate the login authentication event
				// captured at code issuance.
				Acr:      loginACR,
				AuthTime: loginAuthTime,
				Nonce:    &ar.Request.Nonce,
			},
			Status: tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
		}
		v, err := s.idTokenGen.Generate(ctx, idt)
		if err != nil {
			return fmt.Errorf("unable to generate the id token: %w", err)
		}
		if v == "" {
			return fmt.Errorf("idTokenGenerator generated an empty value")
		}
		idt.Value = v
		res.IdToken = idt
	}

	res.AccessToken = at
	res.AuthorizationDetails = grantedDetails

	// No error
	return nil
}

// effectiveAudienceOf resolves the RFC 8707 effective audience of a code
// session: the validated resource indicator when the authorization request
// carried one, otherwise the audience parameter (validated against the
// resource registry by Grant). An empty string is preserved — no audience
// requested means aud stays omitted from the minted tokens.
func effectiveAudienceOf(ar *sessionv1.AuthorizationCodeSession) string {
	if len(ar.Request.Resource) > 0 {
		return ar.Request.Resource[0]
	}
	return ar.Request.Audience
}
