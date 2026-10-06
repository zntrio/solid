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

// Package sd hosts the draft-forten-oauth-sd-jwt-access-token-00
// token generators: selectively disclosable access tokens and the
// ID-token generalization, assembled over an injected
// sdtoken.AccessTokenIssuer. It is a separate package because
// sdk/sdtoken imports sdk/token for its role contracts (token.Signer,
// base typs) — the generators sit above both.
package sd

import (
	"context"
	"fmt"

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/sdk/sdtoken"
	"zntr.io/solid/sdk/token"
)

// -----------------------------------------------------------------------------
// draft-forten-oauth-sd-jwt-access-token-00 generators.
//
// These token.Generator implementations mint selectively disclosable
// tokens whose non-protocol claims are disclosable: the token value
// carries digests only, and the disclosures are written to the
// tokenv1.Token spec (t.Disclosures) — the mutation-and-persist
// pattern of the token service (the caller persists the same object it
// passed in). The issuer (JWT per the draft, CWT as the
// format-agnostic analog) is injected by the caller, built with the
// serialization package's constructor of its choice.

// accessTokenSDGenerator mints SD access tokens per the draft-forten
// profile.
type accessTokenSDGenerator struct {
	issuer sdtoken.AccessTokenIssuer
	extra  map[string]any
}

// AccessTokenWithSelectiveDisclosure returns an access token Generator
// minting selectively disclosable access tokens
// (draft-forten-oauth-sd-jwt-access-token-00): the token value is the
// ordinary-form token carrying _sd digests (typ stays at+jwt /
// application/at+cwt); the RFC 9068 protocol claims (iss, sub, aud,
// exp, nbf, iat, jti, client_id, cnf, scope, authorization_details)
// stay in the payload and the caller-supplied disclosableClaims are
// merged in as additional disclosable claims (email, name, ... —
// assembly-sourced user attributes). Disclosures land in
// t.Disclosures and MUST travel in the token response `disclosures`
// parameter, never in the token string; introspection responses MUST
// NOT carry them.
//
// The issuer is injected already configured: construction options
// (WithRequiredConfirmation, WithDecoyDigests, ...) are applied at its
// constructor, not per Generate call.
func AccessTokenWithSelectiveDisclosure(issuer sdtoken.AccessTokenIssuer, disclosableClaims map[string]any) token.Generator {
	return &accessTokenSDGenerator{
		issuer: issuer,
		extra:  disclosableClaims,
	}
}

// Generate implements token.Generator.
func (g *accessTokenSDGenerator) Generate(ctx context.Context, t *tokenv1.Token) (string, error) {
	if t == nil {
		return "", fmt.Errorf("unable to generate claims from nil token")
	}
	if t.TokenId == "" {
		return "", fmt.Errorf("token id must not be blank")
	}
	if t.Metadata == nil {
		return "", fmt.Errorf("token meta must not be nil")
	}

	// Base protocol claims: the RFC 9068 set from the token spec.
	claims := map[string]any{
		"iss":       t.Metadata.Issuer,
		"sub":       t.Metadata.Subject,
		"aud":       t.Metadata.Audience,
		"exp":       t.Metadata.ExpiresAt,
		"iat":       t.Metadata.IssuedAt,
		"jti":       t.TokenId,
		"client_id": t.Metadata.ClientId,
		"scope":     t.Metadata.Scope,
	}
	if t.Metadata.NotBefore > 0 {
		claims["nbf"] = t.Metadata.NotBefore
	}
	if len(t.Metadata.AuthorizationDetails) > 0 {
		claims["authorization_details"] = t.Metadata.AuthorizationDetails
	}
	// RFC 9470 section 6.1: the login authentication event rides the token as
	// protected (non-disclosable) protocol claims.
	if v := t.Metadata.GetAcr(); v != "" {
		claims["acr"] = v
	}
	if v := t.Metadata.GetAuthTime(); v != 0 {
		claims["auth_time"] = v
	}
	if t.Confirmation != nil {
		// Plain-map form with the RFC-mandated member names (same
		// wire shape as token.ConfirmationAsJSON): the sdtoken
		// profile surface is map-typed, and the WithRequiredConfirmation
		// gate reads cnf.jkt.
		cnf := map[string]any{}
		if t.Confirmation.Jkt != "" {
			cnf["jkt"] = t.Confirmation.Jkt
		}
		if t.Confirmation.X5TS256 != "" {
			cnf["x5t#S256"] = t.Confirmation.X5TS256
		}
		claims["cnf"] = cnf
	}

	// Disclosable claims: assembly-supplied user attributes only. The
	// draft-forten profile rules (ValidateDisclosableClaims) reject
	// any protected claim here — hard errors, not silent plaintext.
	for name, value := range g.extra {
		claims[name] = sdtoken.Disclosable{Value: value}
	}

	value, disclosures, err := g.issuer.Issue(ctx, claims)
	if err != nil {
		return "", fmt.Errorf("unable to issue sd access token: %w", err)
	}

	// The disclosures persist on the token spec: the token response
	// carries them (draft-forten section 4), introspection must not.
	t.Disclosures = disclosures
	return value, nil
}

// idTokenSDGenerator mints SD ID tokens per the ID-token profile.
type idTokenSDGenerator struct {
	issuer   sdtoken.AccessTokenIssuer
	idClaims map[string]any // extra protected ID-token claims (nonce, auth_time, azp, ...)
	extra    map[string]any // disclosable user claims
}

// IDTokenWithSelectiveDisclosure returns a Generator minting
// selectively disclosable ID tokens: the ID-token generalization of
// the draft-forten profile at the SDK level (no standard mints SD ID
// tokens; this surface exists for assemblies — no grant handler mints
// ID tokens in this repo). iss, sub, aud, exp and iat derive from the
// tokenv1.Token spec and are protected (never disclosable); idClaims
// carries additional protected OIDC claims (nonce, auth_time, azp,
// ...); disclosableClaims carries the user claims (email, name, ...)
// that the assembly sources from its identity records. The disclosures
// land on the token spec (t.Disclosures); no grant handler mints ID
// tokens in this repo yet, so no token response carries them today.
//
// The issuer is injected already configured: construction options are
// applied at its constructor, not per Generate call.
func IDTokenWithSelectiveDisclosure(issuer sdtoken.AccessTokenIssuer, idClaims, disclosableClaims map[string]any) token.Generator {
	return &idTokenSDGenerator{
		issuer:   issuer,
		idClaims: idClaims,
		extra:    disclosableClaims,
	}
}

// Generate implements token.Generator.
func (g *idTokenSDGenerator) Generate(ctx context.Context, t *tokenv1.Token) (string, error) {
	if t == nil {
		return "", fmt.Errorf("unable to generate claims from nil token")
	}
	if t.TokenId == "" {
		return "", fmt.Errorf("token id must not be blank")
	}
	if t.Metadata == nil {
		return "", fmt.Errorf("token meta must not be nil")
	}

	// OIDC Core section 2 claims: the validation-relevant set from the
	// token spec plus the assembly-supplied protected claims (nonce,
	// auth_time, azp, ...).
	claims := map[string]any{
		"iss": t.Metadata.Issuer,
		"sub": t.Metadata.Subject,
		"aud": t.Metadata.Audience,
		"exp": t.Metadata.ExpiresAt,
		"iat": t.Metadata.IssuedAt,
		"jti": t.TokenId,
	}
	for name, value := range g.idClaims {
		claims[name] = value
	}
	for name, value := range g.extra {
		claims[name] = sdtoken.Disclosable{Value: value}
	}

	value, disclosures, err := g.issuer.Issue(ctx, claims)
	if err != nil {
		return "", fmt.Errorf("unable to issue sd id token: %w", err)
	}
	t.Disclosures = disclosures
	return value, nil
}
