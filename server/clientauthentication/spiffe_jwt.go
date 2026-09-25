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

package clientauthentication

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	blake2b "golang.org/x/crypto/blake2b"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/spiffe"
	"zntr.io/solid/server/storage"
)

// SPIFFEJWT authenticates clients with a JWT-SVID presented as a
// client_assertion of type urn:ietf:params:oauth:client-assertion-type:jwt-spiffe
// (draft-ietf-oauth-spiffe-client-auth-02, section 3.1). The signing keys of
// the SVID's trust domain come exclusively from the BundleSource — never from
// issuer-claim discovery (draft section 8.1) — and the expectedAudience value
// MUST be the authorization server's own token endpoint identity: the aud
// claim MUST contain it as its sole value.
func SPIFFEJWT(clients storage.ClientReader, bundles spiffe.BundleSource, proofs storage.DPoP, expectedAudience string, supportedAlgorithms []string) AuthenticationProcessor {
	return &spiffeJWTAuthentication{
		clients:             clients,
		bundles:             bundles,
		proofs:              proofs,
		expectedAudience:    expectedAudience,
		supportedAlgorithms: supportedAlgorithms,
	}
}

// spiffeJWTClaims models the JWT-SVID claims validated during
// authentication: sub carries the SPIFFE ID of the presenting workload.
type spiffeJWTClaims struct {
	Subject  string   `json:"sub"`
	Audience audClaim `json:"aud"`
	Expires  uint64   `json:"exp"`
	IssuedAt uint64   `json:"iat"`
	JTI      string   `json:"jti"`
}

type spiffeJWTAuthentication struct {
	clients             storage.ClientReader
	bundles             spiffe.BundleSource
	proofs              storage.DPoP
	expectedAudience    string
	supportedAlgorithms []string
}

//nolint:funlen,gocyclo // to refactor
func (p *spiffeJWTAuthentication) Authenticate(ctx context.Context, req *clientv1.AuthenticateRequest) (*clientv1.AuthenticateResponse, error) {
	res := &clientv1.AuthenticateResponse{}

	// Validate required fields for this authentication method
	if req == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process nil request")
	}
	if req.ClientAssertionType == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("client_assertion_type must be defined")
	}
	if *req.ClientAssertionType != oidc.AssertionTypeJWTSPIFFE {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("client_assertion_type must equals '%s', got '%s'", oidc.AssertionTypeJWTSPIFFE, *req.ClientAssertionType)
	}
	if req.ClientAssertion == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("client_assertion must be defined")
	}
	if *req.ClientAssertion == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("client_assertion must not be empty")
	}

	// Decode assertion without validation first
	t, parts, err := gojwt.NewParser().ParseUnverified(*req.ClientAssertion, gojwt.MapClaims{})
	if err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("jwt-svid is syntaxically invalid: %w", err)
	}

	// Enforce the algorithm allowlist before processing claims (draft
	// section 8.1: no alg confusion, no issuer-derived key discovery).
	if !containsString(p.supportedAlgorithms, t.Method.Alg()) {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("jwt-svid algorithm %q is not supported", t.Method.Alg())
	}

	// Retrieve payload claims
	var claims spiffeJWTClaims
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to decode payload claims: %w", err)
	}
	if err = json.Unmarshal(payload, &claims); err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to decode payload claims: %w", err)
	}

	// Required claims (draft section 3.1, rule 1): sub (the SPIFFE ID), aud,
	// exp are mandatory; jti is defensively promoted for replay protection.
	if claims.Subject == "" || len(claims.Audience) == 0 || claims.JTI == "" || claims.Expires == 0 {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("sub, aud, jti, exp are mandatory and not empty")
	}

	// Temporal validation.
	if claims.IssuedAt > uint64(time.Now().Add(5*time.Minute).Unix()) { //nolint:gosec // unix time is non-negative
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("iat is in the future")
	}
	if claims.Expires > claims.IssuedAt+uint64(maxAssertionLifetime.Seconds()) {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("exp is too far in the future, svid lifetime must not exceed %s", maxAssertionLifetime)
	}
	if claims.Expires < uint64(time.Now().Unix()) { //nolint:gosec // unix time is non-negative
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("expired token")
	}

	// Audience (draft section 3.1, rule 3): the aud claim MUST contain only
	// the authorization server issuer identifier as its sole value — or,
	// following the draft-ietf-oauth-security-topics-update-03 section
	// 2.1.2.2 posture of the sibling authenticators, the exact receiving
	// endpoint carried by the request.
	if len(claims.Audience) != 1 {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("aud must contain exactly one value")
	}
	receivingEndpoint := req.GetEndpoint()
	if claims.Audience[0] != p.expectedAudience && (receivingEndpoint == "" || claims.Audience[0] != receivingEndpoint) {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("aud %q does not match issuer identifier %q nor receiving endpoint %q", claims.Audience[0], p.expectedAudience, receivingEndpoint)
	}

	// Trust domain resolution (draft section 3.1, rule 4): the SVID's sub
	// SPIFFE ID identifies the trust domain whose bundle validates it.
	trustDomain, err := spiffe.TrustDomainFromSPIFFEID(claims.Subject)
	if err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("sub is not a valid spiffe id: %w", err)
	}
	bundle, err := p.bundles.Get(ctx, trustDomain)
	if err != nil {
		// An unknown/unreachable trust domain is an untrusted client, not a
		// server error.
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("no bundle for trust domain %q", trustDomain)
	}

	// Restrict the candidate keys to the JWT-SVID signing keys of the bundle.
	jwtSVIDKeys, err := spiffe.KeysByUse(bundle, spiffe.KeyUseJWTSVID)
	if err != nil {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("unable to filter bundle keys: %w", err)
	}

	// Signature validation (draft section 3.1, rule 4).
	if err = jwk.ValidateSignature(jwtSVIDKeys, *req.ClientAssertion, p.supportedAlgorithms); err != nil {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("jwt-svid signature is invalid: %w", err)
	}

	// Client association (draft section 3.1, rule 5): resolve the client by
	// the SPIFFE ID first, then by the request client_id.
	client, err := p.clients.Get(ctx, claims.Subject)
	if err != nil {
		if req.ClientId != nil && *req.ClientId != "" {
			client, err = p.clients.Get(ctx, *req.ClientId)
		}
		if err != nil {
			if !errors.Is(err, storage.ErrNotFound) {
				res.Error = rfcerrors.ServerError().Build()
				return res, fmt.Errorf("error during client retrieval: %w", err)
			}
			res.Error = rfcerrors.InvalidClient().Build()
			return res, fmt.Errorf("client not found")
		}
	}

	// Enforce the SPIFFE ID binding (draft section 5.1): a client
	// authenticating via SPIFFE MUST declare its spiffe_id — fail closed,
	// no match by convention. Wildcard patterns follow the segment rules of
	// section 5.1.
	if client.SpiffeId == "" || !spiffe.MatchSPIFFEID(client.SpiffeId, claims.Subject) {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client spiffe_id %q does not match svid subject %q", client.SpiffeId, claims.Subject)
	}

	// Prevent assertion replay: the jti must be single-use. Burn it only
	// after the signature has been fully validated (RFC 7523 section 3).
	// Key-prefixed hash namespaces distinct clients.
	jtiHash := blake2b.Sum256([]byte("jwt-spiffe:" + claims.Subject + ":" + claims.JTI))
	jtiKey := base64.RawURLEncoding.EncodeToString(jtiHash[:])
	if exists, errExists := p.proofs.Exists(ctx, jtiKey); errExists != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to verify svid uniqueness: %w", errExists)
	} else if exists {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("svid jti has already been used")
	}
	if err := p.proofs.Register(ctx, jtiKey); err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to register svid jti: %w", err)
	}

	// Assign client to result
	res.Client = client

	// No error
	return res, nil
}
