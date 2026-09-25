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

// SPIFFEWIT authenticates clients with a WIT-SVID (a WIMSE Workload Identity
// Token carrying a SPIFFE ID in its sub claim) presented via the
// OAuth-Client-Attestation / OAuth-Client-Attestation-PoP headers
// (draft-ietf-oauth-spiffe-client-auth-02, section 3.3). The WIT signature
// is verified with the wit-svid keys of the issuing trust domain's bundle;
// the PoP JWT proves possession of the key bound in the WIT cnf claim.
// The expectedAudience value MUST be the authorization server's own token
// endpoint identity.
func SPIFFEWIT(clients storage.ClientReader, bundles spiffe.BundleSource, proofs storage.DPoP, expectedAudience string, supportedAlgorithms []string) AuthenticationProcessor {
	return &spiffeWITAuthentication{
		clients:             clients,
		bundles:             bundles,
		proofs:              proofs,
		expectedAudience:    expectedAudience,
		supportedAlgorithms: supportedAlgorithms,
	}
}

// spiffeWITClaims models the WIT-SVID claims validated during
// authentication: iss identifies the issuing workload (a SPIFFE ID whose
// trust domain keys sign the token), sub carries the client SPIFFE ID, and
// cnf.jwk binds the client's proof-of-possession key.
type spiffeWITClaims struct {
	Issuer       string                               `json:"iss"`
	Subject      string                               `json:"sub"`
	Expires      uint64                               `json:"exp"`
	IssuedAt     uint64                               `json:"iat"`
	NotBefore    uint64                               `json:"nbf"`
	Confirmation *clientAttestationConfirmationClaims `json:"cnf,omitempty"`
}

type spiffeWITAuthentication struct {
	clients             storage.ClientReader
	bundles             spiffe.BundleSource
	proofs              storage.DPoP
	expectedAudience    string
	supportedAlgorithms []string
}

//nolint:funlen,gocyclo // to refactor
func (p *spiffeWITAuthentication) Authenticate(ctx context.Context, req *clientv1.AuthenticateRequest) (*clientv1.AuthenticateResponse, error) {
	res := &clientv1.AuthenticateResponse{}

	// Validate required fields for this authentication method
	if req == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process nil request")
	}
	if req.ClientAttestation == nil || *req.ClientAttestation == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("client_attestation must be defined")
	}
	if req.ClientAttestationPop == nil || *req.ClientAttestationPop == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("client_attestation_pop must be defined")
	}

	// Decode WIT-SVID without validation first
	witToken, witParts, err := gojwt.NewParser().ParseUnverified(*req.ClientAttestation, gojwt.MapClaims{})
	if err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("wit-svid is syntaxically invalid: %w", err)
	}

	// Enforce the algorithm allowlist before processing claims.
	if !containsString(p.supportedAlgorithms, witToken.Method.Alg()) {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("wit-svid algorithm %q is not supported", witToken.Method.Alg())
	}

	// The typ header MUST be wit+jwt (draft section 3.3.1, first bullet;
	// oauth-client-attestation+jwt is also accepted per that bullet).
	typ, _ := witToken.Header["typ"].(string)
	if typ != "wit+jwt" && typ != "oauth-client-attestation+jwt" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("wit-svid typ header must be wit+jwt")
	}

	// Retrieve WIT claims
	var claims spiffeWITClaims
	payload, err := base64.RawURLEncoding.DecodeString(witParts[1])
	if err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to decode wit-svid claims: %w", err)
	}
	if err = json.Unmarshal(payload, &claims); err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to decode wit-svid claims: %w", err)
	}

	// Required claims: iss (issuing workload), sub (client SPIFFE ID), exp,
	// cnf.jwk (key binding).
	if claims.Issuer == "" || claims.Subject == "" || claims.Expires == 0 || claims.Confirmation == nil || len(claims.Confirmation.JWK) == 0 {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("iss, sub, exp, cnf are mandatory and not empty")
	}

	// Temporal validation: WITs are short-lived workload credentials.
	if claims.Expires < uint64(time.Now().Unix()) { //nolint:gosec // unix time is non-negative
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("expired token")
	}
	if claims.IssuedAt > 0 && claims.Expires > claims.IssuedAt+uint64(maxAssertionLifetime.Seconds()) {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("exp is too far in the future, wit lifetime must not exceed %s", maxAssertionLifetime)
	}
	if claims.NotBefore > uint64(time.Now().Unix()) { //nolint:gosec // unix time is non-negative
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("not useable token")
	}

	// WIT signature (draft section 3.3.1, bullet 3): verified with the
	// wit-svid signing keys of the issuing workload's trust domain.
	trustDomain, err := spiffe.TrustDomainFromSPIFFEID(claims.Issuer)
	if err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("iss is not a valid spiffe id: %w", err)
	}
	bundle, err := p.bundles.Get(ctx, trustDomain)
	if err != nil {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("no bundle for trust domain %q", trustDomain)
	}
	witKeys, err := spiffe.KeysByUse(bundle, spiffe.KeyUseWITSVID)
	if err != nil {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("unable to filter bundle keys: %w", err)
	}
	if err = jwk.ValidateSignature(witKeys, *req.ClientAttestation, p.supportedAlgorithms); err != nil {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("wit-svid signature is invalid: %w", err)
	}

	// Materialize the PoP key bound in the WIT cnf claim.
	cnfSet, err := jwk.Parse(claims.Confirmation.JWK)
	if err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("wit-svid cnf.jwk is invalid: %w", err)
	}
	cnfKey, ok := cnfSet.Key(0)
	if !ok {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("wit-svid cnf.jwk is empty")
	}
	popPublicKey, err := materializeVerificationKey(cnfKey)
	if err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to materialize bound public key: %w", err)
	}

	// Validate the PoP JWT (draft section 3.3.1, bullet 4): parse without
	// validation first.
	popToken, popParts, err := gojwt.NewParser().ParseUnverified(*req.ClientAttestationPop, gojwt.MapClaims{})
	if err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("client attestation pop is syntaxically invalid: %w", err)
	}
	if !containsString(p.supportedAlgorithms, popToken.Method.Alg()) {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("pop algorithm %q is not supported", popToken.Method.Alg())
	}

	// Verify the PoP signature with the cnf-bound key.
	if err = popToken.Method.Verify(popParts[0]+"."+popParts[1], popToken.Signature, popPublicKey); err != nil {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client attestation pop is invalid: %w", err)
	}

	// Retrieve PoP claims
	var popClaims clientAttestationPOPClaims
	popPayload, err := base64.RawURLEncoding.DecodeString(popParts[1])
	if err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to decode pop claims: %w", err)
	}
	if err = json.Unmarshal(popPayload, &popClaims); err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to decode pop claims: %w", err)
	}
	if popClaims.Issuer == "" || popClaims.Audience == "" || popClaims.Expires == 0 || popClaims.JTI == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("iss, aud, exp, jti are mandatory and not empty")
	}

	// Key binding: the PoP MUST be issued by the attested client (WIT sub).
	if popClaims.Issuer != claims.Subject {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("pop issuer does not match wit subject")
	}

	// PoP audience and temporal validation.
	if popClaims.Audience != p.expectedAudience && (req.GetEndpoint() == "" || popClaims.Audience != req.GetEndpoint()) {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("pop aud %q does not match issuer identifier %q nor receiving endpoint %q", popClaims.Audience, p.expectedAudience, req.GetEndpoint())
	}
	if popClaims.Expires < uint64(time.Now().Unix()) { //nolint:gosec // unix time is non-negative
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("expired pop")
	}
	if popClaims.Expires > popClaims.IssuedAt+uint64(maxAssertionLifetime.Seconds()) {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("exp is too far in the future, pop lifetime must not exceed %s", maxAssertionLifetime)
	}

	// Client association (draft section 3.3.1, bullet 5): resolve the
	// client by the WIT sub SPIFFE ID first, then by the request client_id.
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

	// Enforce the SPIFFE ID binding (draft section 5.1), fail closed.
	if client.SpiffeId == "" || !spiffe.MatchSPIFFEID(client.SpiffeId, claims.Subject) {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client spiffe_id %q does not match wit subject %q", client.SpiffeId, claims.Subject)
	}

	// Defensive: the client must be registered for the spiffe_wit method.
	if client.TokenEndpointAuthMethod != oidc.AuthMethodSPIFFEWIT {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client is not registered for %s", oidc.AuthMethodSPIFFEWIT)
	}

	// Prevent PoP replay: the jti must be single-use. Burn it only after
	// full validation of the proof.
	jtiHash := blake2b.Sum256([]byte("spiffe-wit:" + claims.Subject + ":" + popClaims.JTI))
	jtiKey := base64.RawURLEncoding.EncodeToString(jtiHash[:])
	if exists, errExists := p.proofs.Exists(ctx, jtiKey); errExists != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to verify pop uniqueness: %w", errExists)
	} else if exists {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("pop jti has already been used")
	}
	if err := p.proofs.Register(ctx, jtiKey); err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to register pop jti: %w", err)
	}

	// Assign client to result
	res.Client = client

	// No error
	return res, nil
}
