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
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	blake2b "golang.org/x/crypto/blake2b"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/types"
	"zntr.io/solid/server/storage"
)

var (
	// errClientAttestationSyntax marks JWT/base64/JSON decode failures,
	// reported as invalid_request.
	errClientAttestationSyntax = errors.New("client attestation is syntactically invalid")
	// errClientAttestationNotFresh marks an expired Client Attestation JWT,
	// the sole condition reported as use_fresh_attestation
	// (draft-ietf-oauth-attestation-based-client-auth-11, section 7.4).
	errClientAttestationNotFresh = errors.New("client attestation is not fresh")
)

// ClientAttestation authentication method
// (draft-ietf-oauth-attestation-based-client-auth-11): the Client Attestation
// JWT rides the OAuth-Client-Attestation header and the Client Attestation
// PoP JWT rides the OAuth-Client-Attestation-PoP header; the mechanism does
// NOT use RFC 7521 assertion transport. The issuer value MUST be the
// authorization server's issuer identifier.
//
// Deliberate profile deviation: per draft-ietf-oauth-security-topics-update-03
// section 2.1.2, the PoP aud claim is accepted when it equals the issuer
// identifier (section 2.1.2.1) or the exact endpoint that received the
// attestation PoP (carried by the AuthenticateRequest endpoint field,
// section 2.1.2.2). This is a superset of draft section 7.2, rule 7.
func ClientAttestation(clients storage.ClientReader, proofs storage.DPoP, issuer string, supportedAlgorithms []string) AuthenticationProcessor {
	return &clientAttestationAuthentication{
		clients:             clients,
		proofs:              proofs,
		issuer:              issuer,
		supportedAlgorithms: supportedAlgorithms,
	}
}

type clientAttestationConfirmationClaims struct {
	JWK json.RawMessage `json:"jwk"`
}

type clientAttestationClaims struct {
	Issuer       string                               `json:"iss"`
	Subject      string                               `json:"sub"`
	Expires      uint64                               `json:"exp"`
	NotBefore    uint64                               `json:"nbf"`
	IssuedAt     uint64                               `json:"iat"`
	JTI          string                               `json:"jti"`
	Confirmation *clientAttestationConfirmationClaims `json:"cnf,omitempty"`
}

type clientAttestationAuthentication struct {
	clients             storage.ClientReader
	proofs              storage.DPoP
	issuer              string
	supportedAlgorithms []string
}

type clientAttestationPOPClaims struct {
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	Expires   uint64 `json:"exp"`
	NotBefore uint64 `json:"nbf"`
	IssuedAt  uint64 `json:"iat"`
	JTI       string `json:"jti"`
}

//nolint:funlen,gocyclo // linear draft-ordered validation chain; each guard is a protocol requirement
func (p *clientAttestationAuthentication) Authenticate(ctx context.Context, req *clientv1.AuthenticateRequest) (*clientv1.AuthenticateResponse, error) {
	res := &clientv1.AuthenticateResponse{}

	// Validate required fields for this authentication method (draft
	// section 7.1, rule 1 / section 7.2, rule 1: exactly one
	// OAuth-Client-Attestation header and exactly one
	// OAuth-Client-Attestation-PoP header).
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

	// Validate the Client Attestation JWT (draft section 7.1).
	clientPublicKey, attestationSubject, err := p.validateClientAttestation(ctx, *req.ClientAttestation)
	if err != nil {
		switch {
		case errors.Is(err, errClientAttestationNotFresh):
			res.Error = rfcerrors.UseFreshAttestation().Build()
		case errors.Is(err, errClientAttestationSyntax):
			res.Error = rfcerrors.InvalidRequest().Build()
		default:
			res.Error = rfcerrors.InvalidClientAttestation().Build()
		}
		return res, fmt.Errorf("invalid client attestation: %w", err)
	}

	// Validate the Client Attestation PoP JWT (draft section 7.2): parse
	// without cryptographic verification first.
	popToken, popParts, err := gojwt.NewParser().ParseUnverified(*req.ClientAttestationPop, gojwt.MapClaims{})
	if err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("client attestation pop is syntaxically invalid: %w", err)
	}

	// Enforce the algorithm allowlist before processing claims (draft
	// section 7.2, rule 3).
	if !types.Contains(p.supportedAlgorithms, popToken.Method.Alg()) {
		res.Error = rfcerrors.InvalidClientAttestation().Build()
		return res, fmt.Errorf("PoP algorithm %q is not supported", popToken.Method.Alg())
	}

	// The typ header MUST be oauth-client-attestation-pop+jwt (draft
	// section 5.1, rule 2; section 7.2, rule 2).
	typ, _ := popToken.Header["typ"].(string)
	if typ != oidc.TypClientAttestationPoPJWT {
		res.Error = rfcerrors.InvalidClientAttestation().Build()
		return res, fmt.Errorf("PoP typ header must be %s", oidc.TypClientAttestationPoPJWT)
	}

	// Retrieve PoP claims
	var claims clientAttestationPOPClaims
	payload, err := base64.RawURLEncoding.DecodeString(popParts[1])
	if err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to decode PoP claims: %w", err)
	}
	if err = json.Unmarshal(payload, &claims); err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to decode PoP claims: %w", err)
	}

	// Required claims: aud, jti, iat (draft section 5.1, rule 4).
	if claims.Audience == "" || claims.JTI == "" || claims.IssuedAt == 0 {
		res.Error = rfcerrors.InvalidClientAttestation().Build()
		return res, fmt.Errorf("aud, jti, iat are mandatory and not empty")
	}

	// The challenge claim is optional (draft section 5.1, rule 5); this
	// server runs no challenge infrastructure, so a client-provided value
	// is accepted and ignored (unknown claims are ignored per rule 1).

	// Materialize the attested public key and verify the PoP signature with
	// the cnf-bound key (draft section 5.1, rule 3; section 7.2, rule 5).
	publicKey, err := materializeVerificationKey(clientPublicKey)
	if err != nil {
		res.Error = rfcerrors.InvalidClientAttestation().Build()
		return res, fmt.Errorf("unable to materialize attested client public key: %w", err)
	}
	if err = popToken.Method.Verify(popParts[0]+"."+popParts[1], popToken.Signature, publicKey); err != nil {
		res.Error = rfcerrors.InvalidClientAttestation().Build()
		return res, fmt.Errorf("client attestation PoP is invalid: %w", err)
	}

	// PoP audience: draft-ietf-oauth-security-topics-update-03 section
	// 2.1.2 (documented deviation): the aud MUST be the AS issuer
	// identifier (section 2.1.2.1) or the exact endpoint that received the
	// assertion (section 2.1.2.2).
	receivingEndpoint := req.GetEndpoint()
	if claims.Audience != p.issuer && (receivingEndpoint == "" || claims.Audience != receivingEndpoint) {
		res.Error = rfcerrors.InvalidClientAttestation().Build()
		return res, fmt.Errorf("PoP aud %q does not match issuer identifier %q nor receiving endpoint %q", claims.Audience, p.issuer, receivingEndpoint)
	}

	// PoP freshness (draft section 7.2, rule 6): local policy requires the
	// iat to fall within a maxAssertionLifetime window around now; optional
	// exp/nbf are enforced when present.
	now := uint64(time.Now().Unix()) //nolint:gosec // unix time is non-negative
	if claims.IssuedAt < now-uint64(maxAssertionLifetime.Seconds()) {
		res.Error = rfcerrors.InvalidClientAttestation().Build()
		return res, fmt.Errorf("PoP iat is too old, lifetime must not exceed %s", maxAssertionLifetime)
	}
	if claims.IssuedAt > now+uint64(maxAssertionLifetime.Seconds()) {
		res.Error = rfcerrors.InvalidClientAttestation().Build()
		return res, fmt.Errorf("PoP iat is in the future beyond the %s window", maxAssertionLifetime)
	}
	if claims.Expires > 0 {
		if claims.Expires < now {
			res.Error = rfcerrors.InvalidClientAttestation().Build()
			return res, fmt.Errorf("expired PoP")
		}
		if claims.Expires > claims.IssuedAt+uint64(maxAssertionLifetime.Seconds()) {
			res.Error = rfcerrors.InvalidClientAttestation().Build()
			return res, fmt.Errorf("exp is too far in the future, PoP lifetime must not exceed %s", maxAssertionLifetime)
		}
	}
	if claims.NotBefore > now {
		res.Error = rfcerrors.InvalidClientAttestation().Build()
		return res, fmt.Errorf("not useable token")
	}

	// Client binding (draft section 7.5): resolve the client by the
	// ATTESTATION sub — the PoP no longer carries an iss claim in -11.
	client, err := p.clients.Get(ctx, attestationSubject)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			res.Error = rfcerrors.ServerError().Build()
			return res, fmt.Errorf("error during client retrieval: %w", err)
		}
		res.Error = rfcerrors.InvalidClientAttestation().Build()
		return res, fmt.Errorf("client not found")
	}

	// draft section 7.5: when the request carries a client_id, it MUST match
	// the attestation sub.
	if req.GetClientId() != "" && req.GetClientId() != attestationSubject {
		res.Error = rfcerrors.InvalidClientAttestation().Build()
		return res, fmt.Errorf("request client_id %q does not match attestation subject %q", req.GetClientId(), attestationSubject)
	}

	// Fail-closed registration check: the client must be registered for
	// the attest_jwt_client_auth method.
	if client.TokenEndpointAuthMethod != oidc.AuthMethodClientAttestationJWT {
		res.Error = rfcerrors.InvalidClientAttestation().Build()
		return res, fmt.Errorf("client is not registered for %s", oidc.AuthMethodClientAttestationJWT)
	}

	// Prevent PoP replay (draft section 12.1): the jti must be single-use.
	// Burn it only after full validation of the proof.
	jtiHash := blake2b.Sum256([]byte("attest:" + attestationSubject + ":" + claims.JTI))
	jtiKey := base64.RawURLEncoding.EncodeToString(jtiHash[:])
	if exists, errExists := p.proofs.Exists(ctx, jtiKey); errExists != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to verify PoP uniqueness: %w", errExists)
	} else if exists {
		res.Error = rfcerrors.InvalidClientAttestation().Build()
		return res, fmt.Errorf("PoP jti has already been used")
	}
	if err := p.proofs.Register(ctx, jtiKey); err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to register PoP jti: %w", err)
	}

	// Assign to response
	res.Client = client

	return res, nil
}

// -----------------------------------------------------------------------------

//nolint:gocyclo // linear draft-ordered validation chain; each guard is a protocol requirement
func (p *clientAttestationAuthentication) validateClientAttestation(ctx context.Context, clientAttestation string) (key jwk.Key, subject string, err error) {
	// Parse attestation without cryptographic verification first
	t, parts, err := gojwt.NewParser().ParseUnverified(clientAttestation, gojwt.MapClaims{})
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", errClientAttestationSyntax, err)
	}

	// Enforce the algorithm allowlist before processing claims (draft
	// section 7.1, rule 3).
	if !types.Contains(p.supportedAlgorithms, t.Method.Alg()) {
		return nil, "", fmt.Errorf("attestation algorithm %q is not supported", t.Method.Alg())
	}

	// The typ header MUST be oauth-client-attestation+jwt (draft section 4;
	// section 7.1, rule 2).
	typ, _ := t.Header["typ"].(string)
	if typ != oidc.TypClientAttestationJWT {
		return nil, "", fmt.Errorf("attestation typ header must be %s", oidc.TypClientAttestationJWT)
	}

	// Retrieve payload claims
	var claims clientAttestationClaims
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", errClientAttestationSyntax, err)
	}
	if err = json.Unmarshal(payload, &claims); err != nil {
		return nil, "", fmt.Errorf("%w: %w", errClientAttestationSyntax, err)
	}

	// Required claims (draft section 4; section 7.1, rule 4): sub is the
	// client_id, exp bounds freshness, cnf.jwk binds the PoP key; iss locates
	// the Client Attester (local trust model per draft section 10.8).
	if claims.Issuer == "" || claims.Subject == "" || claims.Expires == 0 || claims.Confirmation == nil || len(claims.Confirmation.JWK) == 0 {
		return nil, "", fmt.Errorf("iss, sub, exp, cnf are mandatory and not empty")
	}

	// Freshness (draft section 7.1, rule 6): an expired attestation is the
	// sole use_fresh_attestation condition (section 7.4).
	now := uint64(time.Now().Unix()) //nolint:gosec // unix time is non-negative
	if claims.Expires < now {
		return nil, "", errClientAttestationNotFresh
	}
	if claims.NotBefore > now {
		return nil, "", fmt.Errorf("not useable token")
	}

	// Attester trust (local policy per draft section 10.8): the Client
	// Attester is a registered client whose JWKS pin its signing keys.
	client, err := p.clients.Get(ctx, claims.Issuer)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			return nil, "", fmt.Errorf("error during client retrieval: %w", err)
		}
		return nil, "", fmt.Errorf("attester not found")
	}
	if len(client.Jwks) == 0 {
		return nil, "", fmt.Errorf("attester jwks is nil")
	}

	// Parse JWKS (strict: a malformed attester JWKS fails)
	jwks, err := jwk.Parse(client.Jwks)
	if err != nil {
		return nil, "", fmt.Errorf("attester jwks is invalid: %w", err)
	}

	// Verify the attestation signature with the attester keys (draft
	// section 7.1, rule 4).
	if err = jwk.ValidateSignature(jwks, clientAttestation, p.supportedAlgorithms); err != nil {
		return nil, "", fmt.Errorf("client attestation is invalid: %w", err)
	}

	// Private-material rejection (draft section 7.1, rule 5): the cnf key
	// MUST NOT carry private key material. Inspect the raw JWK members
	// before parsing (covers EC/OKP/RSA "d"), then the parsed AKP private
	// key wrapping.
	var cnfMembers map[string]json.RawMessage
	if err = json.Unmarshal(claims.Confirmation.JWK, &cnfMembers); err != nil {
		return nil, "", fmt.Errorf("attestation cnf.jwk is invalid: %w", err)
	}
	if _, hasPrivate := cnfMembers["d"]; hasPrivate {
		return nil, "", fmt.Errorf("attestation cnf.jwk carries private key material")
	}
	cnfSet, err := jwk.Parse(claims.Confirmation.JWK)
	if err != nil {
		return nil, "", fmt.Errorf("attestation cnf.jwk is invalid: %w", err)
	}
	clientPublicKey, ok := cnfSet.Key(0)
	if !ok {
		return nil, "", fmt.Errorf("attestation cnf.jwk is empty")
	}
	if mk, isMLDSA := clientPublicKey.(*jwk.MLDSAKey); isMLDSA && mk.PrivateKey() != nil {
		return nil, "", fmt.Errorf("attestation cnf.jwk carries private key material")
	}

	// Extract client public key and attestation subject
	return clientPublicKey, claims.Subject, nil
}

// materializeVerificationKey resolves the raw Go public key suitable for
// golang-jwt verification from a jwk.Key, unwrapping AKP (ML-DSA) keys that
// jwx cannot export.
func materializeVerificationKey(k jwk.Key) (any, error) {
	if mk, ok := k.(*jwk.MLDSAKey); ok {
		if mk.MLDSPublicKey() == nil {
			return nil, fmt.Errorf("ML-DSA key has no public key material")
		}
		return mk.MLDSPublicKey(), nil
	}
	var raw any
	if err := jwxjwk.Export(k, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}
