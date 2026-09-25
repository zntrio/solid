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
	"strings"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	blake2b "golang.org/x/crypto/blake2b"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/server/storage"
)

// ClientAttestation authentication method. The issuer value MUST be the
// authorization server's issuer identifier. Per draft-ietf-oauth-security-
// topics-update-03 section 2.1.2, the PoP aud claim is accepted only when it
// equals the issuer identifier (section 2.1.2.1) or the exact endpoint that
// received the attestation PoP (carried by the AuthenticateRequest endpoint
// field, section 2.1.2.2).
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

//nolint:funlen,gocyclo // to refactor
func (p *clientAttestationAuthentication) Authenticate(ctx context.Context, req *clientv1.AuthenticateRequest) (*clientv1.AuthenticateResponse, error) {
	res := &clientv1.AuthenticateResponse{}

	// Validate required fields for this authentication method
	if req.ClientAssertionType == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("client_assertion_type must be defined")
	}
	if *req.ClientAssertionType != oidc.AssertionTypeJWTClientAttestation {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("client_assertion_type must equals '%s', got '%s'", oidc.AssertionTypeJWTClientAttestation, *req.ClientAssertionType)
	}
	if req.ClientAssertion == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("client_assertion must be defined")
	}
	if *req.ClientAssertion == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("client_assertion must not be empty")
	}

	// Split attestation and PoP
	assertions := strings.SplitN(*req.ClientAssertion, "~", 2)
	if len(assertions) != 2 {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, errors.New("invalid client assertion part count")
	}

	// Decode assertions without validation first
	clientPublicKey, attestationSubject, err := p.validateClientAttestation(ctx, assertions[0])
	if err != nil {
		res.Error = rfcerrors.UnauthorizedClient().Build()
		return res, errors.New("invalid client attestation")
	}

	// Decode PoP without validation first
	t, parts, err := gojwt.NewParser().ParseUnverified(assertions[1], gojwt.MapClaims{})
	if err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, errors.New("invalid client attestation PoP")
	}

	// Enforce the algorithm allowlist before processing claims.
	if !containsString(p.supportedAlgorithms, t.Method.Alg()) {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("PoP algorithm %q is not supported", t.Method.Alg())
	}

	// Retrieve PoP claims
	var claims clientAttestationPOPClaims
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, errors.New("invalid client attestation PoP")
	}
	if err = json.Unmarshal(payload, &claims); err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, errors.New("invalid client attestation PoP")
	}

	// Materialize the attested public key and verify the PoP signature.
	publicKey, err := materializeVerificationKey(clientPublicKey)
	if err != nil {
		res.Error = rfcerrors.UnauthorizedClient().Build()
		return nil, fmt.Errorf("unable to materialize attested client public key: %w", err)
	}
	if err = t.Method.Verify(parts[0]+"."+parts[1], t.Signature, publicKey); err != nil {
		res.Error = rfcerrors.UnauthorizedClient().Build()
		return nil, fmt.Errorf("client attestation PoP is invalid: %w", err)
	}

	// Validate claims
	if claims.Issuer == "" || claims.Expires == 0 || claims.JTI == "" || claims.Audience == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("iss, exp, jti, aud are mandatory and not empty")
	}
	// draft-ietf-oauth-security-topics-update-03 section 2.1.2: the PoP aud
	// MUST be the AS issuer identifier (section 2.1.2.1) or the exact
	// endpoint that received the assertion (section 2.1.2.2).
	receivingEndpoint := req.GetEndpoint()
	if claims.Audience != p.issuer && (receivingEndpoint == "" || claims.Audience != receivingEndpoint) {
		res.Error = rfcerrors.UnauthorizedClient().Build()
		return res, fmt.Errorf("PoP aud %q does not match issuer identifier %q nor receiving endpoint %q", claims.Audience, p.issuer, receivingEndpoint)
	}
	if claims.Expires < uint64(time.Now().Unix()) {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("expired token")
	}
	if claims.Expires > claims.IssuedAt+uint64(maxAssertionLifetime.Seconds()) {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("exp is too far in the future, assertion lifetime must not exceed %s", maxAssertionLifetime)
	}
	if claims.NotBefore > uint64(time.Now().Unix()) {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("not useable token")
	}

	// The attestation subject MUST match the PoP issuer: the attested key
	// must be bound to the same client identity that presents the PoP.
	if attestationSubject != claims.Issuer {
		res.Error = rfcerrors.UnauthorizedClient().Build()
		return res, fmt.Errorf("attestation subject does not match PoP issuer")
	}

	// Check client in storage
	client, err := p.clients.Get(ctx, claims.Issuer)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			res.Error = rfcerrors.ServerError().Build()
			return res, fmt.Errorf("error during client retrieval: %w", err)
		}
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client not found")
	}

	// Prevent PoP replay: the jti must be single-use. Burn it only after
	// full validation of the proof (RFC 7523 section 3 replay prevention).
	jtiHash := blake2b.Sum256([]byte("attest:" + claims.Issuer + ":" + claims.JTI))
	jtiKey := base64.RawURLEncoding.EncodeToString(jtiHash[:])
	if exists, errExists := p.proofs.Exists(ctx, jtiKey); errExists != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to verify PoP uniqueness: %w", errExists)
	} else if exists {
		res.Error = rfcerrors.UnauthorizedClient().Build()
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
	// Parse attestation without cryptogrpahic verification first
	t, parts, err := gojwt.NewParser().ParseUnverified(clientAttestation, gojwt.MapClaims{})
	if err != nil {
		return nil, "", fmt.Errorf("client attestation is syntaxically invalid: %w", err)
	}

	// Enforce the algorithm allowlist before processing claims.
	if !containsString(p.supportedAlgorithms, t.Method.Alg()) {
		return nil, "", fmt.Errorf("attestation algorithm %q is not supported", t.Method.Alg())
	}

	// Retrieve payload claims
	var claims clientAttestationClaims
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, "", fmt.Errorf("unable to decode payload claims: %w", err)
	}
	if err = json.Unmarshal(payload, &claims); err != nil {
		return nil, "", fmt.Errorf("unable to decode payload claims: %w", err)
	}

	// Validate claims
	if claims.Issuer == "" || claims.Subject == "" || claims.Expires == 0 || claims.Confirmation == nil {
		return nil, "", fmt.Errorf("iss, sub, exp, cnf are mandatory and not empty")
	}
	if claims.Expires < uint64(time.Now().Unix()) {
		return nil, "", fmt.Errorf("expired token")
	}
	if claims.NotBefore > uint64(time.Now().Unix()) {
		return nil, "", fmt.Errorf("not useable token")
	}

	// Check client in storage
	client, err := p.clients.Get(ctx, claims.Issuer)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			return nil, "", fmt.Errorf("error during client retrieval: %w", err)
		}
		return nil, "", fmt.Errorf("client not found")
	}

	// Retrieve JWK associated to the client
	if len(client.Jwks) == 0 {
		return nil, "", fmt.Errorf("client jwks is nil")
	}

	// Parse JWKS (strict: a malformed client JWKS fails)
	jwks, err := jwk.Parse(client.Jwks)
	if err != nil {
		return nil, "", fmt.Errorf("client jwks is invalid: %w", err)
	}

	// Try to validate assertion with one of keys
	if err = jwk.ValidateSignature(jwks, clientAttestation, p.supportedAlgorithms); err != nil {
		return nil, "", fmt.Errorf("client assertion is invalid: %w", err)
	}

	// Extract the attested client public key from the cnf claim
	if len(claims.Confirmation.JWK) == 0 {
		return nil, "", fmt.Errorf("attestation cnf.jwk is empty")
	}
	cnfSet, err := jwk.Parse(claims.Confirmation.JWK)
	if err != nil {
		return nil, "", fmt.Errorf("attestation cnf.jwk is invalid: %w", err)
	}
	clientPublicKey, ok := cnfSet.Key(0)
	if !ok {
		return nil, "", fmt.Errorf("attestation cnf.jwk is empty")
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
