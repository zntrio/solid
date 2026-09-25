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
	"zntr.io/solid/server/storage"
)

// PrivateKeyJWT authentication method. The issuer value MUST be the
// authorization server's issuer identifier. Per draft-ietf-oauth-security-
// topics-update-03 section 2.1.2, an assertion's aud claim is accepted only
// when it is a single value equal to the issuer identifier (the draft's
// preferred countermeasure, section 2.1.2.1) or to the exact endpoint that
// received the assertion (carried by the AuthenticateRequest endpoint field,
// section 2.1.2.2). This kills the cross-endpoint replay surface of a
// multi-audience acceptance and the audience-injection vector of RFC 7519
// array-form aud claims.
func PrivateKeyJWT(clients storage.ClientReader, proofs storage.DPoP, issuer string, supportedAlgorithms []string) AuthenticationProcessor {
	return &privateKeyJWTAuthentication{
		clients:             clients,
		proofs:              proofs,
		issuer:              issuer,
		supportedAlgorithms: supportedAlgorithms,
	}
}

type privateJWTClaims struct {
	JTI       string   `json:"jti"`
	Subject   string   `json:"sub"`
	Issuer    string   `json:"iss"`
	Audience  audClaim `json:"aud"`
	Expires   uint64   `json:"exp"`
	IssuedAt  uint64   `json:"iat"`
	NotBefore uint64   `json:"nbf,omitempty"`
}

// audClaim models the RFC 7519 aud claim, which may be a string or an array
// of strings. Parsing accepts both forms, but draft-ietf-oauth-security-
// topics-update-03 section 2.1.2 mandates a single audience value for client
// authentication assertions: Authenticate rejects any decoded aud that does
// not contain exactly one entry.
type audClaim []string

// UnmarshalJSON accepts either the string or the array-of-strings form.
func (a *audClaim) UnmarshalJSON(b []byte) error {
	// Try the single-string form first.
	var single string
	if err := json.Unmarshal(b, &single); err == nil {
		*a = audClaim{single}
		return nil
	}

	// Fall back to the array form.
	var multiple []string
	if err := json.Unmarshal(b, &multiple); err != nil {
		return fmt.Errorf("aud claim must be a string or an array of strings: %w", err)
	}
	*a = multiple
	return nil
}

// MarshalJSON emits the canonical single-string form when exactly one
// audience is present, and the array form otherwise.
func (a audClaim) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

func (a audClaim) Contains(expected string) bool {
	for _, v := range a {
		if v == expected {
			return true
		}
	}
	return false
}

// maxAssertionLifetime is the maximum allowed duration between iat and exp of
// a client assertion, as permitted by RFC 7523 section 3 ("may reject JWTs
// whose exp ... is unreasonably far in the future").
const maxAssertionLifetime = 10 * time.Minute

type privateKeyJWTAuthentication struct {
	clients             storage.ClientReader
	proofs              storage.DPoP
	issuer              string
	supportedAlgorithms []string
}

//nolint:funlen,gocyclo // to refactor
func (p *privateKeyJWTAuthentication) Authenticate(ctx context.Context, req *clientv1.AuthenticateRequest) (*clientv1.AuthenticateResponse, error) {
	res := &clientv1.AuthenticateResponse{}

	// Validate request
	if req == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process nil request")
	}

	// Validate required fields for this authentication method
	if req.ClientAssertionType == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("client_assertion_type must be defined")
	}
	if *req.ClientAssertionType != oidc.AssertionTypeJWTBearer {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("client_assertion_type must equals '%s', got '%s'", oidc.AssertionTypeJWTBearer, *req.ClientAssertionType)
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
		return res, fmt.Errorf("assertion is syntaxically invalid: %w", err)
	}

	// Enforce the algorithm allowlist before processing claims: reject
	// e.g. HS256 tokens early on an EC-only authenticator.
	if !containsString(p.supportedAlgorithms, t.Method.Alg()) {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("assertion algorithm %q is not supported", t.Method.Alg())
	}

	// Retrieve payload claims
	var claims privateJWTClaims
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to decode payload claims: %w", err)
	}
	if err = json.Unmarshal(payload, &claims); err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to decode payload claims: %w", err)
	}
	// Validate claims
	if claims.Issuer == "" || claims.Subject == "" || len(claims.Audience) == 0 || claims.JTI == "" || claims.Expires == 0 {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("iss, sub, aud, jti, exp are mandatory and not empty")
	}
	if claims.Issuer != claims.Subject {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("iss and sub must be identic")
	}
	// draft-ietf-oauth-security-topics-update-03 section 2.1.2: the aud
	// claim MUST carry exactly one value (an array containing the expected
	// audience alongside attacker-controlled ones is rejected), and that
	// value MUST be the AS issuer identifier (section 2.1.2.1) or the exact
	// endpoint that received the assertion (section 2.1.2.2).
	if len(claims.Audience) != 1 {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("aud must contain exactly one value")
	}
	receivingEndpoint := req.GetEndpoint()
	if claims.Audience[0] != p.issuer && (receivingEndpoint == "" || claims.Audience[0] != receivingEndpoint) {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("aud %q does not match issuer identifier %q nor receiving endpoint %q", claims.Audience[0], p.issuer, receivingEndpoint)
	}
	if claims.IssuedAt > uint64(time.Now().Add(5*time.Minute).Unix()) {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("iat is in the future")
	}
	if claims.Expires > claims.IssuedAt+uint64(maxAssertionLifetime.Seconds()) {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("exp is too far in the future, assertion lifetime must not exceed %s", maxAssertionLifetime)
	}
	if claims.NotBefore > 0 && claims.NotBefore > uint64(time.Now().Unix()) {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("nbf is in the future")
	}
	if claims.Expires < uint64(time.Now().Unix()) {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("expired token")
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

	// Retrieve JWK associated to the client
	if len(client.Jwks) == 0 {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client jwks is nil")
	}

	// Parse JWKS (strict: a malformed client JWKS fails as invalid client)
	jwks, err := jwk.Parse(client.Jwks)
	if err != nil {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client jwks is invalid: %w", err)
	}

	// Try to validate assertion with one of keys
	if err := jwk.ValidateSignature(jwks, *req.ClientAssertion, p.supportedAlgorithms); err != nil {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client assertion is invalid: %w", err)
	}

	// Prevent assertion replay: the jti must be single-use. Burn it only
	// after the signature has been fully validated (RFC 7523 section 3:
	// "the authorization server MAY reject JWTs with a jti value previously
	// used"). Key-prefixed hash namespaces distinct clients.
	jtiHash := blake2b.Sum256([]byte("jwt-bearer:" + claims.Issuer + ":" + claims.JTI))
	jtiKey := base64.RawURLEncoding.EncodeToString(jtiHash[:])
	if exists, errExists := p.proofs.Exists(ctx, jtiKey); errExists != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to verify assertion uniqueness: %w", errExists)
	} else if exists {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("assertion jti has already been used")
	}
	if err := p.proofs.Register(ctx, jtiKey); err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to register assertion jti: %w", err)
	}

	// Defensive: the client must be registered for the private_key_jwt
	// method (cross-method authentication attempts fail closed, as with
	// the other asymmetric authenticators).
	if client.TokenEndpointAuthMethod != oidc.AuthMethodPrivateKeyJWT {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client is not registered for %s", oidc.AuthMethodPrivateKeyJWT)
	}

	// Assign client to result
	res.Client = client

	// No error
	return res, nil
}

// containsString reports whether list contains the value.
func containsString(list []string, value string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}
