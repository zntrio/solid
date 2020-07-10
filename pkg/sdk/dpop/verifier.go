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

package dpop

import (
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"zntr.io/solid/pkg/server/storage"

	"github.com/square/go-jose/v3"
	"github.com/square/go-jose/v3/jwt"
	"golang.org/x/crypto/blake2b"
)

const (
	// HeaderType defines typ claim value
	HeaderType = "dpop+jwt"
	// ExpirationTreshold defines clock swrew tolerance
	ExpirationTreshold = 15 * time.Second
	// SignatureAlgorithm defines algorithm used for proof signature
	SignatureAlgorithm = jose.ES256
)

// Verifier describes proof verifier contract.
type Verifier interface {
	Verify(ctx context.Context, r *http.Request, proof string) (string, error)
}

// -----------------------------------------------------------------------------

// DefaultVerifier returns a verifier instance with in-memory cache for proof
// storage.
func DefaultVerifier(proofs storage.DPoP) Verifier {
	return &defaultVerifier{
		proofs: proofs,
	}
}

// -----------------------------------------------------------------------------

type defaultVerifier struct {
	proofs storage.DPoP
}

// Verify given DPoP proof.
// https://www.ietf.org/id/draft-ietf-oauth-dpop-01.html#section-4.2
func (v *defaultVerifier) Verify(ctx context.Context, r *http.Request, proof string) (string, error) {
	// Check parameters
	if r == nil {
		return "", fmt.Errorf("http request must not be nil")
	}
	if proof == "" {
		return "", fmt.Errorf("proof must not be blank")
	}

	// Check dpop
	token, err := jwt.ParseSigned(proof)
	if err != nil {
		return "", fmt.Errorf("proof has not a valid jwt syntax: %w", err)
	}

	// Validate header
	if errHdr := v.validateHeader(token); errHdr != nil {
		return "", errHdr
	}

	// Validate claims
	jtiHash, errClm := v.validateClaims(r, token.Headers[0].JSONWebKey, token)
	if errClm != nil {
		return "", errClm
	}

	// Check if exists
	valid, err := v.proofs.Exists(ctx, jtiHash)
	if err != nil {
		return "", fmt.Errorf("unable to query proof storage: %w", err)
	}
	if valid {
		return "", fmt.Errorf("invalid proof: already used")
	}

	// Insert proof in cache
	if err = v.proofs.Register(ctx, jtiHash); err != nil {
		return "", fmt.Errorf("unable to register proof in storage: %w", err)
	}

	// Compute confirmation
	thumb, err := token.Headers[0].JSONWebKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("unable to compute confirmation: %w", err)
	}

	// Return confirmation
	return base64.RawURLEncoding.EncodeToString(thumb), nil
}

func (v *defaultVerifier) validateHeader(token *jwt.JSONWebToken) error {
	// Check arguments
	if token == nil {
		return fmt.Errorf("unable to process nil token")
	}

	// Check claims
	if len(token.Headers) == 0 {
		return fmt.Errorf("proof has not a valid jwt syntax, missing header")
	}
	if len(token.Headers) > 1 {
		return fmt.Errorf("proof has not a valid jwt syntax, too many headers")
	}

	// JWK
	if token.Headers[0].JSONWebKey == nil {
		return fmt.Errorf("proof has not a valid jwt syntax, no public jwk embedded")
	}
	// Typ
	typ, ok := token.Headers[0].ExtraHeaders[jose.HeaderKey("typ")]
	if !ok {
		return fmt.Errorf("proof has not a valid jwt syntax, 'typ' header is mandatory")
	}
	if typ != HeaderType {
		return fmt.Errorf("proof has not a valid jwt syntax, 'typ' header value must be '%s'", HeaderType)
	}

	// Algorithm
	if token.Headers[0].Algorithm != string(SignatureAlgorithm) {
		return fmt.Errorf("proof has not a valid jwt syntax, 'alg' header value must be '%s'", SignatureAlgorithm)
	}

	// No error
	return nil
}

func (v *defaultVerifier) validateClaims(r *http.Request, jwk *jose.JSONWebKey, token *jwt.JSONWebToken) (string, error) {
	// Check arguments
	if r == nil {
		return "", fmt.Errorf("unable to process nil request")
	}
	if jwk == nil {
		return "", fmt.Errorf("unable to process nil jwk")
	}
	if token == nil {
		return "", fmt.Errorf("unable to process nil token")
	}

	// Check signature
	var claims proofClaims
	if err := token.Claims(jwk, &claims); err != nil {
		return "", fmt.Errorf("unable to decode proof claims: %w", err)
	}

	// Check http parameters
	if claims.HTTPMethod != r.Method {
		return "", fmt.Errorf("invalid proof: http method don't match, got:'%s', expected: '%s'", r.Method, claims.HTTPMethod)
	}

	// Prepare the url
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwardScheme := r.Header.Get("X-Forwarded-Scheme"); forwardScheme != "" {
		scheme = forwardScheme
	}
	cleanURL := fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.Path)

	if claims.HTTPURL != cleanURL {
		return "", fmt.Errorf("invalid proof: http url don't match, got:'%s', expected: '%s'", cleanURL, claims.HTTPURL)
	}

	// Check expiration
	if claims.IssuedAt-uint64(time.Now().Unix()) > uint64(ExpirationTreshold) {
		return "", fmt.Errorf("invalid proof: issued in the future")
	}
	if uint64(time.Now().Unix())-claims.IssuedAt > uint64(ExpirationTreshold) {
		return "", fmt.Errorf("invalid proof: expired")
	}

	// Compute jti hash
	jtiHashRaw := blake2b.Sum256([]byte(claims.JTI))
	jtiStorage := base64.RawURLEncoding.EncodeToString(jtiHashRaw[:])

	// No error
	return jtiStorage, nil
}
