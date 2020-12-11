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
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"

	"zntr.io/solid/pkg/sdk/jwt"
	"zntr.io/solid/pkg/sdk/types"
	"zntr.io/solid/pkg/server/storage"
)

// -----------------------------------------------------------------------------

// DefaultVerifier returns a verifier instance with in-memory cache for proof
// storage.
func DefaultVerifier(proofs storage.DPoP, verifier jwt.Verifier) (Verifier, error) {
	// Check arguments
	if types.IsNil(proofs) {
		return nil, fmt.Errorf("proof storage is mandatory and couldn't be nil")
	}
	if types.IsNil(verifier) {
		return nil, fmt.Errorf("jwt verifier is mandatory and couldn't be nil")
	}

	// No error
	return &defaultVerifier{
		proofs:   proofs,
		verifier: verifier,
	}, nil
}

// -----------------------------------------------------------------------------

type defaultVerifier struct {
	proofs   storage.DPoP
	verifier jwt.Verifier
}

// Verify given DPoP proof.
// https://www.ietf.org/id/draft-ietf-oauth-dpop-01.html#section-4.2
func (v *defaultVerifier) Verify(ctx context.Context, htm, htu, proof string) (string, error) {
	// Check parameters
	if htm == "" {
		return "", fmt.Errorf("htm must not be blank")
	}
	if htu == "" {
		return "", fmt.Errorf("htu must not be blank")
	}
	if proof == "" {
		return "", fmt.Errorf("proof must not be blank")
	}

	// Validate url
	u, err := url.ParseRequestURI(htu)
	if err != nil {
		return "", fmt.Errorf("invalid URL syntax for proof verification '%s': %w", htu, err)
	}

	// Validate method
	switch strings.ToUpper(htm) {
	case http.MethodConnect, http.MethodDelete, http.MethodGet, http.MethodHead, http.MethodOptions:
	case http.MethodPatch, http.MethodPost, http.MethodPut, http.MethodTrace:
	default:
		return "", fmt.Errorf("invalid HTTP Method in proof verification '%s'", htm)
	}

	// Check dpop
	token, err := v.verifier.Parse(proof)
	if err != nil {
		return "", fmt.Errorf("proof has not a valid jwt syntax: %w", err)
	}

	// Validate header
	if errHdr := v.validateProofHeader(token); errHdr != nil {
		return "", errHdr
	}

	// Extract claims
	claims, errClm := v.extractProofClaims(token)
	if errClm != nil {
		return "", errClm
	}

	// Validate proof claims
	jtiHash, errJti := v.validateProofClaims(htm, u.String(), claims)
	if errJti != nil {
		return "", errJti
	}

	// Check if exists
	if errCache := v.checkProofCache(ctx, jtiHash); errCache != nil {
		return "", errCache
	}

	// Compute confirmation
	thumb, err := token.PublicKeyThumbPrint()
	if err != nil {
		return "", fmt.Errorf("unable to compute confirmation: %w", err)
	}

	// Return confirmation
	return thumb, nil
}

func (v *defaultVerifier) validateProofHeader(proof jwt.Token) error {
	// Check arguments
	if types.IsNil(proof) {
		return fmt.Errorf("unable to process nil token")
	}

	// Check token type
	typ, err := proof.Type()
	if err != nil {
		return fmt.Errorf("proof has not a valid jwt syntax, valid 'typ' header is mandatory")
	}
	if typ != HeaderType {
		return fmt.Errorf("proof has not a valid jwt syntax, 'typ' header value must be '%s'", HeaderType)
	}

	// JWK
	pubJWK, err := proof.PublicKey()
	if err != nil {
		return fmt.Errorf("proof has not a valid jwt syntax, a valid embedded public key is mandatory")
	}
	if types.IsNil(pubJWK) {
		return fmt.Errorf("proof has not a valid jwt syntax, the embedded public is invalid")
	}

	// No error
	return nil
}

func (v *defaultVerifier) extractProofClaims(proof jwt.Token) (*proofClaims, error) {
	// Check arguments
	if types.IsNil(proof) {
		return nil, fmt.Errorf("unable to process nil token")
	}

	// Extract public key from token
	jwk, err := proof.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve public key from token: %w", err)
	}

	// Check signature
	var claims proofClaims
	if err := proof.Claims(jwk, &claims); err != nil {
		return nil, fmt.Errorf("unable to decode proof claims: %w", err)
	}

	// No error
	return &claims, nil
}

func (v *defaultVerifier) validateProofClaims(htm, htu string, claims *proofClaims) (string, error) {
	// Check arguments
	if htm == "" {
		return "", fmt.Errorf("htm must not be blank")
	}
	if htu == "" {
		return "", fmt.Errorf("htu must not be blank")
	}
	if claims == nil {
		return "", fmt.Errorf("claims must not be nil")
	}

	// Check http parameters
	if claims.HTTPMethod != htm {
		return "", fmt.Errorf("invalid proof: http method don't match, got:'%s', expected: '%s'", htm, claims.HTTPMethod)
	}

	// Prepare the url
	if claims.HTTPURL != htu {
		return "", fmt.Errorf("invalid proof: http url don't match, got:'%s', expected: '%s'", htu, claims.HTTPURL)
	}

	// Check expiration
	if uint64(time.Now().Add(-ExpirationTreshold).Unix()) > claims.IssuedAt {
		return "", fmt.Errorf("invalid proof: expired")
	}

	// Check future proof
	if uint64(time.Now().Add(ExpirationTreshold).Unix()) < claims.IssuedAt {
		return "", fmt.Errorf("invalid proof: issued in the future")
	}

	// Compute jti hash
	jtiHashRaw := blake2b.Sum256([]byte(claims.JTI))
	jtiStorage := base64.RawURLEncoding.EncodeToString(jtiHashRaw[:])

	// No error
	return jtiStorage, nil
}

func (v *defaultVerifier) checkProofCache(ctx context.Context, jtiHash string) error {
	// Check existence
	valid, err := v.proofs.Exists(ctx, jtiHash)
	if err != nil {
		return fmt.Errorf("unable to query proof storage: %w", err)
	}
	if valid {
		return fmt.Errorf("invalid proof: already used")
	}

	// Insert proof in cache
	if err = v.proofs.Register(ctx, jtiHash); err != nil {
		return fmt.Errorf("unable to register proof in storage: %w", err)
	}

	// No error
	return nil
}
