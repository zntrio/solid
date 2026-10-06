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

package sdjwt

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/sdtoken"
	"zntr.io/solid/sdk/token"
	"zntr.io/solid/sdk/token/jwt"
)

// verifier assembles the RFC 9901 Verifier role with the defensive
// default posture: key binding required, audience and nonce checks
// mandatory, 5-minute KB-JWT freshness window, 60-second leeway.
type verifier struct {
	issuerVerifier token.Verifier
	cfg            *verifyConfig
}

// Verifier returns an SD-JWT / SD-JWT+KB Verifier (RFC 9901 sections
// 7.1, 7.3).
func NewVerifier(issuerVerifier token.Verifier, opts ...VerifyOption) Verifier {
	return &verifier{
		issuerVerifier: issuerVerifier,
		cfg:            newVerifyConfig(opts...),
	}
}

// Verify implements the RFC 9901 section 7.1 / 7.3 processing algorithm
// and returns the Processed SD-JWT Payload.
func (v *verifier) Verify(ctx context.Context, presentation string) (map[string]any, error) {
	// Step 1: parse the compact serialization.
	parsed, err := Parse(presentation)
	if err != nil {
		return nil, err
	}

	// Key binding policy (required by default).
	if parsed.KeyBindingJWT == "" && !v.cfg.optionalKeyBinding {
		return nil, ErrKeyBindingRequired
	}

	// Step 2: verify the issuer JWT and decode the payload.
	payload, err := verifiedPayload(v.issuerVerifier, parsed.IssuerSignedJWT)
	if err != nil {
		return nil, err
	}

	// Issuer JWT typ check: non-empty and ending in "+sd-jwt" by default.
	if err := checkIssuerTyp(v.issuerVerifier, parsed.IssuerSignedJWT, v.cfg.expectedTypSuffix); err != nil {
		return nil, err
	}

	// _sd_alg handling: absent defaults to sha-256, others rejected.
	if err := checkSDAlg(payload); err != nil {
		return nil, err
	}

	// Step 3: decode disclosures and process with verifier semantics.
	decoded := make([]sdtoken.DecodedDisclosure, 0, len(parsed.Disclosures))
	for _, d := range parsed.Disclosures {
		dd, errDec := decodeDisclosure(d)
		if errDec != nil {
			return nil, errDec
		}
		decoded = append(decoded, dd)
	}
	processed, _, errProc := sdtoken.Process(jsonAdapter{}, payload, decoded, sdtoken.ProcessOptions{HolderSemantics: false})
	if errProc != nil {
		return nil, errProc
	}
	processed = pruneNilElements(processed)
	processedClaims, ok := processed.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: processed payload is not a claim map", ErrInvalidSDJWT)
	}

	// Step 4: key binding validation (RFC 9901 section 7.3 step 5).
	if parsed.KeyBindingJWT != "" {
		if err := v.checkKeyBinding(parsed, processedClaims); err != nil {
			return nil, err
		}
	}

	// Step 5: temporal claims of the processed payload (section 7.1
	// step 6).
	now := time.Now()
	if err := checkTemporal(processedClaims, now, v.cfg.leeway); err != nil {
		return nil, err
	}

	return processedClaims, nil
}

// checkKeyBinding validates the KB-JWT per RFC 9901 section 7.3 step 5.
func (v *verifier) checkKeyBinding(parsed SDJWT, processedClaims map[string]any) error {
	kbVerifier, err := v.kbVerifierFor(processedClaims)
	if err != nil {
		return err
	}

	// Verify the KB-JWT signature against the holder key.
	var kbClaims map[string]any
	if err := kbVerifier.Claims(context.Background(), parsed.KeyBindingJWT, &kbClaims); err != nil {
		return fmt.Errorf("%w: kb-jwt signature verification failed", ErrInvalidKeyBinding)
	}

	// KB-JWT typ: exact "kb+jwt" (section 7.3 step 5).
	if err := checkTyp(kbVerifier, parsed.KeyBindingJWT, TypeKeyBinding, true); err != nil {
		return err
	}

	return v.checkKBJWTClaims(parsed, kbClaims)
}

// kbVerifierFor resolves the KB-JWT verifier: the configured
// WithKeyBindingKeyProvider when set (draft-forten section 5.3: the
// DPoP proof key), otherwise the cnf.jwk extraction (RFC 9901
// section 7.3 step 5).
func (v *verifier) kbVerifierFor(processedClaims map[string]any) (token.Verifier, error) {
	if v.cfg.kbKeyProvider != nil {
		return v.cfg.kbKeyProvider(processedClaims)
	}
	return kbJWTVerifierFor(processedClaims)
}

// kbJWTVerifierFor extracts the cnf.jwk holder key from the processed
// payload and assembles the one-key verifier set for the KB-JWT.
func kbJWTVerifierFor(processedClaims map[string]any) (token.Verifier, error) {
	cnf, has := processedClaims["cnf"]
	if !has {
		return nil, fmt.Errorf("%w: payload carries no cnf claim", ErrInvalidKeyBinding)
	}
	cnfMap, ok := cnf.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: cnf claim is not an object", ErrInvalidKeyBinding)
	}
	jwkClaim, has := cnfMap["jwk"]
	if !has {
		return nil, fmt.Errorf("%w: cnf claim carries no jwk member", ErrInvalidKeyBinding)
	}

	// Re-serialize the holder key claim and parse it as a JWK.
	jwkJSON, err := json.Marshal(jwkClaim)
	if err != nil {
		return nil, fmt.Errorf("%w: unable to serialize cnf.jwk", ErrInvalidKeyBinding)
	}
	holderKey, err := jwxjwk.ParseKey(jwkJSON)
	if err != nil {
		return nil, fmt.Errorf("%w: cnf.jwk is not a valid JWK: %w", ErrInvalidKeyBinding, err)
	}

	// Build the one-key verifier set for the KB-JWT.
	keySet := jwxjwk.NewSet()
	if err := keySet.AddKey(holderKey); err != nil {
		return nil, fmt.Errorf("%w: unable to assemble holder key set", ErrInvalidKeyBinding)
	}
	return jwt.DefaultVerifier(func(context.Context) (jwk.Set, error) { return keySet, nil }, jwt.SupportedSignAlgorithms()), nil
}

// checkKBJWTClaims validates the aud, nonce, iat freshness window, and
// sd_hash claims of a signature-verified KB-JWT.
func (v *verifier) checkKBJWTClaims(parsed SDJWT, kbClaims map[string]any) error {
	if err := v.checkKBAudience(kbClaims); err != nil {
		return err
	}
	if err := v.checkKBNonce(kbClaims); err != nil {
		return err
	}
	if err := v.checkKBIatFreshness(kbClaims); err != nil {
		return err
	}
	return v.checkKBSDHash(parsed, kbClaims)
}

// checkKBAudience enforces aud == the configured audience (mandatory).
func (v *verifier) checkKBAudience(kbClaims map[string]any) error {
	if v.cfg.audience == "" {
		return fmt.Errorf("%w: no audience configured", ErrInvalidKeyBinding)
	}
	aud, has := kbClaims["aud"]
	if !has {
		return fmt.Errorf("%w: kb-jwt carries no aud claim", ErrInvalidKeyBinding)
	}
	audString, ok := aud.(string)
	if !ok || audString != v.cfg.audience {
		return fmt.Errorf("%w: kb-jwt audience mismatch", ErrInvalidKeyBinding)
	}
	return nil
}

// checkKBNonce enforces the mandatory nonce validator.
func (v *verifier) checkKBNonce(kbClaims map[string]any) error {
	if v.cfg.nonceValidator == nil {
		return fmt.Errorf("%w: no nonce validator configured", ErrInvalidKeyBinding)
	}
	nonce, has := kbClaims["nonce"]
	if !has {
		return fmt.Errorf("%w: kb-jwt carries no nonce claim", ErrInvalidKeyBinding)
	}
	nonceString, ok := nonce.(string)
	if !ok {
		return fmt.Errorf("%w: kb-jwt nonce is not a string", ErrInvalidKeyBinding)
	}
	if err := v.cfg.nonceValidator(nonceString); err != nil {
		return fmt.Errorf("%w: kb-jwt nonce rejected: %w", ErrInvalidKeyBinding, err)
	}
	return nil
}

// checkKBIatFreshness enforces the iat freshness window with leeway.
func (v *verifier) checkKBIatFreshness(kbClaims map[string]any) error {
	iat, has := kbClaims["iat"]
	if !has {
		return fmt.Errorf("%w: kb-jwt carries no iat claim", ErrInvalidKeyBinding)
	}
	iatValue, ok := numeric(iat)
	if !ok {
		return fmt.Errorf("%w: kb-jwt iat is not numeric", ErrInvalidKeyBinding)
	}
	age := time.Now().Unix() - iatValue
	if age < -v.cfg.leeway || age > v.cfg.kbMaxAge+v.cfg.leeway {
		return fmt.Errorf("%w: kb-jwt iat outside the freshness window", ErrInvalidKeyBinding)
	}
	return nil
}

// checkKBSDHash enforces sd_hash == SHA-256 over the presentation's
// SD-JWT part (JWT~D~...~D~, including the trailing "~").
func (v *verifier) checkKBSDHash(parsed SDJWT, kbClaims map[string]any) error {
	expectedSDJWT := parsed.IssuerSignedJWT
	for _, d := range parsed.Disclosures {
		expectedSDJWT += "~" + d
	}
	expectedSDJWT += "~"
	expectedHash := sdHashOf(expectedSDJWT)
	got, has := kbClaims[ClaimSDHash]
	if !has {
		return fmt.Errorf("%w: kb-jwt carries no sd_hash claim", ErrInvalidKeyBinding)
	}
	gotHash, ok := got.(string)
	if !ok || gotHash != expectedHash {
		return fmt.Errorf("%w: kb-jwt sd_hash mismatch", ErrInvalidKeyBinding)
	}
	return nil
}

// checkIssuerTyp enforces the issuer JWT typ policy: by default a
// non-empty value ending in "+sd-jwt" (RFC 9901 section 5.2 / 7.1).
func checkIssuerTyp(verifier token.Verifier, rawJWT, expectedOverride string) error {
	return checkTyp(verifier, rawJWT, expectedOverride, false)
}

// checkTyp enforces the KB-JWT typ policy: exact "kb+jwt" match.
func checkTyp(verifier token.Verifier, rawJWT, expected string, exact bool) error {
	// Parse the token (signature already verified by the caller or
	// checked separately): the typ header is read syntactically only.
	tok, err := verifier.Parse(rawJWT)
	if err != nil {
		return fmt.Errorf("%w: unable to parse jwt header", ErrInvalidSDJWT)
	}
	typ, err := tok.Type()
	if err != nil {
		return fmt.Errorf("%w: token carries no typ header", ErrInvalidSDJWT)
	}
	if exact {
		if typ != expected {
			return fmt.Errorf("%w: typ %q does not equal %q", ErrInvalidSDJWT, typ, expected)
		}
		return nil
	}
	if expected != "" {
		if typ != expected {
			return fmt.Errorf("%w: typ %q does not equal %q", ErrInvalidSDJWT, typ, expected)
		}
		return nil
	}
	if typ == "" || !strings.HasSuffix(typ, "+sd-jwt") {
		return fmt.Errorf("%w: typ %q is not an sd-jwt media type", ErrInvalidSDJWT, typ)
	}
	return nil
}
