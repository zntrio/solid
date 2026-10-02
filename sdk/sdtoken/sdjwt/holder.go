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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"zntr.io/solid/sdk/sdtoken"
	"zntr.io/solid/sdk/token"
)

// holder assembles the RFC 9901 Holder role: it verifies the issuer
// signature with an injected token.Verifier and holds an injected
// KB-JWT serializer (the caller owns the holder key material, e.g.
// jwt.RawTypedSigner("kb+jwt", "ES256", holderKeyProvider)).
type holder struct {
	issuerVerifier token.Verifier
	kbSigner       token.Serializer
}

// Holder returns an SD-JWT Holder (RFC 9901 section 7.2).
func NewHolder(issuerVerifier token.Verifier, kbSigner token.Serializer) Holder {
	return &holder{
		issuerVerifier: issuerVerifier,
		kbSigner:       kbSigner,
	}
}

// Present builds an SD-JWT presentation carrying the selected subset of
// the issued disclosures (RFC 9901 section 7.2).
func (h *holder) Present(issued string, selected ...string) (string, error) {
	// Step 1: parse the issued SD-JWT.
	parsed, err := Parse(issued)
	if err != nil {
		return "", err
	}
	// The Holder MUST reject SD-JWT+KB inputs (section 7.2 step 1).
	if parsed.KeyBindingJWT != "" {
		return "", fmt.Errorf("%w: input is an sd-jwt+kb", ErrInvalidSDJWT)
	}

	// Step 2: verify the issuer signature and decode the payload.
	payload, err := verifiedPayload(h.issuerVerifier, parsed.IssuerSignedJWT)
	if err != nil {
		return "", err
	}
	if err := checkSDAlg(payload); err != nil {
		return "", err
	}

	// Step 3: decode all disclosures and run holder-semantics processing
	// (every disclosure must match a redaction site; decoy digests carry
	// no disclosure and remain unmatched at the site side).
	decoded := make([]sdtoken.DecodedDisclosure, 0, len(parsed.Disclosures))
	for _, d := range parsed.Disclosures {
		dd, errDec := decodeDisclosure(d)
		if errDec != nil {
			return "", errDec
		}
		decoded = append(decoded, dd)
	}
	if _, _, errProc := sdtoken.Process(jsonAdapter{}, payload, decoded, sdtoken.ProcessOptions{HolderSemantics: true}); errProc != nil {
		return "", errProc
	}

	// Step 4: the selection must be a duplicate-free subset of the
	// issued disclosures.
	issuedSet := make(map[string]struct{}, len(parsed.Disclosures))
	for _, d := range parsed.Disclosures {
		issuedSet[d] = struct{}{}
	}
	seen := make(map[string]struct{}, len(selected))
	for _, s := range selected {
		if _, ok := issuedSet[s]; !ok {
			return "", fmt.Errorf("%w: selected disclosure is not part of the issued sd-jwt", ErrInvalidSDJWT)
		}
		if _, dup := seen[s]; dup {
			return "", fmt.Errorf("%w: selected disclosure presented twice", ErrInvalidSDJWT)
		}
		seen[s] = struct{}{}
	}

	// Step 5: reassemble JWT~sel1~...~selN~.
	out := parsed.IssuerSignedJWT
	for _, s := range selected {
		out += "~" + s
	}
	out += "~"

	return out, nil
}

// KeyBind attaches a KB-JWT to a presentation (RFC 9901 section 4.3),
// producing SD-JWT+KB.
func (h *holder) KeyBind(presentation, nonce, audience string, issuedAt int64) (string, error) {
	// The input must be a plain SD-JWT presentation (trailing "~").
	parsed, err := Parse(presentation)
	if err != nil {
		return "", err
	}
	if parsed.KeyBindingJWT != "" {
		return "", fmt.Errorf("%w: input already carries a kb-jwt", ErrInvalidSDJWT)
	}

	// sd_hash: base64url SHA-256 over the presentation's SD-JWT part
	// including the trailing "~" (RFC 9901 section 4.3.1). Since
	// Present's output is the exact SD-JWT part, hash the presentation
	// as presented.
	sdHash := sdHashOf(presentation)

	// KB payload (section 4.3): nonce, aud, iat, sd_hash.
	kbClaims := map[string]any{
		"nonce":     nonce,
		"aud":       audience,
		"iat":       issuedAt,
		ClaimSDHash: sdHash,
	}

	// Sign the KB-JWT with the holder key.
	kbJWT, err := h.kbSigner.Serialize(context.TODO(), kbClaims)
	if err != nil {
		return "", fmt.Errorf("unable to sign kb-jwt: %w", err)
	}

	// SD-JWT+KB: presentation without the trailing "~", then the KB-JWT.
	return presentation[:len(presentation)-1] + "~" + kbJWT, nil
}

// sdHashOf computes the sd_hash KB claim over an SD-JWT presentation
// part (RFC 9901 section 4.3.1: base64url(SHA-256(ASCII(SD-JWT)))).
func sdHashOf(sdjwtPart string) string {
	sum := sha256.Sum256([]byte(sdjwtPart))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// verifiedPayload verifies the issuer JWT and decodes its claims.
func verifiedPayload(verifier token.Verifier, rawJWT string) (map[string]any, error) {
	var payload map[string]any
	if err := verifier.Claims(context.TODO(), rawJWT, &payload); err != nil {
		return nil, fmt.Errorf("unable to verify issuer-signed jwt: %w", err)
	}
	return payload, nil
}

// checkSDAlg enforces the sha-256-only posture on _sd_alg: absent
// defaults to sha-256 (RFC 9901 section 7.1 step 6), any other value is
// rejected.
func checkSDAlg(payload map[string]any) error {
	v, has := payload[ClaimSDAlg]
	if !has {
		return nil
	}
	alg, isString := v.(string)
	if !isString {
		return fmt.Errorf("%w: %q is not a string", sdtoken.ErrUnsupportedHashAlgorithm, ClaimSDAlg)
	}
	if HashAlgorithm(alg) != HashSHA256 {
		return fmt.Errorf("%w: %q", sdtoken.ErrUnsupportedHashAlgorithm, alg)
	}
	return nil
}

// checkTemporal validates exp/nbf of the processed payload with the
// given leeway (RFC 9901 section 7.1 step 6).
func checkTemporal(payload map[string]any, now time.Time, leeway int64) error {
	if v, has := payload["exp"]; has {
		if exp, ok := numeric(v); ok && now.After(time.Unix(exp+leeway, 0)) {
			return fmt.Errorf("%w: token expired", ErrInvalidSDJWT)
		}
	}
	if v, has := payload["nbf"]; has {
		if nbf, ok := numeric(v); ok && now.Before(time.Unix(nbf-leeway, 0)) {
			return fmt.Errorf("%w: token not yet valid", ErrInvalidSDJWT)
		}
	}
	return nil
}

// numeric coerces a JSON numeric claim to int64.
func numeric(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	default:
		return 0, false
	}
}
