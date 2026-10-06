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

package sdcwt

import (
	"context"
	"crypto"
	"crypto/rand"
	"fmt"

	cbor "github.com/fxamacker/cbor/v2"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/veraison/go-cose"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/sdtoken"
	"zntr.io/solid/sdk/token/cwt"
)

// holder assembles the draft-ietf-spice-sd-cwt-08 Holder role.
type holder struct {
	issuerKeys        jwk.KeySetProviderFunc
	holderAlg         cose.Algorithm
	holderKeyProvider jwk.KeyProviderFunc
}

// NewHolder returns an SD-CWT Holder: issuer signatures verify against
// issuerKeys; key binding tokens are signed with the holder key.
func NewHolder(issuerKeys jwk.KeySetProviderFunc, holderAlg cose.Algorithm, holderKeyProvider jwk.KeyProviderFunc) Holder {
	return &holder{
		issuerKeys:        issuerKeys,
		holderAlg:         holderAlg,
		holderKeyProvider: holderKeyProvider,
	}
}

// Present rebuilds the SD-CWT with only the selected disclosures in
// sd_claims (the unprotected header is not signed, so the issuer
// signature stays valid).
func (h *holder) Present(ctx context.Context, issued []byte, selected [][]byte) ([]byte, error) {
	_ = ctx // no context-dependent work: local crypto only
	// Parse and verify the issued SD-CWT.
	msg, _, err := verifySDCWT(issued, h.issuerKeys)
	if err != nil {
		return nil, err
	}

	// The selection must be a duplicate-free subset of the issued
	// disclosures.
	issuedRaw := msg.Headers.Unprotected[HeaderLabelSdClaims]
	issuedList, ok := issuedRaw.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: sd-cwt carries no sd_claims header", ErrInvalidSDCWT)
	}
	issuedSet := make(map[string]struct{}, len(issuedList))
	for _, d := range issuedList {
		if b, isBstr := d.([]byte); isBstr {
			issuedSet[sdtoken.DigestKey(b)] = struct{}{}
		}
	}
	seen := make(map[string]struct{}, len(selected))
	out := make([]any, 0, len(selected))
	for _, s := range selected {
		key := sdtoken.DigestKey(s)
		if _, ok := issuedSet[key]; !ok {
			return nil, fmt.Errorf("%w: selected disclosure is not part of the issued sd-cwt", ErrInvalidSDCWT)
		}
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("%w: selected disclosure presented twice", ErrInvalidSDCWT)
		}
		seen[key] = struct{}{}
		out = append(out, s)
	}

	// Rebuild the message with the selected sd_claims. The raw
	// unprotected header captured at decode time must be dropped, or
	// MarshalCBOR re-emits the original disclosure list verbatim.
	msg.Headers.RawUnprotected = nil
	msg.Headers.Unprotected = cose.UnprotectedHeader{
		HeaderLabelSdClaims: out,
	}
	presented, err := msg.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("unable to marshal presentation: %w", err)
	}

	return presented, nil
}

// KeyBind builds the KBT (draft section 8): a COSE_Sign1 with typ 294
// and kcwt (13) carrying the raw presentation bytes; payload holds
// aud (3), iat (6) or cti (7), cnonce (39); MUST NOT carry iss/sub.
func (h *holder) KeyBind(ctx context.Context, presentation []byte, audience string, cnonce []byte, opts ...KeyBindOption) ([]byte, error) {
	cfg := newKeyBindConfig(opts...)

	// Enforce the algorithm allowlist before resolving keys.
	if err := cwt.EnforceAlgorithmAllowlist(h.holderAlg); err != nil {
		return nil, err
	}

	// Resolve the holder signing key (AKP/ML-DSA aware).
	keySigner, kid, err := cwt.ResolveSigningKey(ctx, h.holderKeyProvider)
	if err != nil {
		return nil, err
	}

	var signer cose.Signer
	if akp, isAKP := keySigner.(*jwk.MLDSAKey); isAKP {
		signer, err = cwt.CoseSignerMLDSAForKey(akp)
		if err != nil {
			return nil, err
		}
	} else {
		cryptoSigner, isCryptoSigner := keySigner.(crypto.Signer)
		if !isCryptoSigner {
			return nil, fmt.Errorf("unable to materialize holder key: unsupported key type %T", keySigner)
		}
		signer, err = cose.NewSigner(h.holderAlg, cryptoSigner)
		if err != nil {
			return nil, fmt.Errorf("unable to initialize COSE signer: %w", err)
		}
	}

	// KBT payload (draft section 8.1): aud, iat or cti, cnonce. iss and
	// sub MUST NOT appear.
	payload := map[any]any{
		ClaimKeyAud:    audience,
		ClaimKeyCnonce: cnonce,
	}
	if len(cfg.cti) > 0 {
		payload[uint64(ClaimKeyCti)] = cfg.cti
	} else {
		payload[uint64(ClaimKeyIat)] = cfg.issuedAt
	}

	payloadBytes, err := cbor.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("unable to serialize kbt payload: %w", err)
	}

	// kcwt (13): embed the exact presentation bytes (RFC 9528).
	msg := cose.Sign1Message{
		Headers: cose.Headers{
			Protected: cose.ProtectedHeader{
				cose.HeaderLabelAlgorithm: h.holderAlg,
				cose.HeaderLabelKeyID:     []byte(kid),
				cose.HeaderLabelType:      MediaTypeKbCWT,
				int64(13):                 presentation,
			},
		},
		Payload: payloadBytes,
	}
	if err = msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, fmt.Errorf("unable to sign kbt: %w", err)
	}
	kbt, err := msg.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("unable to marshal kbt: %w", err)
	}

	return kbt, nil
}

// verifySDCWT parses a COSE_Sign1 SD-CWT, checks the typ and sd_alg
// headers, enforces the structural constraints, and verifies the
// signature against the candidate keys of the issuer set. The typ is
// the SD-CWT media type (293 / "application/sd-cwt").
func verifySDCWT(raw []byte, issuerKeys jwk.KeySetProviderFunc) (*cose.Sign1Message, map[any]any, error) {
	return verifySDCWTWithType(raw, issuerKeys, checkSDCWTType)
}

// verifySDCWTWithType is verifySDCWT with a pluggable typ check: the
// draft-forten profile tokens keep their ordinary media type
// ("application/at+cwt" / "application/id+cwt"), so the profile
// adapter passes its own check.
func verifySDCWTWithType(raw []byte, issuerKeys jwk.KeySetProviderFunc, checkTyp func(cose.ProtectedHeader) error) (*cose.Sign1Message, map[any]any, error) {
	// Structural constraints first (draft section 5).
	if err := checkDefiniteLength(raw); err != nil {
		return nil, nil, err
	}

	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(raw); err != nil {
		return nil, nil, fmt.Errorf("%w: unable to parse COSE_Sign1: %w", ErrInvalidSDCWT, err)
	}

	// typ check (pluggable).
	if err := checkTyp(msg.Headers.Protected); err != nil {
		return nil, nil, err
	}

	// sd_alg MUST be -16 (or absent, meaning the default).
	if err := checkSDAlg(msg.Headers.Protected); err != nil {
		return nil, nil, err
	}

	// Resolve the algorithm and candidate keys.
	alg, err := msg.Headers.Protected.Algorithm()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: sd-cwt has no algorithm header", ErrInvalidSDCWT)
	}
	jwks, err := issuerKeys(context.Background())
	if err != nil {
		return nil, nil, fmt.Errorf("unable to retrieve issuer keys: %w", err)
	}
	keys := candidateSigningKeys(jwks)

	// Attempt verification with each candidate key.
	if !verifySign1WithAnyKey(&msg, keys, alg) {
		return nil, nil, fmt.Errorf("%w: invalid sd-cwt signature", ErrInvalidSDCWT)
	}

	// Decode the payload with duplicate-map-key enforcement and
	// structural checks (draft sections 5.2-5.5).
	claimsAny, err := enforceDuplicateMapKeys(msg.Payload)
	if err != nil {
		return nil, nil, err
	}
	claims, ok := claimsAny.(map[any]any)
	if !ok {
		return nil, nil, fmt.Errorf("%w: sd-cwt payload is not a claims map", ErrInvalidSDCWT)
	}
	if err := checkMapKeys(claims, 0); err != nil {
		return nil, nil, err
	}
	if err := checkDateClaims(claims); err != nil {
		return nil, nil, err
	}

	return &msg, claims, nil
}

// checkSDCWTType enforces the SD-CWT typ header values (293 or
// "application/sd-cwt"; draft section 4). fxamacker decodes CBOR
// unsigned ints in any-typed headers as int64.
func checkSDCWTType(ph cose.ProtectedHeader) error {
	switch v := ph[cose.HeaderLabelType].(type) {
	case int64:
		if v == int64(MediaTypeSdCWT) {
			return nil
		}
	case uint64:
		if v == uint64(MediaTypeSdCWT) {
			return nil
		}
	case uint:
		if v == MediaTypeSdCWT {
			return nil
		}
	case string:
		if v == "application/sd-cwt" {
			return nil
		}
	}
	return fmt.Errorf("%w: invalid sd-cwt typ", ErrInvalidSDCWT)
}

// checkKBTType enforces the KBT typ header values (294 or
// "application/kb+cwt"; draft section 8).
func checkKBTType(ph cose.ProtectedHeader) error {
	switch v := ph[cose.HeaderLabelType].(type) {
	case int64:
		if v == int64(MediaTypeKbCWT) {
			return nil
		}
	case uint64:
		if v == uint64(MediaTypeKbCWT) {
			return nil
		}
	case uint:
		if v == MediaTypeKbCWT {
			return nil
		}
	case string:
		if v == "application/kb+cwt" {
			return nil
		}
	}
	return fmt.Errorf("%w: invalid kbt typ", ErrInvalidKBT)
}

// materializePublicKey converts a jwk key into a native Go public key
// consumable by go-cose verifiers.
func materializePublicKey(k jwk.Key) (crypto.PublicKey, error) {
	pub, err := jwxjwk.PublicKeyOf(k)
	if err != nil {
		return nil, fmt.Errorf("unable to derive public key: %w", err)
	}
	var raw crypto.PublicKey
	if err := jwxjwk.Export(pub, &raw); err != nil {
		return nil, fmt.Errorf("unable to materialize public key: %w", err)
	}
	return raw, nil
}

// candidateSigningKeys returns every signing (non-enc) key of the set.
func candidateSigningKeys(jwks jwk.Set) []jwk.Key {
	var keys []jwk.Key
	for i := range jwks.Len() {
		k, ok := jwks.Key(i)
		if !ok {
			continue
		}
		if use, hasUse := k.KeyUsage(); hasUse && use == "enc" {
			continue
		}
		keys = append(keys, k)
	}
	return keys
}

// verifySign1WithAnyKey attempts message verification with each
// candidate key until one verifies (mirrors sdk/token/cwt).
func verifySign1WithAnyKey(msg *cose.Sign1Message, keys []jwk.Key, alg cose.Algorithm) bool {
	for _, k := range keys {
		var verifier cose.Verifier
		if akp, isAKP := k.(*jwk.MLDSAKey); isAKP {
			v, errVerifier := cwt.CoseVerifierMLDSAForKey(akp)
			if errVerifier != nil {
				continue
			}
			verifier = v
		} else {
			publicKey, errKey := materializePublicKey(k)
			if errKey != nil {
				continue
			}
			v, errVerifier := cose.NewVerifier(alg, publicKey)
			if errVerifier != nil {
				continue
			}
			verifier = v
		}
		if errVerify := msg.Verify(nil, verifier); errVerify == nil {
			return true
		}
	}
	return false
}

// checkSDAlg enforces sd_alg ∈ {absent, -16} (draft section 9: -16
// designates sha-256, the only supported hash here).
func checkSDAlg(ph cose.ProtectedHeader) error {
	v, has := ph[HeaderLabelSdAlg]
	if !has {
		return nil // absent: sha-256 default (draft section 9)
	}
	switch alg := v.(type) {
	case int64:
		if alg == HashAlgSHA256 {
			return nil
		}
	case int:
		if int64(alg) == HashAlgSHA256 {
			return nil
		}
	}
	return fmt.Errorf("%w: unsupported sd_alg", ErrInvalidSDCWT)
}
