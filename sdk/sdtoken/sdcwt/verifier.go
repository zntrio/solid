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
	"fmt"
	"time"

	"github.com/veraison/go-cose"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/sdtoken"
)

// verifier assembles the draft-ietf-spice-sd-cwt-08 Verifier role
// (section 9). Audience and cnonce validation are mandatory.
type verifier struct {
	issuerKeys jwk.KeySetProviderFunc
	cfg        *verifyConfig
}

// NewVerifier returns an SD-CWT KBT Verifier. WithAudience and
// WithCnonceValidator are mandatory; Verify rejects the token when
// either is missing.
func NewVerifier(issuerKeys jwk.KeySetProviderFunc, opts ...VerifyOption) Verifier {
	return &verifier{
		issuerKeys: issuerKeys,
		cfg:        newVerifyConfig(opts...),
	}
}

// Verify implements the draft section 9 processing checklist and
// returns the Validated Disclosed Claims Set.
func (v *verifier) Verify(ctx context.Context, kbt []byte) (map[any]any, error) {
	// Mandatory options.
	if v.cfg.audience == "" {
		return nil, fmt.Errorf("%w: WithAudience is required", ErrMissingRequiredOption)
	}
	if v.cfg.cnonceValidator == nil {
		return nil, fmt.Errorf("%w: WithCnonceValidator is required", ErrMissingRequiredOption)
	}

	// Steps 1-2: parse the KBT (structural + header checks).
	kbtMsg, embedded, err := parseKBT(kbt)
	if err != nil {
		return nil, err
	}

	// Step 3: parse the embedded SD-CWT.
	sdMsg, sdClaims, err := verifySDCWT(embedded, v.issuerKeys)
	if err != nil {
		return nil, err
	}

	// Step 4 + payload constraints: holder key binding, structural
	// payload checks, forbidden claims.
	kbtClaims, err := verifyKBTBinding(kbtMsg, sdClaims)
	if err != nil {
		return nil, err
	}

	// Steps 5-6: cnonce (mandatory validator) and aud.
	if err := v.checkKBTAudCnonce(kbtClaims); err != nil {
		return nil, err
	}

	// Step 7: time-claim constraints.
	now := time.Now().Unix()
	leeway := int64(v.cfg.leeway.Seconds())
	if err := checkKBTTimeConstraints(kbtClaims, sdClaims, now, leeway); err != nil {
		return nil, err
	}

	// Step 8: disclosure processing.
	return processSDCWTDisclosures(sdMsg, sdClaims)
}

// parseKBT performs the structural and header checks on the KBT bytes
// (draft sections 5.1, 8) and returns the parsed message with the
// embedded SD-CWT bytes.
func parseKBT(kbt []byte) (*cose.Sign1Message, []byte, error) {
	// Structural constraints on the KBT bytes (draft section 5.1).
	if err := checkDefiniteLength(kbt); err != nil {
		return nil, nil, err
	}

	var kbtMsg cose.Sign1Message
	if err := kbtMsg.UnmarshalCBOR(kbt); err != nil {
		return nil, nil, fmt.Errorf("%w: unable to parse kbt: %w", ErrInvalidKBT, err)
	}

	// typ MUST be 294 / "application/kb+cwt" (draft section 8).
	if err := checkKBTType(kbtMsg.Headers.Protected); err != nil {
		return nil, nil, err
	}

	// kcwt (13) MUST be present and carry the embedded SD-CWT.
	kcwtAny, has := kbtMsg.Headers.Protected[int64(13)]
	if !has {
		return nil, nil, fmt.Errorf("%w: kbt carries no kcwt header", ErrInvalidKBT)
	}
	embedded, ok := kcwtAny.([]byte)
	if !ok || len(embedded) == 0 {
		return nil, nil, fmt.Errorf("%w: kbt kcwt is empty or not a bstr", ErrInvalidKBT)
	}

	// sd_claims in the KBT header, when present, must be empty: the
	// disclosures travel in the embedded SD-CWT (draft section 8).
	if rawClaims, hasClaims := kbtMsg.Headers.Unprotected[HeaderLabelSdClaims]; hasClaims {
		if arr, isArr := rawClaims.([]any); !isArr || len(arr) > 0 {
			return nil, nil, fmt.Errorf("%w: kbt sd_claims must be empty", ErrInvalidKBT)
		}
	}

	return &kbtMsg, embedded, nil
}

// verifyKBTBinding extracts the holder key from the SD-CWT cnf claim,
// verifies the KBT signature with it, and enforces the KBT payload
// structural constraints and the forbidden iss/sub rule.
func verifyKBTBinding(kbtMsg *cose.Sign1Message, sdClaims map[any]any) (map[any]any, error) {
	holderKey, holderAlg, err := confirmationKey(sdClaims)
	if err != nil {
		return nil, err
	}
	holderVerifier, err := cose.NewVerifier(holderAlg, holderKey)
	if err != nil {
		return nil, fmt.Errorf("%w: unable to initialize holder verifier: %w", ErrInvalidKBT, err)
	}
	if err = kbtMsg.Verify(nil, holderVerifier); err != nil {
		return nil, fmt.Errorf("%w: kbt signature verification failed: %w", ErrInvalidKBT, err)
	}

	// Decode the KBT payload with the structural constraints.
	kbtClaimsAny, err := enforceDuplicateMapKeys(kbtMsg.Payload)
	if err != nil {
		return nil, err
	}
	kbtClaims, ok := kbtClaimsAny.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("%w: kbt payload is not a claims map", ErrInvalidKBT)
	}
	if err := checkMapKeys(kbtClaims, 0); err != nil {
		return nil, err
	}

	// iss/sub MUST NOT appear in the KBT (draft section 8.1).
	for _, forbidden := range []any{uint64(1), uint64(2), "iss", "sub"} {
		if _, has := kbtClaims[forbidden]; has {
			return nil, fmt.Errorf("%w: kbt carries a forbidden iss/sub claim", ErrInvalidKBT)
		}
	}
	return kbtClaims, nil
}

// checkKBTAudCnonce enforces the mandatory cnonce validation and the
// audience match (draft section 9 steps 5-6).
func (v *verifier) checkKBTAudCnonce(kbtClaims map[any]any) error {
	cnonceAny, hasCnonce := kbtClaims[uint64(ClaimKeyCnonce)]
	if !hasCnonce {
		return fmt.Errorf("%w: kbt carries no cnonce claim", ErrInvalidKBT)
	}
	cnonce, ok := cnonceAny.([]byte)
	if !ok {
		return fmt.Errorf("%w: kbt cnonce is not a bstr", ErrInvalidKBT)
	}
	if err := v.cfg.cnonceValidator(cnonce); err != nil {
		return fmt.Errorf("%w: cnonce rejected: %w", ErrInvalidKBT, err)
	}

	audAny, hasAud := kbtClaims[uint64(ClaimKeyAud)]
	if !hasAud {
		return fmt.Errorf("%w: kbt carries no aud claim", ErrInvalidKBT)
	}
	aud, ok := audAny.(string)
	if !ok || aud != v.cfg.audience {
		return fmt.Errorf("%w: kbt audience mismatch", ErrInvalidKBT)
	}
	return nil
}

// processSDCWTDisclosures decodes the sd_claims disclosures from the
// embedded SD-CWT and runs order-independent verifier-semantics
// processing (draft section 9 step 8), returning the Validated
// Disclosed Claims Set.
func processSDCWTDisclosures(sdMsg *cose.Sign1Message, sdClaims map[any]any) (map[any]any, error) {
	rawDisclosures, hasDisclosures := sdMsg.Headers.Unprotected[HeaderLabelSdClaims]
	if !hasDisclosures {
		return nil, fmt.Errorf("%w: sd-cwt carries no sd_claims header", ErrInvalidSDCWT)
	}
	disclosureList, ok := rawDisclosures.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: sd_claims is not an array", ErrInvalidSDCWT)
	}
	if len(disclosureList) == 0 {
		// Draft section 9 step 2: an empty sd_claims array is invalid.
		return nil, fmt.Errorf("%w: sd_claims is empty", ErrInvalidSDCWT)
	}
	decoded := make([]sdtoken.DecodedDisclosure, 0, len(disclosureList))
	for _, d := range disclosureList {
		b, isBstr := d.([]byte)
		if !isBstr {
			return nil, fmt.Errorf("%w: sd_claims entry is not a bstr", ErrInvalidSDCWT)
		}
		dd, errDec := decodeDisclosure(b)
		if errDec != nil {
			return nil, errDec
		}
		decoded = append(decoded, dd)
	}

	// Order-independent processing with verifier semantics.
	processed, _, errProc := sdtoken.Process(cborAdapter{}, sdClaims, decoded, sdtoken.ProcessOptions{HolderSemantics: false})
	if errProc != nil {
		return nil, errProc
	}
	processed = pruneNilElements(processed)
	processedClaims, ok := processed.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("%w: processed claims are not a map", ErrInvalidSDCWT)
	}

	// Validated Disclosed Claims Set.
	return processedClaims, nil
}

// checkKBTTimeConstraints enforces the draft section 9 step 7
// checklist: iat-or-cti presence in the KBT; no KBT exp/nbf without
// iat; the nbf ≤ iat < exp inequalities; and the KBT ↔ SD-CWT
// cross-constraints (each delegated below).
func checkKBTTimeConstraints(kbt, sdcwtClaims map[any]any, now, leeway int64) error {
	if err := checkKBTInternalTime(kbt, now, leeway); err != nil {
		return err
	}
	return checkKBTCrossTime(kbt, sdcwtClaims, leeway)
}

// checkKBTInternalTime enforces the KBT-local time constraints:
// iat-or-cti presence, no exp/nbf without iat, and nbf ≤ iat < exp.
func checkKBTInternalTime(kbt map[any]any, now, leeway int64) error {
	// iat or cti REQUIRED (draft section 8.1).
	_, hasIat := kbt[uint64(ClaimKeyIat)]
	_, hasCti := kbt[uint64(ClaimKeyCti)]
	if !hasIat && !hasCti {
		return fmt.Errorf("%w: kbt carries neither iat nor cti", ErrInvalidKBT)
	}

	iat, hasIatValue := numericClaim(kbt[uint64(ClaimKeyIat)])
	_, hasExp := kbt[uint64(ClaimKeyExp)]
	_, hasNbf := kbt[uint64(ClaimKeyNbf)]

	// No KBT exp/nbf without iat.
	if hasExp && !hasIat {
		return fmt.Errorf("%w: kbt exp without iat", ErrInvalidKBT)
	}
	if hasNbf && !hasIat {
		return fmt.Errorf("%w: kbt nbf without iat", ErrInvalidKBT)
	}

	// KBT nbf ≤ iat.
	if nbf, ok := numericClaim(kbt[uint64(ClaimKeyNbf)]); ok && hasIatValue && nbf > iat+leeway {
		return fmt.Errorf("%w: kbt nbf after iat", ErrInvalidKBT)
	}
	// KBT iat < exp and exp in the future.
	if exp, ok := numericClaim(kbt[uint64(ClaimKeyExp)]); ok {
		if now > exp+leeway {
			return fmt.Errorf("%w: kbt expired", ErrInvalidKBT)
		}
		if hasIatValue && iat >= exp-leeway {
			return fmt.Errorf("%w: kbt iat not before exp", ErrInvalidKBT)
		}
	}
	return nil
}

// timeCrossCheck pairs one KBT claim against one SD-CWT claim with a
// relation test; ok reports whether both claims exist and decode.
type timeCrossCheck struct {
	kbtLabel    int64
	sdcwtLabel  int64
	description string
	// relation holds only when both values decode; leeway applies.
	relation func(kbtValue, sdcwtValue, leeway int64) bool
}

// checkKBTCrossTime enforces the KBT ↔ SD-CWT cross-constraints
// (draft section 9 step 7): expKBT ≤ expSDCWT, nbfKBT ≥ nbfSDCWT,
// iatKBT ≥ iatSDCWT, nbfKBT < expSDCWT, iatKBT < expSDCWT,
// iatKBT ≥ nbfSDCWT.
func checkKBTCrossTime(kbt, sdcwtClaims map[any]any, leeway int64) error {
	checks := []timeCrossCheck{
		{
			kbtLabel:    ClaimKeyExp,
			sdcwtLabel:  ClaimKeyExp,
			description: "kbt exp exceeds sd-cwt exp",
			relation:    func(kbtV, sdcwtV, l int64) bool { return kbtV > sdcwtV+l },
		},
		{
			kbtLabel:    ClaimKeyNbf,
			sdcwtLabel:  ClaimKeyNbf,
			description: "kbt nbf before sd-cwt nbf",
			relation:    func(kbtV, sdcwtV, l int64) bool { return kbtV+l < sdcwtV },
		},
		{
			kbtLabel:    ClaimKeyIat,
			sdcwtLabel:  ClaimKeyIat,
			description: "kbt iat before sd-cwt iat",
			relation:    func(kbtV, sdcwtV, l int64) bool { return kbtV+l < sdcwtV },
		},
		{
			kbtLabel:    ClaimKeyNbf,
			sdcwtLabel:  ClaimKeyExp,
			description: "kbt nbf not before sd-cwt exp",
			relation:    func(kbtV, sdcwtV, l int64) bool { return kbtV >= sdcwtV-l },
		},
		{
			kbtLabel:    ClaimKeyIat,
			sdcwtLabel:  ClaimKeyExp,
			description: "kbt iat not before sd-cwt exp",
			relation:    func(kbtV, sdcwtV, l int64) bool { return kbtV >= sdcwtV-l },
		},
		{
			kbtLabel:    ClaimKeyIat,
			sdcwtLabel:  ClaimKeyNbf,
			description: "kbt iat before sd-cwt nbf",
			relation:    func(kbtV, sdcwtV, l int64) bool { return kbtV+l < sdcwtV },
		},
	}
	for _, check := range checks {
		kbtValue, okK := numericClaim(kbt[claimKeyFor(check.kbtLabel)])
		sdcwtValue, okS := numericClaim(sdcwtClaims[claimKeyFor(check.sdcwtLabel)])
		if okK && okS && check.relation(kbtValue, sdcwtValue, leeway) {
			return fmt.Errorf("%w: %s", ErrInvalidKBT, check.description)
		}
	}
	return nil
}

// numericClaim coerces a CBOR numeric claim to int64.
func numericClaim(v any) (int64, bool) {
	switch n := v.(type) {
	case uint64:
		if n > 1<<62 {
			return 0, false
		}
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	case float64:
		return int64(n), true
	default:
		return 0, false
	}
}

// compile-time interface guards.
var (
	_ Verifier = (*verifier)(nil)
	_ Holder   = (*holder)(nil)
	_ Issuer   = (*issuer)(nil)
)

// claimKeyFor normalizes a non-negative claim label constant into the
// uint64 encoding used by CBOR-decoded claim maps.
func claimKeyFor(label int64) uint64 {
	if label < 0 {
		// Negative labels (alg-style) never index decoded claims;
		// callers only use positive CWT claim labels here.
		return 0
	}
	return uint64(label) // #nosec G115 -- guarded above
}
