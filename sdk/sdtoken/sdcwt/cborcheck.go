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
	"fmt"
	"math"

	cbor "github.com/fxamacker/cbor/v2"

	"zntr.io/solid/sdk/sdtoken"
)

// maxClaimsDepth is the claims-map nesting bound (draft section 5.5:
// MAY reject deeper structures; enforced defensively).
const maxClaimsDepth = 16

// maxTextKeyLen bounds text-string claim keys (draft section 5.3).
const maxTextKeyLen = 255

// maxNumericDateAbs bounds numeric date claim values (draft section
// 5.2: |v| ≤ 2^53).
const maxNumericDateAbs = 1 << 53

// dupMapKeyDecMode rejects duplicate map keys during decode (draft
// section 5.4), including preferred-encoding equivalence.
var dupMapKeyDecMode = func() cbor.DecMode {
	dm, err := cbor.DecOptions{
		DupMapKey: cbor.DupMapKeyEnforcedAPF,
	}.DecMode()
	if err != nil {
		// DupMapKeyEnforcedAPF is a compile-time-constant option of
		// fxamacker/cbor v2.9.4: construction cannot fail.
		panic(fmt.Sprintf("unable to build duplicate-map-key decode mode: %v", err))
	}
	return dm
}()

// checkMapKeys enforces the draft section 5 constraints on a decoded
// claims tree: map keys only uint64/int64/string (≤255 bytes) plus the
// simple(59) container marker, nesting depth ≤ 16, no NaN/Inf and
// |numeric dates| ≤ 2^53, no nested tags in map keys.
func checkMapKeys(v any, depth int) error {
	if depth > maxClaimsDepth {
		return fmt.Errorf("%w: claims nesting deeper than %d levels", ErrInvalidSDCWT, maxClaimsDepth)
	}
	switch typed := v.(type) {
	case map[any]any:
		for k, val := range typed {
			if err := checkClaimKey(k); err != nil {
				return err
			}
			if err := checkMapKeys(val, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, elem := range typed {
			if err := checkMapKeys(elem, depth); err != nil {
				return err
			}
		}
	case cbor.Tag:
		// Tagged values: validate the content (tag 60 redactions are
		// handled by the adapter; other tags pass through).
		return checkMapKeys(typed.Content, depth)
	case float64:
		if isNaNOrInf(typed) {
			return fmt.Errorf("%w: NaN or infinite claim value", ErrInvalidSDCWT)
		}
		if absFloat(typed) > maxNumericDateAbs {
			return fmt.Errorf("%w: numeric value magnitude exceeds 2^53", ErrInvalidSDCWT)
		}
	}
	return nil
}

// checkClaimKey enforces the draft section 5.3 key constraints: uint64,
// int64, or string ≤ 255 bytes; the simple(59) container marker; no
// nested tags, no bstr/float keys.
func checkClaimKey(k any) error {
	// The redacted_claim_keys container marker is legal as a map key
	// at any claims level.
	if sv, isSimple := k.(cbor.SimpleValue); isSimple && uint8(sv) == uint8(redactedClaimKeysMarker) {
		return nil
	}
	switch typed := k.(type) {
	case uint64, int64:
		return nil
	case string:
		if len(typed) > maxTextKeyLen {
			return fmt.Errorf("%w: text claim key exceeds %d bytes", ErrInvalidSDCWT, maxTextKeyLen)
		}
		return nil
	case cbor.Tag:
		return fmt.Errorf("%w: nested tag in map key", ErrInvalidSDCWT)
	default:
		return fmt.Errorf("%w: invalid map key type %T", ErrInvalidSDCWT, k)
	}
}

// checkDateClaims enforces the draft section 5.2 numeric-date
// constraints on the recognized CWT date claims.
func checkDateClaims(claims map[any]any) error {
	for _, label := range []any{ClaimKeyExp, ClaimKeyNbf, ClaimKeyIat} {
		if v, has := claims[label]; has {
			f, isFloat := v.(float64)
			if !isFloat {
				// Integers are preferred encodings; uint64/int64 are
				// always within 2^53 when they came from valid CBOR
				// claims. Validate anyway for float64-encoded dates.
				continue
			}
			if isNaNOrInf(f) {
				return fmt.Errorf("%w: date claim %v is NaN or infinite", ErrInvalidSDCWT, label)
			}
			if absFloat(f) > maxNumericDateAbs {
				return fmt.Errorf("%w: date claim %v magnitude exceeds 2^53", ErrInvalidSDCWT, label)
			}
		}
	}
	return nil
}

func isNaNOrInf(f float64) bool {
	return math.IsNaN(f) || math.IsInf(f, 0)
}

func absFloat(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}

// enforceDuplicateMapKeys decodes raw CBOR with duplicate-map-key
// rejection (draft section 5.4), returning the decoded tree.
func enforceDuplicateMapKeys(raw []byte) (any, error) {
	var out any
	if err := dupMapKeyDecMode.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("%w: duplicate map key or invalid CBOR: %w", ErrInvalidSDCWT, err)
	}
	return out, nil
}

// compile-time check: the adapter satisfies the core contract.
var _ sdtoken.FormatAdapter = cborAdapter{}
