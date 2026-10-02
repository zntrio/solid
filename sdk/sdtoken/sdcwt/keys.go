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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"fmt"

	"github.com/veraison/go-cose"
)

// Confirmation builds the COSE-native cnf claim map (draft: cnf is
// claim 8 carrying {1: COSE_Key}) from a native public key: EC2 for
// P-256/384/521 ecdsa keys, OKP for Ed25519. Anything else is an
// error (the project's asymmetric-only posture already excludes RSA).
func Confirmation(pub crypto.PublicKey) (map[any]any, error) {
	switch typed := pub.(type) {
	case *ecdsa.PublicKey:
		// Uncompressed point encoding (0x04 || X || Y) via the modern
		// API: no raw coordinate access (deprecated in Go 1.26).
		uncompressed, err := typed.Bytes()
		if err != nil {
			return nil, fmt.Errorf("unable to encode public key: %w", err)
		}
		crv, err := ec2CurveLabel(typed.Curve)
		if err != nil {
			return nil, err
		}
		byteLen := (len(uncompressed) - 1) / 2
		x := append([]byte(nil), uncompressed[1:1+byteLen]...)
		y := append([]byte(nil), uncompressed[1+byteLen:]...)
		// EC2 key: {1: 2, -1: crv, -2: x, -3: y} (RFC 9053 section 2).
		return map[any]any{
			ClaimKeyCwtCoseKey: map[any]any{
				1:  2,
				-1: crv,
				-2: x,
				-3: y,
			},
		}, nil
	case ed25519.PublicKey:
		if len(typed) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid ed25519 public key size")
		}
		// OKP key: {1: 1, -1: 6, -2: pub} (RFC 9053 section 2).
		return map[any]any{
			ClaimKeyCwtCoseKey: map[any]any{
				1:  1,
				-1: 6,
				-2: []byte(typed),
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported confirmation key type %T", pub)
	}
}

// ec2CurveLabel maps a curve to the COSE EC2 crv label.
func ec2CurveLabel(curve elliptic.Curve) (int64, error) {
	switch curve {
	case elliptic.P256():
		return 1, nil
	case elliptic.P384():
		return 2, nil
	case elliptic.P521():
		return 3, nil
	default:
		return 0, fmt.Errorf("unsupported elliptic curve %v", curve.Params().Name)
	}
}

// confirmationKey is the inverse of Confirmation: extract the holder
// public key (and its COSE algorithm) from the cnf claim of a claims
// map (draft section 9 step 4).
//
// Claim maps mix integer encodings: Go-built maps carry int keys,
// CBOR-decoded ones int64 (negative labels) / uint64 (positive
// labels). All lookups go through lookupClaim, which normalizes.
func confirmationKey(claims map[any]any) (crypto.PublicKey, cose.Algorithm, error) {
	cnf := lookupClaim(claims, ClaimKeyCnf)
	if cnf == nil {
		return nil, 0, fmt.Errorf("%w: claims carry no cnf claim", ErrInvalidSDCWT)
	}
	cnfMap, ok := cnf.(map[any]any)
	if !ok {
		return nil, 0, fmt.Errorf("%w: cnf claim is not a map", ErrInvalidSDCWT)
	}
	coseKeyClaim := lookupClaim(cnfMap, ClaimKeyCwtCoseKey)
	if coseKeyClaim == nil {
		return nil, 0, fmt.Errorf("%w: cnf carries no COSE_Key", ErrInvalidSDCWT)
	}
	keyMap, ok := coseKeyClaim.(map[any]any)
	if !ok {
		return nil, 0, fmt.Errorf("%w: cnf COSE_Key is not a map", ErrInvalidSDCWT)
	}

	// Key type (1): 2 = EC2, 1 = OKP.
	kty, ok := lookupInt(keyMap, 1)
	if !ok {
		return nil, 0, fmt.Errorf("%w: COSE_Key carries no key type", ErrInvalidSDCWT)
	}
	switch kty {
	case 2:
		return ec2Key(keyMap)
	case 1:
		return okpKey(keyMap)
	default:
		return nil, 0, fmt.Errorf("%w: unsupported COSE key type %d", ErrInvalidSDCWT, kty)
	}
}

// lookupClaim finds a claim under an integer label, accepting the int,
// int64 and uint64 encodings of the same label across Go-built and
// CBOR-decoded claim maps. Returns nil when absent.
func lookupClaim(m map[any]any, label int64) any {
	for k, v := range m {
		switch kk := k.(type) {
		case int:
			if int64(kk) == label {
				return v
			}
		case int64:
			if kk == label {
				return v
			}
		case uint64:
			if kk <= 1<<62 && int64(kk) == label { // #nosec G115 -- bounded by the 1<<62 guard
				return v
			}
		}
	}
	return nil
}

// lookupInt finds an integer claim under an integer label.
func lookupInt(m map[any]any, label int64) (int64, bool) {
	v := lookupClaim(m, label)
	if v == nil {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case uint64:
		if n > 1<<62 {
			return 0, false
		}
		return int64(n), true // #nosec G115 -- bounded by the 1<<62 guard above
	default:
		return 0, false
	}
}

// ec2Key builds an ECDSA public key from an EC2 COSE key map. The
// point is reconstructed through ecdsa.ParseUncompressedPublicKey,
// which validates on-curve membership (no deprecated raw coordinate
// handling).
func ec2Key(keyMap map[any]any) (crypto.PublicKey, cose.Algorithm, error) {
	crv, ok := lookupInt(keyMap, -1)
	if !ok {
		return nil, 0, fmt.Errorf("%w: EC2 key carries no curve", ErrInvalidSDCWT)
	}
	xAny := lookupClaim(keyMap, -2)
	yAny := lookupClaim(keyMap, -3)
	if xAny == nil || yAny == nil {
		return nil, 0, fmt.Errorf("%w: EC2 key misses coordinates", ErrInvalidSDCWT)
	}
	xBytes, okX := xAny.([]byte)
	yBytes, okY := yAny.([]byte)
	if !okX || !okY {
		return nil, 0, fmt.Errorf("%w: EC2 coordinates are not bstr", ErrInvalidSDCWT)
	}
	var curve elliptic.Curve
	var alg cose.Algorithm
	switch crv {
	case 1:
		curve, alg = elliptic.P256(), cose.AlgorithmES256
	case 2:
		curve, alg = elliptic.P384(), cose.AlgorithmES384
	case 3:
		curve, alg = elliptic.P521(), cose.AlgorithmES512
	default:
		return nil, 0, fmt.Errorf("%w: unsupported EC2 curve %d", ErrInvalidSDCWT, crv)
	}
	// Reassemble the uncompressed point and parse: on-curve and
	// coordinate-range validation happen inside the parser.
	byteLen := (curve.Params().BitSize + 7) / 8
	if len(xBytes) != byteLen || len(yBytes) != byteLen {
		return nil, 0, fmt.Errorf("%w: EC2 coordinates have wrong length", ErrInvalidSDCWT)
	}
	uncompressed := make([]byte, 1+2*byteLen)
	uncompressed[0] = 0x04
	copy(uncompressed[1:], xBytes)
	copy(uncompressed[1+byteLen:], yBytes)
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, uncompressed)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: invalid EC2 point: %w", ErrInvalidSDCWT, err)
	}
	return pub, alg, nil
}

// okpKey builds an Ed25519 public key from an OKP COSE key map.
func okpKey(keyMap map[any]any) (crypto.PublicKey, cose.Algorithm, error) {
	crv, ok := lookupInt(keyMap, -1)
	if !ok || crv != 6 {
		return nil, 0, fmt.Errorf("%w: unsupported OKP curve", ErrInvalidSDCWT)
	}
	pubAny := lookupClaim(keyMap, -2)
	if pubAny == nil {
		return nil, 0, fmt.Errorf("%w: OKP key misses public material", ErrInvalidSDCWT)
	}
	pubBytes, ok := pubAny.([]byte)
	if !ok || len(pubBytes) != ed25519.PublicKeySize {
		return nil, 0, fmt.Errorf("%w: invalid Ed25519 public material", ErrInvalidSDCWT)
	}
	return ed25519.PublicKey(pubBytes), cose.AlgorithmEdDSA, nil
}
