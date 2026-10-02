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
	"reflect"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/sdtoken"
	"zntr.io/solid/sdk/token/cwt"
)

// issuer assembles the draft-ietf-spice-sd-cwt-08 Issuer role.
type issuer struct {
	alg         cose.Algorithm
	keyProvider jwk.KeyProviderFunc
}

// NewIssuer returns an SD-CWT Issuer. The signing key is resolved
// through the key provider (AKP/ML-DSA handled by cwt.ResolveSigningKey)
// and the algorithm allowlist is enforced (cwt.EnforceAlgorithmAllowlist).
func NewIssuer(alg cose.Algorithm, keyProvider jwk.KeyProviderFunc) Issuer {
	return &issuer{
		alg:         alg,
		keyProvider: keyProvider,
	}
}

// Issue implements the SD-CWT issuance algorithm: deterministic walk,
// per-level redacted_claim_keys arrays (simple 59) with decoy
// disclosures, tag-60 redacted elements, all protected/typ/sd_alg
// headers, COSE_Sign1 with tag 18, disclosures in the unprotected
// sd_claims (17) header.
func (i *issuer) Issue(ctx context.Context, claims map[any]any, opts ...IssueOption) (sdcwt []byte, disclosures [][]byte, err error) {
	if claims == nil {
		return nil, nil, ErrInvalidSDCWT
	}

	cfg := newIssueConfig(opts...)
	if cfg.saltFactory == nil {
		cfg.saltFactory = sdtoken.NewSalt
	}

	// Enforce the algorithm allowlist before any work.
	if errAlg := cwt.EnforceAlgorithmAllowlist(i.alg); errAlg != nil {
		return nil, nil, errAlg
	}

	// Step 1: deterministic walk of the marker tree.
	sites, err := sdtoken.Walk(claims)
	if err != nil {
		return nil, nil, err
	}

	// redactedKeys tracks the per-map redacted_claim_keys digest arrays
	// (raw digest bytes for the CBOR wire), keyed by map pointer
	// identity; mapsByPtr remembers the owning maps for write-backs.
	redactedKeys := map[uintptr][][]byte{}
	mapsByPtr := map[uintptr]map[any]any{}
	var elementArrays []elementArrayAddress
	// Step 2: per site (children before parents), encode the disclosure
	// and replace the marker with its digest.
	disclosures, errDisclosures := encodeCWTWalkSites(sites, cfg, redactedKeys, mapsByPtr, &elementArrays)
	if errDisclosures != nil {
		return nil, nil, errDisclosures
	}

	// Step 3: decoy digests (draft section 10): each decoy adds a
	// digest AND a 1-element decoy disclosure the holder must hold.
	if cfg.decoys > 0 {
		if errDecoys := addCBORDecoys(cfg, redactedKeys, mapsByPtr, elementArrays, &disclosures); errDecoys != nil {
			return nil, nil, errDecoys
		}
	}

	// Step 4-5: resolve the signing key and build the COSE signer
	// (AKP/ML-DSA aware), then the headers.
	signer, kid, err := i.coseSigner(ctx)
	if err != nil {
		return nil, nil, err
	}

	// Step 5: headers — protected alg/kid/typ(293)/sd_alg(-16),
	// unprotected sd_claims (bstr disclosures).
	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: i.alg,
			cose.HeaderLabelKeyID:     []byte(kid),
			cose.HeaderLabelType:      MediaTypeSdCWT,
			HeaderLabelSdAlg:          HashAlgSHA256,
		},
		Unprotected: cose.UnprotectedHeader{
			HeaderLabelSdClaims: disclosures,
		},
	}

	// Step 6: marshal claims as CBOR payload.
	payload, err := cbor.Marshal(claims)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to serialize claims as CBOR: %w", err)
	}

	// Step 7: sign (no external AAD) and marshal as COSE_Sign1 tag 18.
	msg := cose.Sign1Message{
		Headers: headers,
		Payload: payload,
	}
	if err = msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, nil, fmt.Errorf("unable to sign sd-cwt: %w", err)
	}
	assertion, err := msg.MarshalCBOR()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to marshal sd-cwt: %w", err)
	}

	return assertion, disclosures, nil
}

// coseSigner resolves the signing key (AKP/ML-DSA aware, mirroring
// sdk/token/cwt/signer.go) and builds the COSE signer for the
// configured algorithm.
func (i *issuer) coseSigner(ctx context.Context) (cose.Signer, string, error) {
	keySigner, kid, err := cwt.ResolveSigningKey(ctx, i.keyProvider)
	if err != nil {
		return nil, "", err
	}

	if akp, isAKP := keySigner.(*jwk.MLDSAKey); isAKP {
		signer, errSigner := cwt.CoseSignerMLDSAForKey(akp)
		return signer, kid, errSigner
	}

	cryptoSigner, isCryptoSigner := keySigner.(crypto.Signer)
	if !isCryptoSigner {
		return nil, "", fmt.Errorf("unable to materialize signing key: unsupported key type %T", keySigner)
	}
	signer, err := cose.NewSigner(i.alg, cryptoSigner)
	if err != nil {
		return nil, "", fmt.Errorf("unable to initialize COSE signer: %w", err)
	}
	return signer, kid, nil
}

// encodeCWTWalkSites encodes one disclosure per walk site (children
// before parents), replacing each marker with its raw digest in the
// tree.
func encodeCWTWalkSites(sites []sdtoken.WalkSite, cfg *issueConfig, redactedKeys map[uintptr][][]byte, mapsByPtr map[uintptr]map[any]any, elementArrays *[]elementArrayAddress) ([][]byte, error) {
	var disclosures [][]byte
	for _, site := range sites {
		salt, errSalt := cfg.saltFactory()
		if errSalt != nil {
			return nil, fmt.Errorf("unable to generate disclosure salt: %w", errSalt)
		}

		var wire, rawDigest []byte
		var errEnc error
		if site.IsElement {
			wire, rawDigest, errEnc = encodeDisclosure(salt, nil, site.Value)
		} else {
			wire, rawDigest, errEnc = encodeDisclosure(salt, site.MapKey, site.Value)
		}
		if errEnc != nil {
			return nil, errEnc
		}

		disclosures = append(disclosures, wire)

		if errReplace := replaceMarker(site, rawDigest, redactedKeys, mapsByPtr, elementArrays); errReplace != nil {
			return nil, errReplace
		}
	}
	return disclosures, nil
}

// replaceMarker rewrites the marker value at a walk site for CBOR:
// map values are removed and their raw digest collected into the
// parent map's redacted_claim_keys (simple 59) array; array elements
// become tag 60(digest bstr).
func replaceMarker(site sdtoken.WalkSite, rawDigest []byte, redactedKeys map[uintptr][][]byte, mapsByPtr map[uintptr]map[any]any, elementArrays *[]elementArrayAddress) error {
	if site.IsElement {
		n := len(site.Path)
		if n < 2 {
			return fmt.Errorf("%w: element site path is too short", sdtoken.ErrInvalidDisclosure)
		}
		// The element's parent array lives at path[n-2]; its own
		// address is the pair before that: (map, key) or (array,
		// index). Only map-held arrays can be addressed for decoy
		// write-backs; nested arrays inside arrays are extended via
		// their enclosing address when reachable.
		arr, ok := site.Path[n-2].([]any)
		if !ok {
			return fmt.Errorf("%w: element site container is not an array", sdtoken.ErrInvalidDisclosure)
		}
		index, ok := site.Path[n-1].(int)
		if !ok || index < 0 || index >= len(arr) {
			return fmt.Errorf("%w: element site index is invalid", sdtoken.ErrInvalidDisclosure)
		}
		arr[index] = cbor.Tag{Number: 60, Content: rawDigest}

		// Record the (parent map, key) address of this array for
		// decoy write-backs when the array is a map value.
		if n >= 4 {
			if holder, isMap := site.Path[n-4].(map[any]any); isMap {
				if key, isKey := site.Path[n-3].(string); isKey {
					*elementArrays = append(*elementArrays, elementArrayAddress{
						parent: holder,
						key:    key,
						ptr:    slicePointer(arr),
					})
				}
			}
		}
		return nil
	}

	n := len(site.Path)
	if n < 2 {
		return fmt.Errorf("%w: map site path is too short", sdtoken.ErrInvalidDisclosure)
	}
	m, ok := site.Path[n-2].(map[any]any)
	if !ok {
		return fmt.Errorf("%w: map site container is not a map", sdtoken.ErrInvalidDisclosure)
	}
	key := site.Path[n-1]

	// Remove the plaintext key/value.
	delete(m, key)
	mapPtr := mapPointer(m)

	// The CBOR wire carries raw digest bytes.
	redactedKeys[mapPtr] = append(redactedKeys[mapPtr], rawDigest)
	mapsByPtr[mapPtr] = m

	// Write back immediately: parent disclosures encode this map's
	// value (children before parents).
	if _, has := m[redactedClaimKeysMarker]; !has {
		m[redactedClaimKeysMarker] = []any{}
	}
	m[redactedClaimKeysMarker] = toAnySlice(redactedKeys[mapPtr])

	return nil
}

// addCBORDecoys appends n decoy digests per redacted_claim_keys array
// and per array containing tag-60 elements; each decoy also appends a
// 1-element decoy disclosure (draft section 10).
func addCBORDecoys(cfg *issueConfig, redactedKeys map[uintptr][][]byte, mapsByPtr map[uintptr]map[any]any, elementArrays []elementArrayAddress, disclosures *[][]byte) error {
	for ptr, arr := range redactedKeys {
		extended := arr
		for range cfg.decoys {
			salt, err := cfg.saltFactory()
			if err != nil {
				return fmt.Errorf("unable to generate decoy salt: %w", err)
			}
			digest, errDecoy := decoyDigest(salt)
			if errDecoy != nil {
				return errDecoy
			}
			extended = append(extended, digest)
			wire, errWire := cbor.Marshal([]any{salt})
			if errWire != nil {
				return fmt.Errorf("unable to encode decoy disclosure: %w", errWire)
			}
			*disclosures = append(*disclosures, wire)
		}
		redactedKeys[ptr] = extended
		if m, ok := mapsByPtr[ptr]; ok {
			m[redactedClaimKeysMarker] = toAnySlice(extended)
		}
	}
	// Element arrays: addressed by (owning map, claim key) so the
	// extension writes back into the live tree (slice headers passed
	// by value cannot grow in place).
	seenArrays := map[uintptr]struct{}{}
	for _, addr := range elementArrays {
		if _, seen := seenArrays[addr.ptr]; seen {
			continue
		}
		seenArrays[addr.ptr] = struct{}{}
		arr, ok := addr.parent[addr.key].([]any)
		if !ok {
			continue
		}
		for range cfg.decoys {
			salt, err := cfg.saltFactory()
			if err != nil {
				return fmt.Errorf("unable to generate decoy salt: %w", err)
			}
			digest, errDecoy := decoyDigest(salt)
			if errDecoy != nil {
				return errDecoy
			}
			arr = append(arr, cbor.Tag{Number: 60, Content: digest})
			wire, errWire := cbor.Marshal([]any{salt})
			if errWire != nil {
				return fmt.Errorf("unable to encode decoy disclosure: %w", errWire)
			}
			*disclosures = append(*disclosures, wire)
		}
		addr.parent[addr.key] = arr
	}
	return nil
}

// elementArrayAddress names an array-valued claim by its owning map
// and key, so decoy extensions write back into the tree.
type elementArrayAddress struct {
	parent map[any]any
	key    any
	ptr    uintptr
}

// toAnySlice converts [][]byte to []any for the CBOR claim tree.
func toAnySlice(b [][]byte) []any {
	out := make([]any, len(b))
	for i, v := range b {
		out[i] = v
	}
	return out
}

// slicePointer returns the Go pointer identity of a []any for decoy
// deduplication.
func slicePointer(arr []any) uintptr {
	return reflect.ValueOf(arr).Pointer()
}

// mapPointer returns the Go pointer identity of a claims map (maps
// are not comparable as values, so pointer identity keys the
// per-level digest arrays).
func mapPointer(m map[any]any) uintptr {
	return reflect.ValueOf(m).Pointer()
}
