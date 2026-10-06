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
	"encoding/base64"
	"fmt"
	"reflect"
	"sort"

	"zntr.io/solid/sdk/sdtoken"
	"zntr.io/solid/sdk/token"
)

// issuer assembles the RFC 9901 Issuer role over an injected JWT
// serializer (alg allowlist enforced at signer construction).
type issuer struct {
	signer token.Signer
}

// NewIssuer returns an SD-JWT Issuer (RFC 9901 section 5.1). The signer
// is injected by the caller, e.g. jwt.RawTypedSigner("vc+sd-jwt",
// "ES256", kp): typ values of RFC 9901 do not follow the "<base>+jwt"
// HeaderType derivation, hence RawTypedSigner.
func NewIssuer(signer token.Signer, _ ...IssueOption) Issuer {
	return &issuer{signer: signer}
}

// Issue implements the RFC 9901 section 5.1 issuance algorithm over the
// wire-agnostic core walk: inner markers before outer ones, digests
// collected into per-level _sd arrays (sorted lexicographically to hide
// claim order, section 4.2.4.1), decoy digests appended per array.
func (i *issuer) Issue(ctx context.Context, claims map[string]any, opts ...IssueOption) (sdjwt string, disclosures []string, err error) {
	if claims == nil {
		return "", nil, ErrInvalidSDJWT
	}

	cfg := newIssueConfig(opts...)
	if cfg.saltFactory == nil {
		cfg.saltFactory = sdtoken.NewSalt
	}

	// Step 1: deterministic walk of the marker tree.
	sites, err := sdtoken.Walk(claims)
	if err != nil {
		return "", nil, err
	}

	// digestArrays tracks the per-map _sd digest arrays, keyed by the
	// owning map's Go pointer identity (maps are not comparable as
	// values). mapsByPtr remembers the maps for write-backs; the array
	// form has no per-level array, redacted elements live inline as
	// {"...": digest}.
	digestArrays := map[uintptr][]string{}
	mapsByPtr := map[uintptr]map[string]any{}
	// Step 2: per site (children before parents), encode the disclosure
	// and replace the marker with its digest.
	disclosures, err = encodeWalkSites(sites, cfg, digestArrays, mapsByPtr)
	if err != nil {
		return "", nil, err
	}

	// Step 3: decoy digests — bare digests over base64url(random salt),
	// no disclosure object (RFC 9901 section 5.1).
	if cfg.decoys > 0 {
		if errDecoys := addJSONDecoys(cfg, digestArrays, mapsByPtr); errDecoys != nil {
			return "", nil, errDecoys
		}
	}

	// Step 4: sort every _sd array lexicographically and write it back
	// into the owning map (section 4.2.4.1: the order must not leak the
	// claim order).
	for ptr, arr := range digestArrays {
		sort.Strings(arr)
		if m, ok := mapsByPtr[ptr]; ok {
			m[ClaimSD] = arr
		}
	}

	// Step 5: always emit the hash algorithm (defensive explicitness,
	// RFC 9901 section 5.1.2).
	if _, exists := claims[ClaimSDAlg]; !exists {
		claims[ClaimSDAlg] = string(HashSHA256)
	}

	// Step 6: sign and assemble JWT~D1~...~Dn~ (trailing "~").
	signed, err := i.signer.Sign(ctx, claims)
	if err != nil {
		return "", nil, fmt.Errorf("unable to sign sd-jwt claims: %w", err)
	}

	out := signed
	for _, d := range disclosures {
		out += "~" + d
	}
	out += "~"

	return out, disclosures, nil
}

// encodeWalkSites encodes one disclosure per walk site (children before
// parents), replacing each marker with its digest in the tree.
func encodeWalkSites(sites []sdtoken.WalkSite, cfg *issueConfig, digestArrays map[uintptr][]string, mapsByPtr map[uintptr]map[string]any) ([]string, error) {
	var disclosures []string
	for _, site := range sites {
		salt, errSalt := cfg.saltFactory()
		if errSalt != nil {
			return nil, fmt.Errorf("unable to generate disclosure salt: %w", errSalt)
		}

		var wire, digestKey string
		var errEnc error
		if site.IsElement {
			wire, digestKey, errEnc = encodeDisclosure(salt, "", site.Value)
		} else {
			key, _ := site.MapKey.(string)
			wire, digestKey, errEnc = encodeDisclosure(salt, key, site.Value)
		}
		if errEnc != nil {
			return nil, errEnc
		}

		disclosures = append(disclosures, wire)

		if errReplace := replaceMarker(site, digestKey, digestArrays, mapsByPtr); errReplace != nil {
			return nil, errReplace
		}
	}
	return disclosures, nil
}

// replaceMarker rewrites the marker value at a walk site: map values are
// removed from their parent map and their digest collected into the
// parent's _sd array; array elements become {"...": digest}.
//
// The walk path stores, alternating: the container holding the marker
// (map or array), then the address (key or index) of the marker within
// it — children first, so the last pair addresses the marker itself.
// Children were already replaced inside the marker's value; the
// rewritten subtree now lives in the disclosure and the tree keeps only
// the digest reference.
func replaceMarker(site sdtoken.WalkSite, digestKey string, digestArrays map[uintptr][]string, mapsByPtr map[uintptr]map[string]any) error {
	if site.IsElement {
		// The path ends with (array, index) of the element marker.
		n := len(site.Path)
		if n < 2 {
			return fmt.Errorf("%w: element site path is too short", sdtoken.ErrInvalidDisclosure)
		}
		arr, ok := site.Path[n-2].([]any)
		if !ok {
			return fmt.Errorf("%w: element site container is not an array", sdtoken.ErrInvalidDisclosure)
		}
		index, ok := site.Path[n-1].(int)
		if !ok || index < 0 || index >= len(arr) {
			return fmt.Errorf("%w: element site index is invalid", sdtoken.ErrInvalidDisclosure)
		}
		arr[index] = map[string]any{arrayElementKey: digestKey}
		return nil
	}

	// Map form: the path ends with (map, key) of the marker value.
	n := len(site.Path)
	if n < 2 {
		return fmt.Errorf("%w: map site path is too short", sdtoken.ErrInvalidDisclosure)
	}
	m, ok := site.Path[n-2].(map[string]any)
	if !ok {
		return fmt.Errorf("%w: map site container is not a map", sdtoken.ErrInvalidDisclosure)
	}
	key, ok := site.Path[n-1].(string)
	if !ok {
		return fmt.Errorf("%w: map site key is not a string", sdtoken.ErrInvalidDisclosure)
	}

	// Remove the plaintext key/value: the claim moves into the
	// disclosure, the tree keeps the digest in the _sd array.
	delete(m, key)
	mapPtr := reflect.ValueOf(m).Pointer()
	digestArrays[mapPtr] = append(digestArrays[mapPtr], digestKey)
	mapsByPtr[mapPtr] = m

	// Write back immediately: parent disclosures encode this map's
	// value (children before parents), so the _sd array must already
	// carry this digest when an enclosing marker is serialized.
	m[ClaimSD] = digestArrays[mapPtr]

	return nil
}

// addJSONDecoys appends n decoy digests to every _sd array (RFC 9901
// section 5.1: bare digests over base64url(random salt), no disclosure
// object). The arrays are keyed by owning-map pointer identity; the
// parent maps are provided so the extension can be written back.
func addJSONDecoys(cfg *issueConfig, digestArrays map[uintptr][]string, mapsByPtr map[uintptr]map[string]any) error {
	for ptr, arr := range digestArrays {
		extended := arr
		for range cfg.decoys {
			salt, err := cfg.saltFactory()
			if err != nil {
				return fmt.Errorf("unable to generate decoy salt: %w", err)
			}
			extended = append(extended, sdtoken.DigestKey([]byte(base64URLEncode(salt))))
		}
		digestArrays[ptr] = extended
		if m, ok := mapsByPtr[ptr]; ok {
			m[ClaimSD] = extended
		}
	}
	return nil
}

func base64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
