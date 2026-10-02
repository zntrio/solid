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
	"encoding/base64"
	"fmt"
	"unicode/utf8"

	cbor "github.com/fxamacker/cbor/v2"

	"zntr.io/solid/sdk/sdtoken"
)

// redactedClaimKeysMarker is the simple(59) map key naming a
// redacted_claim_keys array (draft section 4).
var redactedClaimKeysMarker = cbor.SimpleValue(59)

// encodeDisclosure serializes a CBOR Salted Disclosed Claim (draft
// section 4.1): the element form is [bstr(16), value], the map form is
// [bstr(16), value, claimKey] (salt, value, claim — Figure 12). The
// digest is the raw SHA-256 over the CBOR bytes (Figure 8), normalized
// internally via sdtoken.DigestKey.
func encodeDisclosure(salt []byte, key, value any) (wire, rawDigest []byte, err error) {
	if len(salt) != saltedClaimSaltLen {
		return nil, nil, fmt.Errorf("%w: salt must be %d bytes", sdtoken.ErrInvalidDisclosure, saltedClaimSaltLen)
	}

	// RFC 8949 section 3.1: text strings must be valid UTF-8;
	// fxamacker rejects invalid sequences on decode, so reject them
	// at encode time to keep the disclosure round-trippable.
	if validationErr := validateUTF8Strings(key, value); validationErr != nil {
		return nil, nil, validationErr
	}

	var arr []any
	if key == nil {
		arr = []any{salt, value}
	} else {
		if sdtoken.ReservedKey(key) {
			return nil, nil, fmt.Errorf("%w: claim key %v is reserved", sdtoken.ErrReservedClaimKey, key)
		}
		arr = []any{salt, value, key}
	}

	wireBytes, err := cbor.Marshal(arr)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to encode disclosure as CBOR: %w", err)
	}

	return wireBytes, sdtoken.Digest(wireBytes), nil
}

// decodeDisclosure parses a bstr-encoded Salted Disclosed Claim into
// the wire-agnostic core representation (draft sections 4.1, 10):
// 1-element arrays are decoys, 2-element the element form, 3-element
// the map claim form. Salts must be exactly 16 bytes.
func decodeDisclosure(b []byte) (sdtoken.DecodedDisclosure, error) {
	var arr []any
	if err := cbor.Unmarshal(b, &arr); err != nil {
		return sdtoken.DecodedDisclosure{}, fmt.Errorf("%w: disclosure is not a CBOR array", sdtoken.ErrInvalidDisclosure)
	}

	switch len(arr) {
	case 1, 2, 3:
	default:
		return sdtoken.DecodedDisclosure{}, fmt.Errorf("%w: disclosure array has %d elements", sdtoken.ErrInvalidDisclosure, len(arr))
	}

	salt, ok := arr[0].([]byte)
	if !ok || len(salt) != saltedClaimSaltLen {
		return sdtoken.DecodedDisclosure{}, fmt.Errorf("%w: disclosure salt is not a 16-byte bstr", sdtoken.ErrInvalidDisclosure)
	}

	out := sdtoken.DecodedDisclosure{
		Salt: salt,
		Wire: b,
	}

	switch len(arr) {
	case 1:
		// Decoy disclosure (draft section 10): salt only.
		out.IsDecoy = true
	case 2:
		out.Value = arr[1]
	case 3:
		out.Value = arr[1]
		out.ClaimKey = arr[2]
		if sdtoken.ReservedKey(out.ClaimKey) {
			return sdtoken.DecodedDisclosure{}, fmt.Errorf("%w: disclosure claim key is reserved", sdtoken.ErrInvalidDisclosure)
		}
	}

	// Normalized digest lookup key over the exact wire bytes.
	out.Digest = sdtoken.DigestKey(b)

	return out, nil
}

// validateUTF8Strings rejects invalid UTF-8 in disclosure claim keys
// and string values (RFC 8949 section 3.1 text-string requirement;
// keeps the wire bytes decodable by strict CBOR decoders).
func validateUTF8Strings(items ...any) error {
	for _, item := range items {
		if s, isString := item.(string); isString {
			if !utf8.ValidString(s) {
				return fmt.Errorf("%w: text string is not valid UTF-8", sdtoken.ErrInvalidDisclosure)
			}
		}
	}
	return nil
}

// decoyDigest returns the raw SHA-256 digest of a decoy: computed
// over the 1-element CBOR array [bstr(salt)] (draft section 10). The
// normalized lookup key is derived by the caller.
func decoyDigest(salt []byte) ([]byte, error) {
	wire, err := cbor.Marshal([]any{salt})
	if err != nil {
		return nil, fmt.Errorf("unable to encode decoy as CBOR: %w", err)
	}
	return sdtoken.Digest(wire), nil
}

// cborAdapter implements sdtoken.FormatAdapter over map[any]any /
// []any claim trees (the CBOR form of draft-ietf-spice-sd-cwt-08).
type cborAdapter struct{}

// ClaimTreeDigestSites enumerates every simple(59) redacted_claim_keys
// array at any depth and every tag-60 element inside arrays.
func (cborAdapter) ClaimTreeDigestSites(root any) ([]sdtoken.RedactionSite, error) {
	var sites []sdtoken.RedactionSite
	walkCBORTree(root, func(container any, index int, kind sdtoken.SiteKind, digest string) {
		sites = append(sites, sdtoken.RedactionSite{
			Kind:   kind,
			Digest: digest,
			Parent: container,
			Index:  index,
		})
	})
	return sites, nil
}

// walkCBORTree visits every redaction site in the tree. KindMap sites
// report the map owning the simple(59) key; KindElement sites report
// the array containing the tag-60 element. Digests are raw SHA-256
// bytes on the wire; the normalized string form is derived via
// sdtoken.DigestKey-free base64url of the bstr (the tag content).
func walkCBORTree(node any, visit func(container any, index int, kind sdtoken.SiteKind, digest string)) {
	switch typed := node.(type) {
	case map[any]any:
		for k, v := range typed {
			if sv, isSimple := k.(cbor.SimpleValue); isSimple && uint8(sv) == uint8(redactedClaimKeysMarker) {
				if digests, ok := v.([]any); ok {
					for i, d := range digests {
						if digestBytes, isBstr := d.([]byte); isBstr {
							visit(typed, i, sdtoken.KindMap, digestKeyOfBytes(digestBytes))
						}
					}
				}
			}
			walkCBORTree(v, visit)
		}
	case []any:
		for i, elem := range typed {
			if tag, isTag := elem.(cbor.Tag); isTag && tag.Number == 60 {
				if digestBytes, isBstr := tag.Content.([]byte); isBstr {
					visit(typed, i, sdtoken.KindElement, digestKeyOfBytes(digestBytes))
				}
			}
			walkCBORTree(elem, visit)
		}
	}
}

// digestKeyOfBytes normalizes a raw digest bstr into the engine lookup
// key: base64url of the raw SHA-256 bytes.
func digestKeyOfBytes(digest []byte) string {
	return base64URLEncode(digest)
}

// InsertMapClaim inserts key/value at the site's parent map, rejecting
// collisions.
func (cborAdapter) InsertMapClaim(site sdtoken.RedactionSite, key, value any) error {
	m, ok := site.Parent.(map[any]any)
	if !ok {
		return fmt.Errorf("%w: redaction site parent is not a map", sdtoken.ErrInvalidDisclosure)
	}
	if _, exists := m[key]; exists {
		return sdtoken.ErrClaimCollision
	}
	m[key] = value
	return nil
}

// ReplaceElement swaps the array element at the site for the disclosed
// value.
func (cborAdapter) ReplaceElement(site sdtoken.RedactionSite, value any) error {
	arr, ok := site.Parent.([]any)
	if !ok {
		return fmt.Errorf("%w: redaction site parent is not an array", sdtoken.ErrInvalidDisclosure)
	}
	if site.Index < 0 || site.Index >= len(arr) {
		return fmt.Errorf("%w: redaction site index out of range", sdtoken.ErrInvalidDisclosure)
	}
	arr[site.Index] = value
	return nil
}

// RemoveElement deletes an undisclosed redacted element from its array
// by replacing it with a nil sentinel; nils are compacted away by
// pruneNilElements at the end of processing.
func (cborAdapter) RemoveElement(site sdtoken.RedactionSite) error {
	arr, ok := site.Parent.([]any)
	if !ok {
		return fmt.Errorf("%w: redaction site parent is not an array", sdtoken.ErrInvalidDisclosure)
	}
	if site.Index < 0 || site.Index >= len(arr) {
		return fmt.Errorf("%w: redaction site index out of range", sdtoken.ErrInvalidDisclosure)
	}
	arr[site.Index] = nil
	return nil
}

// StripDigestContainer removes the simple(59) redacted_claim_keys
// entry from its parent map.
func (cborAdapter) StripDigestContainer(site sdtoken.RedactionSite) error {
	m, ok := site.Parent.(map[any]any)
	if !ok {
		return fmt.Errorf("%w: redaction site parent is not a map", sdtoken.ErrInvalidDisclosure)
	}
	delete(m, redactedClaimKeysMarker)
	return nil
}

// pruneNilElements compacts nil sentinels out of every array in the
// tree, depth-first, preserving order.
func pruneNilElements(node any) any {
	switch typed := node.(type) {
	case map[any]any:
		for k, v := range typed {
			typed[k] = pruneNilElements(v)
		}
		return typed
	case []any:
		out := typed[:0]
		for _, elem := range typed {
			if elem == nil {
				continue
			}
			out = append(out, pruneNilElements(elem))
		}
		return out
	default:
		return node
	}
}

func base64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
