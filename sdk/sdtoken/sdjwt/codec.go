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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"unicode/utf8"

	"zntr.io/solid/sdk/sdtoken"
)

// encodeDisclosure serializes a JSON disclosure (RFC 9901 section 4.2):
// the salt is rendered as the base64url string of the raw 128-bit salt,
// the array is ["<salt>","<key>",value] (map form) or ["<salt>",value]
// (element form), JSON-marshaled, then the UTF-8 bytes are base64url
// encoded to the wire form. The digest key is the normalized SHA-256
// lookup key over the wire bytes.
func encodeDisclosure(salt []byte, key string, value any) (wire, digestKey string, err error) {
	// Reject reserved claim keys: they would be ambiguous with the
	// redaction markers themselves.
	if sdtoken.ReservedKey(key) {
		return "", "", fmt.Errorf("%w: claim key %q is reserved", sdtoken.ErrReservedClaimKey, key)
	}

	// RFC 8259 JSON strings are Unicode: Go's encoding/json silently
	// replaces invalid UTF-8 with U+FFFD on marshal, which would break
	// digest round-trips — reject invalid sequences at encode time.
	if !utf8.ValidString(key) {
		return "", "", fmt.Errorf("%w: claim key is not valid UTF-8", sdtoken.ErrInvalidDisclosure)
	}
	if s, isString := value.(string); isString && !utf8.ValidString(s) {
		return "", "", fmt.Errorf("%w: claim value is not valid UTF-8", sdtoken.ErrInvalidDisclosure)
	}
	saltString := base64.RawURLEncoding.EncodeToString(salt)

	var arr []any
	if key == "" {
		// Element form: 2-element array.
		arr = []any{saltString, value}
	} else {
		// Map form: 3-element array.
		arr = []any{saltString, key, value}
	}

	// JSON object array encoding.
	jsonBytes, err := json.Marshal(arr)
	if err != nil {
		return "", "", fmt.Errorf("unable to encode disclosure as JSON: %w", err)
	}

	// base64url over the UTF-8 bytes (RFC 9901 section 4.2).
	wireString := base64.RawURLEncoding.EncodeToString(jsonBytes)

	// Digest over the exact wire bytes (US-ASCII of the base64url
	// string, RFC 9901 section 4.2.3).
	return wireString, sdtoken.DigestKey([]byte(wireString)), nil
}

// decodeDisclosure parses a base64url JSON disclosure into the
// wire-agnostic core representation (RFC 9901 section 7.1 step 3).
func decodeDisclosure(d string) (sdtoken.DecodedDisclosure, error) {
	jsonBytes, err := base64.RawURLEncoding.DecodeString(d)
	if err != nil {
		return sdtoken.DecodedDisclosure{}, fmt.Errorf("%w: disclosure is not base64url", sdtoken.ErrInvalidDisclosure)
	}

	var arr []any
	if err = json.Unmarshal(jsonBytes, &arr); err != nil {
		return sdtoken.DecodedDisclosure{}, fmt.Errorf("%w: disclosure is not a JSON array", sdtoken.ErrInvalidDisclosure)
	}

	switch len(arr) {
	case 2, 3:
	default:
		return sdtoken.DecodedDisclosure{}, fmt.Errorf("%w: disclosure array has %d elements", sdtoken.ErrInvalidDisclosure, len(arr))
	}

	// Salt is the first element: a base64url string decoding to the raw
	// 128-bit salt.
	saltString, ok := arr[0].(string)
	if !ok {
		return sdtoken.DecodedDisclosure{}, fmt.Errorf("%w: disclosure salt is not a string", sdtoken.ErrInvalidDisclosure)
	}
	salt, err := base64.RawURLEncoding.DecodeString(saltString)
	if err != nil {
		return sdtoken.DecodedDisclosure{}, fmt.Errorf("%w: disclosure salt is not base64url", sdtoken.ErrInvalidDisclosure)
	}

	out := sdtoken.DecodedDisclosure{
		Salt:  salt,
		Value: arr[len(arr)-1],
		Wire:  []byte(d),
	}
	if len(arr) == 3 {
		claimKey, isString := arr[1].(string)
		if !isString {
			return sdtoken.DecodedDisclosure{}, fmt.Errorf("%w: disclosure claim key is not a string", sdtoken.ErrInvalidDisclosure)
		}
		out.ClaimKey = claimKey
	}

	// Normalized digest lookup key over the exact wire bytes.
	out.Digest = sdtoken.DigestKey([]byte(d))

	return out, nil
}

// jsonAdapter implements sdtoken.FormatAdapter over map[string]any /
// []any claim trees (the JSON form of RFC 9901).
type jsonAdapter struct{}

// ClaimTreeDigestSites enumerates every _sd digest array at any depth
// and every {"...": "<digest>"} element marker inside arrays.
func (jsonAdapter) ClaimTreeDigestSites(root any) ([]sdtoken.RedactionSite, error) {
	var sites []sdtoken.RedactionSite
	walkJSONTree(root, func(container any, index int, kind sdtoken.SiteKind, digest string) {
		sites = append(sites, sdtoken.RedactionSite{
			Kind:   kind,
			Digest: digest,
			Parent: container,
			Index:  index,
		})
	})
	return sites, nil
}

// walkJSONTree visits every redaction site in the tree. KindMap sites
// report the map owning the _sd key; KindElement sites report the array
// containing the {"...": digest} element.
func walkJSONTree(node any, visit func(container any, index int, kind sdtoken.SiteKind, digest string)) {
	switch typed := node.(type) {
	case map[string]any:
		for k, v := range typed {
			if k == ClaimSD {
				if digests, ok := v.([]any); ok {
					for i, d := range digests {
						if digest, isString := d.(string); isString {
							visit(typed, i, sdtoken.KindMap, digest)
						}
					}
				}
			}
			walkJSONTree(v, visit)
		}
	case []any:
		for i, elem := range typed {
			if marker, isMap := elem.(map[string]any); isMap && len(marker) == 1 {
				if v, has := marker[arrayElementKey]; has {
					if digest, isString := v.(string); isString {
						visit(typed, i, sdtoken.KindElement, digest)
					}
				}
			}
			walkJSONTree(elem, visit)
		}
	}
}

// InsertMapClaim inserts key/value at the site's parent map, rejecting
// collisions.
func (jsonAdapter) InsertMapClaim(site sdtoken.RedactionSite, key, value any) error {
	m, ok := site.Parent.(map[string]any)
	if !ok {
		return fmt.Errorf("%w: redaction site parent is not a map", sdtoken.ErrInvalidDisclosure)
	}
	keyString, ok := key.(string)
	if !ok {
		return fmt.Errorf("%w: JSON claim key is not a string", sdtoken.ErrInvalidDisclosure)
	}
	if _, exists := m[keyString]; exists {
		return sdtoken.ErrClaimCollision
	}
	m[keyString] = value
	return nil
}

// ReplaceElement swaps the array element at the site for the disclosed
// value.
func (jsonAdapter) ReplaceElement(site sdtoken.RedactionSite, value any) error {
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
// by replacing it with a nil sentinel; nil sentinels are compacted away
// by pruneNilElements at the end of processing (Go slice headers
// cannot be shortened through an any-typed parent reference).
func (jsonAdapter) RemoveElement(site sdtoken.RedactionSite) error {
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

// pruneNilElements compacts nil sentinels out of every array in the
// tree, depth-first, preserving order. It returns the (possibly new)
// root when the root itself is an array.
func pruneNilElements(node any) any {
	switch typed := node.(type) {
	case map[string]any:
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

// StripDigestContainer removes the _sd entry from its parent map.
func (jsonAdapter) StripDigestContainer(site sdtoken.RedactionSite) error {
	m, ok := site.Parent.(map[string]any)
	if !ok {
		return fmt.Errorf("%w: redaction site parent is not a map", sdtoken.ErrInvalidDisclosure)
	}
	delete(m, ClaimSD)
	return nil
}
