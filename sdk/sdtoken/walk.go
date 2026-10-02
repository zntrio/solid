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

package sdtoken

import (
	"fmt"
	"sort"
)

// WalkSite is one selectively disclosable position found by Walk.
type WalkSite struct {
	// IsElement distinguishes the array-element form from the map form.
	IsElement bool
	// MapKey is the claim key of the marker value (map form only).
	MapKey any
	// Index is the array position of the marker (element form only).
	Index int
	// Value is the marked claim value.
	Value any
	// Path is the addressable position of the marker within the tree:
	// the map (map form) or array (element form) containing it, followed
	// by the marker container's own addressable position, alternating.
	Path []any
}

// ReservedKey reports whether a plaintext claim key collides with a
// redaction marker name of either format and is therefore rejected.
// The JSON side reserves "_sd" and "..."; the CBOR side reserves the
// simple(59)/tag-58/tag-60 wire forms, which cannot collide with valid
// claim key types (uint64/int64/string).
func ReservedKey(key any) bool {
	switch k := key.(type) {
	case string:
		return k == "_sd" || k == "..."
	default:
		return false
	}
}

// walkKeyOrders stabilizes map iteration order for the deterministic walk.
// JSON map[string]any keys sort lexicographically. CBOR map[any]any keys
// sort by type class: uint64 ascending, then int64 ascending, then string
// lexicographically (uint64 before int64 because COSE preferred
// encodings are unsigned).
func walkKeyOrders(m any) []any {
	switch typed := m.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for k := range typed {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make([]any, len(keys))
		for i, k := range keys {
			out[i] = k
		}
		return out
	case map[any]any:
		var uints []uint64
		var ints []int64
		var strs []string
		for k := range typed {
			switch kk := k.(type) {
			case uint64:
				uints = append(uints, kk)
			case int64:
				ints = append(ints, kk)
			case string:
				strs = append(strs, kk)
			default:
				// Non-orderable key types (bstr, floats, tags, simple
				// values) are rejected by the CBOR format constraints
				// before the walk runs; ordering them is out of scope.
				strs = append(strs, fmt.Sprintf("%v", kk))
			}
		}
		sort.Slice(uints, func(i, j int) bool { return uints[i] < uints[j] })
		sort.Slice(ints, func(i, j int) bool { return ints[i] < ints[j] })
		sort.Strings(strs)
		out := make([]any, 0, len(uints)+len(ints)+len(strs))
		for _, k := range uints {
			out = append(out, k)
		}
		for _, k := range ints {
			out = append(out, k)
		}
		for _, k := range strs {
			out = append(out, k)
		}
		return out
	default:
		return nil
	}
}

// Walk enumerates every Disclosable map value and DisclosableElement
// array element in the claim tree, depth-first, children before parents
// (inner markers before outer ones), matching recursive disclosure
// construction (RFC 9901 section 4.2.6, draft-ietf-spice-sd-cwt-08
// section 14.2). The walk order defines the disclosure list order
// returned by Issue and is stable across runs: map iteration order is
// stabilized by sorting keys (JSON lexicographically; CBOR by type class
// — uint64 ascending, then int64 ascending, then string
// lexicographically). Plaintext claim keys colliding with a redaction
// marker name are rejected (ReservedKey).
func Walk(root any) ([]WalkSite, error) {
	var sites []WalkSite
	if err := walkValue(root, nil, &sites); err != nil {
		return nil, err
	}
	return sites, nil
}

func walkValue(node any, path []any, sites *[]WalkSite) error {
	switch typed := node.(type) {
	case map[string]any:
		for _, key := range walkKeyOrders(typed) {
			value := typed[key.(string)]
			if err := walkMapEntry(key, value, typed, path, sites); err != nil {
				return err
			}
		}
	case map[any]any:
		for _, key := range walkKeyOrders(typed) {
			value := typed[key]
			if err := walkMapEntry(key, value, typed, path, sites); err != nil {
				return err
			}
		}
	case []any:
		for i, elem := range typed {
			switch marked := elem.(type) {
			case Disclosable:
				return fmt.Errorf("%w: Disclosable is a map-value marker and cannot appear as an array element", ErrInvalidDisclosure)
			case DisclosableElement:
				childPath := append(appendPath(path), typed, i)
				// Children first: a marker whose value itself contains
				// markers produces inner disclosures before its own.
				if err := walkValue(marked.Value, childPath, sites); err != nil {
					return err
				}
				*sites = append(*sites, WalkSite{
					IsElement: true,
					Index:     i,
					Value:     marked.Value,
					Path:      childPath,
				})
			default:
				if err := walkValue(elem, append(appendPath(path), typed, i), sites); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func walkMapEntry(key, value, container any, path []any, sites *[]WalkSite) error {
	if ReservedKey(key) {
		return fmt.Errorf("%w: claim key %q collides with a redaction marker name", ErrReservedClaimKey, key)
	}
	switch marked := value.(type) {
	case Disclosable:
		childPath := append(appendPath(path), container, key)
		// Children first: a marker whose value itself contains markers
		// produces inner disclosures before its own.
		if err := walkValue(marked.Value, childPath, sites); err != nil {
			return err
		}
		*sites = append(*sites, WalkSite{
			IsElement: false,
			MapKey:    key,
			Value:     marked.Value,
			Path:      childPath,
		})
		return nil
	case DisclosableElement:
		return fmt.Errorf("%w: DisclosableElement is an array-element marker and cannot appear as a map value", ErrInvalidDisclosure)
	default:
		return walkValue(value, append(appendPath(path), container, key), sites)
	}
}

func appendPath(path []any) []any {
	if path == nil {
		return nil
	}
	out := make([]any, 0, len(path)+2)
	out = append(out, path...)
	return out
}
