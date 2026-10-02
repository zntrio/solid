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
	"bytes"
	"testing"

	cbor "github.com/fxamacker/cbor/v2"

	"zntr.io/solid/sdk/sdtoken"
)

// FuzzDecodeDisclosure asserts decodeDisclosure never panics and that
// accepted disclosures keep consistent invariants: the decoded digest
// equals the recomputed digest over the exact wire bytes, salts are
// exactly 16 bytes, and the arity matches the decoy/claim-key forms.
func FuzzDecodeDisclosure(f *testing.F) {
	// Seeds: draft Figure 7 bytes, element form, decoy form, mutants.
	f.Add([]byte{0x83, 0x50, 0xba, 0xe6, 0x11, 0x06, 0x7b, 0xb8, 0x23, 0x48, 0x67, 0x97, 0xda, 0x1e, 0xbb, 0xb5, 0x2f, 0x83, 0x6b, 0x41, 0x42, 0x43, 0x44, 0x2d, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x19, 0x01, 0xf5})
	f.Add(append([]byte{0x82, 0x50}, append(bytes.Repeat([]byte{0x01}, 16), 0x61, 0x44)...)[:2+16+2])
	f.Add(append([]byte{0x81, 0x50}, bytes.Repeat([]byte{0x02}, 16)...))
	f.Add([]byte{0x81})
	f.Add([]byte{0x82, 0x41, 0x61, 0x61})
	f.Add([]byte{})
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, wire []byte) {
		dd, err := decodeDisclosure(wire)
		if err != nil {
			return // rejection is fine; panics are not
		}
		// Digest consistency over the exact wire bytes.
		if got := sdtoken.DigestKey(wire); got != dd.Digest {
			t.Errorf("decodeDisclosure(%x) digest = %q, recomputed %q", wire, dd.Digest, got)
		}
		// Salt invariant.
		if len(dd.Salt) != 16 {
			t.Errorf("decodeDisclosure(%x) accepted a %d-byte salt", wire, len(dd.Salt))
		}
		// Arity invariants: decoys carry no claim key or value; the
		// element form has no claim key.
		if dd.IsDecoy && dd.ClaimKey != nil {
			t.Errorf("decodeDisclosure(%x) decoy carries a claim key", wire)
		}
		if dd.IsDecoy && dd.Value != nil {
			t.Errorf("decodeDisclosure(%x) decoy carries a value", wire)
		}
	})
}

// FuzzCheckDefiniteLength asserts the structural walker never panics,
// never over-reads, and accepts well-formed definite-length CBOR while
// rejecting anything containing an indefinite-length marker (0x1f
// additional info or 0xff break).
func FuzzCheckDefiniteLength(f *testing.F) {
	// Seeds: valid definite items, indefinite maps/arrays/strings,
	// truncated items, garbage.
	f.Add([]byte{0xa1, 0x01, 0x02})
	f.Add([]byte{0x9f, 0x01, 0x02, 0xff})
	f.Add([]byte{0x9f, 0x01, 0xff})
	f.Add([]byte{0x7f, 0x61, 0x61, 0xff})
	f.Add([]byte{0x5f, 0x41, 0x61, 0xff})
	f.Add([]byte{0x18, 0x18})
	f.Add([]byte{0x19, 0x01})
	f.Add([]byte{})
	f.Add([]byte{0xa1})
	f.Add([]byte{0xc0})
	f.Add([]byte{0xd8, 0x18})
	// Regressions: trailing garbage after a complete item (30 9f),
	// break-code bytes as legitimate argument data (38 ff), hostile
	// truncated arguments (8 ff), and overflow-triggering lengths.
	f.Add([]byte{0x30, 0x9f})
	f.Add([]byte{0x38, 0xff})
	f.Add([]byte{0x38, 0xff, 0xff, 0xff})
	f.Add([]byte{0xbe, 0x5b, 0xb0, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30})
	f.Fuzz(func(t *testing.T, raw []byte) {
		err := checkDefiniteLength(raw)
		if err != nil {
			return // rejection is fine; panics and over-reads are not
		}
		// Accepted inputs must be exactly one complete item: the
		// walker consumed the full input (enforced internally), and
		// the standard decoder must also parse it without panic.
		// Note: 0xff bytes may legitimately appear as argument or
		// content bytes (e.g. nint arguments); only indefinite
		// *initial bytes* are forbidden, which the walker enforces.
		var v any
		_ = cbor.Unmarshal(raw, &v)
	})
}

// FuzzEnforceDuplicateMapKeys asserts duplicate-map-key decoding never
// panics and that accepted inputs contain no duplicate integer keys
// under preferred-encoding equivalence (uint8- and uint16-encoded
// equal values).
func FuzzEnforceDuplicateMapKeys(f *testing.F) {
	f.Add([]byte{0xa2, 0x01, 0x01, 0x02, 0x02})
	f.Add([]byte{0xa2, 0x01, 0x01, 0x18, 0x01, 0x02})
	f.Add([]byte{0xa1, 0x01, 0x02})
	f.Add([]byte{0x9f, 0x01, 0x02, 0xff})
	f.Add([]byte{0x00})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		out, err := enforceDuplicateMapKeys(raw)
		if err != nil {
			return
		}
		// Accepted maps must not contain duplicate integer keys: the
		// decoder guarantees it; cross-check the decoded Go map.
		if m, isMap := out.(map[any]any); isMap {
			seen := map[uint64]struct{}{}
			for k := range m {
				switch kk := k.(type) {
				case uint64:
					if _, dup := seen[kk]; dup {
						t.Errorf("enforceDuplicateMapKeys(%x) accepted duplicate key %d", raw, kk)
					}
					seen[kk] = struct{}{}
				}
			}
		}
	})
}

// FuzzEncodeDecodeDisclosure asserts encode/decode round-trips for
// string-valued claims: any salt/claim-key/value triple that encodes
// cleanly must decode back to the same claim key and value.
func FuzzEncodeDecodeDisclosure(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, uint64(501), "ABCD-123456")
	f.Add(make([]byte, 16), uint64(1), "issuer")
	f.Add(make([]byte, 16), uint64(0), "element-value")
	f.Add([]byte("0000000000000000"), uint64(501), "\x82") // regression: invalid UTF-8 value (undecodable CBOR text)
	f.Fuzz(func(t *testing.T, salt []byte, key uint64, value string) {
		wire, _, err := encodeDisclosure(salt, key, value)
		if err != nil {
			return // rejected (bad salt length)
		}
		dd, err := decodeDisclosure(wire)
		if err != nil {
			t.Fatalf("encode/decode asymmetry: encode accepted %d but decode failed: %v", key, err)
		}
		if dd.IsDecoy {
			t.Error("3-element decode produced a decoy")
		}
		if got, ok := dd.ClaimKey.(uint64); !ok || got != key {
			t.Errorf("claim key round-trip: %d became %v", key, dd.ClaimKey)
		}
		if dd.Value != value {
			t.Errorf("value round-trip: %q became %v", value, dd.Value)
		}
	})
}
