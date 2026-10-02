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
	"strings"
	"testing"

	"zntr.io/solid/sdk/sdtoken"
)

// FuzzParse asserts Parse never panics and always round-trips accepted
// inputs through Serialize byte-exactly.
func FuzzParse(f *testing.F) {
	// Seeds: valid compact serializations (RFC 9901 section 4 shapes)
	// and malformed near-misses.
	f.Add("eyJhbGciOiJFUzI1NiJ9.e30.YY~")
	f.Add("eyJhbGciOiJFUzI1NiJ9.e30.YY~ZGlzY2xvc3VyZTE~")
	f.Add("eyJhbGciOiJFUzI1NiJ9.e30.YY~ZGlzY2xvc3VyZTE~eyJhbGciOiJFUzI1NiJ9.e30.YY")
	f.Add("")
	f.Add("not-a-sd-jwt")
	f.Add("a.b~")
	f.Add("~~")
	f.Add("a.b.c~d~e.f.g")
	f.Fuzz(func(t *testing.T, raw string) {
		parsed, err := Parse(raw)
		if err != nil {
			return // rejection is fine; panics are not
		}
		// Round-trip: Serialize must reproduce the input byte-exactly.
		if got := parsed.Serialize(); got != raw {
			t.Errorf("Parse(%q).Serialize() = %q", raw, got)
		}
		// Structural invariants.
		if parsed.IssuerSignedJWT == "" {
			t.Errorf("Parse(%q) accepted an empty issuer JWT", raw)
		}
		if strings.Contains(raw, parsed.KeyBindingJWT) == false && parsed.KeyBindingJWT != "" {
			t.Errorf("Parse(%q) invented a KB-JWT %q", raw, parsed.KeyBindingJWT)
		}
	})
}

// digestKeyOf recomputes the normalized digest key of a wire string
// (RFC 9901 section 4.2.3: SHA-256 over the US-ASCII wire bytes).
func digestKeyOf(t *testing.T, d string) string {
	t.Helper()
	return sdtoken.DigestKey([]byte(d))
}

// element/map form arity matches the claim key presence.
func FuzzDecodeDisclosure(f *testing.F) {
	// Seeds: RFC 9901 section 5.1 vectors, element form, and mutants.
	f.Add("WyIyR0xDNDJzS1Z2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd")
	f.Add("WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0")
	f.Add("WyJzYWx0IiwgImVsZW1lbnQiXQ")
	f.Add("WyJzYWx0Il0")
	f.Add("")
	f.Add("not-base64url!!!")
	f.Add("W3")
	f.Fuzz(func(t *testing.T, d string) {
		dd, err := decodeDisclosure(d)
		if err != nil {
			return // rejection is fine; panics are not
		}
		// Digest consistency over the exact wire bytes.
		if got := digestKeyOf(t, d); got != dd.Digest {
			t.Errorf("decodeDisclosure(%q) digest = %q, recomputed %q", d, dd.Digest, got)
		}
		// Arity invariants.
		if dd.ClaimKey == nil && dd.IsDecoy {
			// 1-element decoy form cannot exist in RFC 9901 (CBOR-only).
			t.Errorf("decodeDisclosure(%q) accepted a JSON decoy form", d)
		}
	})
}

// FuzzEncodeDecodeDisclosure asserts encode/decode round-trips: any
// salt/key/string-value triple that encodes cleanly must decode back
// to the same claim key and value.
func FuzzEncodeDecodeDisclosure(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, "given_name", "John")
	f.Add(make([]byte, 16), "", "element-value")
	f.Add(make([]byte, 16), "_sd", "reserved")
	f.Add(make([]byte, 16), "nationalities", "DE")
	f.Add([]byte("0"), "\xb3", "0") // regression: invalid UTF-8 claim key (mangled by encoding/json)
	f.Fuzz(func(t *testing.T, salt []byte, key string, value string) {
		wire, _, err := encodeDisclosure(salt, key, value)
		if err != nil {
			return // rejected (bad salt length, reserved key, invalid UTF-8)
		}
		dd, err := decodeDisclosure(wire)
		if err != nil {
			t.Fatalf("encode/decode asymmetry: encode accepted %q/%q but decode failed: %v", key, value, err)
		}
		if key == "" {
			if dd.ClaimKey != nil {
				t.Errorf("element form decoded a claim key %v", dd.ClaimKey)
			}
		} else if dd.ClaimKey != key {
			t.Errorf("claim key round-trip: %q became %v", key, dd.ClaimKey)
		}
		if dd.Value != value {
			t.Errorf("value round-trip: %q became %v", value, dd.Value)
		}
	})
}

func FuzzParseJSONDisclosureArray(f *testing.F) {
	f.Add([]byte(`["salt","key","value"]`))
	f.Add([]byte(`["salt","value"]`))
	f.Add([]byte(`[1,2,3,4]`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, jsonBytes []byte) {
		// Wire form: base64url of the fuzzed JSON.
		d := base64.RawURLEncoding.EncodeToString(jsonBytes)
		dd, err := decodeDisclosure(d)
		if err != nil {
			return
		}
		// Decoded arrays must have 2 or 3 elements.
		if dd.ClaimKey == nil && !dd.IsDecoy {
			if dd.Value == nil {
				t.Errorf("decodeDisclosure(%q) produced an empty disclosure", d)
			}
		}
		_ = dd // invariants above; no JSON pkg dependency needed
	})
}
