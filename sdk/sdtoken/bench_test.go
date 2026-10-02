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
	"testing"
)

func benchClaims() map[string]any {
	return map[string]any{
		"iss":         "https://issuer.example.com",
		"sub":         "subject-123",
		"iat":         1750000000,
		"given_name":  Disclosable{Value: "John"},
		"family_name": Disclosable{Value: "Doe"},
		"address": Disclosable{Value: map[string]any{
			"street_address": Disclosable{Value: "123 Main St"},
			"locality":       Disclosable{Value: "Anytown"},
			"region":         Disclosable{Value: "Anystate"},
		}},
		"nationalities": []any{
			DisclosableElement{Value: "US"},
			DisclosableElement{Value: "DE"},
		},
	}
}

func BenchmarkWalk(b *testing.B) {
	claims := benchClaims()
	b.ResetTimer()
	for b.Loop() {
		if _, err := Walk(claims); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDigestKey(b *testing.B) {
	wire := []byte("WyIyR0xDNDJzS1Z2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd")
	b.ResetTimer()
	for b.Loop() {
		_ = DigestKey(wire)
	}
}

func BenchmarkNewSalt(b *testing.B) {
	for b.Loop() {
		if _, err := NewSalt(); err != nil {
			b.Fatal(err)
		}
	}
}
