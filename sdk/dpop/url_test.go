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

package dpop

import (
	"testing"
)

// TestNormalizedURLEqualDefaultPorts asserts the RFC 9449 section 4.3 htu
// comparison tolerates explicit scheme-default ports and rejects real
// mismatches.
func TestNormalizedURLEqualDefaultPorts(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want bool
	}{
		{"identical", "https://server.example.com/resource", "https://server.example.com/resource", true},
		{"https default port explicit", "https://server.example.com:443/resource", "https://server.example.com/resource", true},
		{"http default port explicit", "http://server.example.com:80/resource", "http://server.example.com/resource", true},
		{"scheme case", "HTTPS://Server.Example.com/resource", "https://server.example.com/resource", true},
		{"non-default port kept", "https://server.example.com:8443/resource", "https://server.example.com/resource", false},
		{"different host", "https://attacker.example.com/resource", "https://server.example.com/resource", false},
		{"different path", "https://server.example.com/other", "https://server.example.com/resource", false},
		{"query ignored by design of caller", "https://server.example.com/resource?a=1", "https://server.example.com/resource?a=2", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizedURLEqual(tc.a, tc.b)
			if err != nil {
				t.Fatalf("normalizedURLEqual(%q, %q) error = %v", tc.a, tc.b, err)
			}
			if got != tc.want {
				t.Errorf("normalizedURLEqual(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}
