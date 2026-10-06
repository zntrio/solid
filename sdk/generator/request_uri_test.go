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

package generator

import (
	"context"
	"strings"
	"testing"
)

func TestRequestURIValidate(t *testing.T) {
	g := DefaultRequestURI()
	ctx := context.Background()

	valid := "urn:solid:" + strings.Repeat("a", DefaultRequestURILen)
	if err := g.Validate(ctx, "https://as.example", valid); err != nil {
		t.Errorf("valid request_uri rejected: %v", err)
	}

	// A well-formed suffix embedded in a longer URI must NOT validate.
	embedded := "https://attacker.example/leak?next=" + valid
	if err := g.Validate(ctx, "https://as.example", embedded); err == nil {
		t.Error("substring request_uri accepted, matcher is not anchored")
	}

	// Prefix embedding must also fail.
	prefixed := valid + "/suffix"
	if err := g.Validate(ctx, "https://as.example", prefixed); err == nil {
		t.Error("request_uri with trailing suffix accepted, matcher is not anchored on the end")
	}

	// Whitespace is trimmed before matching.
	if err := g.Validate(ctx, "https://as.example", "  "+valid+"  "); err != nil {
		t.Errorf("whitespace-padded request_uri rejected: %v", err)
	}

	for _, tc := range []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"wrong urn namespace", "urn:ietf:params:oauth:request_uri:" + strings.Repeat("a", DefaultRequestURILen)},
		{"too short", "urn:solid:" + strings.Repeat("a", DefaultRequestURILen-1)},
		{"too long", "urn:solid:" + strings.Repeat("a", DefaultRequestURILen+1)},
		{"invalid charset", "urn:solid:" + strings.Repeat("_", DefaultRequestURILen)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := g.Validate(ctx, "https://as.example", tc.in); err == nil {
				t.Errorf("invalid request_uri %q accepted", tc.in)
			}
		})
	}
}

func TestRequestURIGenerate(t *testing.T) {
	g := DefaultRequestURI()
	uri, err := g.Generate(context.Background(), "https://as.example")
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if err := g.Validate(context.Background(), "https://as.example", uri); err != nil {
		t.Errorf("generated request_uri %q does not validate: %v", uri, err)
	}
}
