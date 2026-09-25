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

package random

import (
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	t.Parallel()

	for _, length := range []int{0, 1, 8, 16, 96, 128} {
		s := String(length)
		if len(s) != length {
			t.Fatalf("expected length %d, got %d", length, len(s))
		}
		for _, r := range s {
			if !strings.ContainsRune(string(StdChars), r) {
				t.Fatalf("unexpected character %q in %q", r, s)
			}
		}
	}
}

func TestStringChars(t *testing.T) {
	t.Parallel()

	charset := []byte("BCDFGHJKLMNPQRSTVWXZ")
	s := StringChars(20, charset)
	if len(s) != 20 {
		t.Fatalf("expected length 20, got %d", len(s))
	}
	for _, r := range s {
		if !strings.ContainsRune(string(charset), r) {
			t.Fatalf("unexpected character %q in %q", r, s)
		}
	}
}

func TestStringChars_InvalidCharset(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for invalid charset")
		}
	}()
	StringChars(8, []byte("a"))
}

func TestString_Uniqueness(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{}, 1000)
	for range 1000 {
		s := String(32)
		if _, dup := seen[s]; dup {
			t.Fatalf("duplicate value generated: %s", s)
		}
		seen[s] = struct{}{}
	}
}
