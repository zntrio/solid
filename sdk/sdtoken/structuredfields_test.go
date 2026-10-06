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
	"errors"
	"strings"
	"testing"
)

// RFC 9651 section 4.2.2.1 sf-string grammar vectors, plus the
// draft-forten field semantics (Lists of strings, Items that are
// strings, multi-line combination).

func TestParseDisclosuresField(t *testing.T) {
	tests := []struct {
		name    string
		values  []string
		want    []string
		wantErr error
	}{
		{
			name:   "single disclosure",
			values: []string{`"Ik2hax0Yis4"`},
			want:   []string{"Ik2hax0Yis4"},
		},
		{
			name:   "list of two with spacing",
			values: []string{`"Ik2hax0Yis4", "U_2ZAgP94G0"`},
			want:   []string{"Ik2hax0Yis4", "U_2ZAgP94G0"},
		},
		{
			name:   "multi-line combination preserves order",
			values: []string{`"a"`, `"b", "c"`},
			want:   []string{"a", "b", "c"},
		},
		{
			name:   "escapes decode",
			values: []string{`"a\"b", "c\\d"`},
			want:   []string{`a"b`, `c\d`},
		},
		{
			name:   "leading and trailing whitespace tolerated",
			values: []string{"  \"a\" ,  \"b\"  "},
			want:   []string{"a", "b"},
		},
		{
			name:    "token item instead of string",
			values:  []string{`foo`},
			wantErr: ErrStructuredField,
		},
		{
			name:    "number item",
			values:  []string{`42`},
			wantErr: ErrStructuredField,
		},
		{
			name:    "unescaped double quote",
			values:  []string{`"a"b"`},
			wantErr: ErrStructuredField,
		},
		{
			name:    "empty inner string",
			values:  []string{`""`},
			wantErr: ErrStructuredField,
		},
		{
			name:    "empty member",
			values:  []string{`"a", , "b"`},
			wantErr: ErrStructuredField,
		},
		{
			name:    "item with parameters",
			values:  []string{`"a";q=1`},
			wantErr: ErrStructuredField,
		},
		{
			name:    "inner list",
			values:  []string{`("a")`},
			wantErr: ErrStructuredField,
		},
		{
			name:    "non-ascii byte",
			values:  []string{`"é"`},
			wantErr: ErrStructuredField,
		},
		{
			name:   "empty values = empty list",
			values: nil,
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseDisclosuresField(tt.values)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("item %d = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestFormatDisclosuresFieldRoundTrip(t *testing.T) {
	disclosures := []string{"Ik2hax0Yis4", `a"b`, `c\d`}
	formatted := FormatDisclosuresField(disclosures)
	if !strings.Contains(formatted, `"a\"b"`) || !strings.Contains(formatted, `"c\\d"`) {
		t.Fatalf("escaping missing in %q", formatted)
	}
	parsed, err := ParseDisclosuresField([]string{formatted})
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != len(disclosures) {
		t.Fatalf("round trip length = %d, want %d", len(parsed), len(disclosures))
	}
	for i := range parsed {
		if parsed[i] != disclosures[i] {
			t.Fatalf("round trip item %d = %q, want %q", i, parsed[i], disclosures[i])
		}
	}

	if FormatDisclosuresField(nil) != "" {
		t.Fatal("empty list must format to the empty string")
	}
}

func TestParseKeyBindingField(t *testing.T) {
	kb, err := ParseKeyBindingField(`"eyJhbGciOiJFUzI1NiJ9.e30.x"`)
	if err != nil {
		t.Fatal(err)
	}
	if kb != "eyJhbGciOiJFUzI1NiJ9.e30.x" {
		t.Fatalf("kb = %q", kb)
	}

	if _, err := ParseKeyBindingField(`"a", "b"`); !errors.Is(err, ErrStructuredField) {
		t.Fatalf("two items must be rejected, got %v", err)
	}
	if _, err := ParseKeyBindingField(`a-token`); !errors.Is(err, ErrStructuredField) {
		t.Fatalf("bare token must be rejected, got %v", err)
	}
	if _, err := ParseKeyBindingField(""); !errors.Is(err, ErrStructuredField) {
		t.Fatalf("empty value must be rejected as a non-single item, got %v", err)
	}

	if FormatKeyBindingField(`a"b\c`) != `"a\"b\\c"` {
		t.Fatalf("format = %q", FormatKeyBindingField(`a"b\c`))
	}
}

func TestParseDisclosuresFieldSpaceInString(t *testing.T) {
	// RFC 9651 section 4.2.5: unescaped includes SP — "a b" is a valid
	// sf-string, and the formatter already emits SP unescaped.
	for _, tt := range []struct{ in, want string }{
		{`"a b"`, "a b"},
		{`"a  b"`, "a  b"},
	} {
		got, err := ParseDisclosuresField([]string{tt.in})
		if err != nil {
			t.Fatalf("%s: %v", tt.in, err)
		}
		if len(got) != 1 || got[0] != tt.want {
			t.Fatalf("%s: got %v", tt.in, got)
		}
	}
}
