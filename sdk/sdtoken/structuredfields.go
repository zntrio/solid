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
	"strings"
)

// Structured Fields (RFC 9651) support for the draft-forten HTTP fields:
// the scope here is sf-string Lists (SD-JWT-Disclosures) and a
// single-string Item (SD-JWT-Key-Binding). Hand-rolled to keep the
// minimal-dependency posture of the repo (no external SF parser in
// go.mod); the grammar implemented is RFC 9651 section 4.2.2:
//
//	sf-string = DQUOTE *sf-quoted DQUOTE
//	sf-quoted = %x21 / %x23-5B / %x5D-7E / "\" DQUOTE / "\" "\"
//
// Lists combine multiple field-line values in order (RFC 9110 section
// 5.3), so the caller passes http.Header.Values(FieldDisclosures) as-is.
//
// Known limitation: members are split on commas before parsing, so an
// sf-string CONTAINING a literal comma — legal per RFC 9651 — is
// rejected. draft-forten values are base64url / compact-serial strings
// (comma-free alphabets), so no conforming sender can produce one; a
// future field carrying arbitrary strings needs a quote-aware scanner.

// ParseDisclosuresField parses the combined field-line values of the
// SD-JWT-Disclosures field: a List of sf-strings. Items are separated by
// commas with optional surrounding whitespace; anything other than a
// bare sf-string item (tokens, numbers, parameters, inner lists) is
// rejected (ErrStructuredField). The number of returned strings equals
// the number of list members.
func ParseDisclosuresField(values []string) ([]string, error) {
	var out []string
	for _, line := range values {
		items, err := parseSFStringList(line)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
	}
	return out, nil
}

// FormatDisclosuresField renders an SD-JWT-Disclosures field value: a
// List of sf-strings joined by ", " (RFC 9651 section 4.2 serializing
// convention). An empty list yields the empty string.
func FormatDisclosuresField(disclosures []string) string {
	if len(disclosures) == 0 {
		return ""
	}
	escaped := make([]string, 0, len(disclosures))
	for _, d := range disclosures {
		escaped = append(escaped, formatSFString(d))
	}
	return strings.Join(escaped, ", ")
}

// ParseKeyBindingField parses the SD-JWT-Key-Binding field: a single
// Item that is an sf-string (RFC 9651 section 4.2.2.1).
func ParseKeyBindingField(value string) (string, error) {
	items, err := parseSFStringList(value)
	if err != nil {
		return "", err
	}
	if len(items) != 1 {
		return "", fmt.Errorf("%w: key binding field is not a single item", ErrStructuredField)
	}
	return items[0], nil
}

// FormatKeyBindingField renders the SD-JWT-Key-Binding field value.
func FormatKeyBindingField(keyBinding string) string {
	return formatSFString(keyBinding)
}

// parseSFStringList parses one field-line value holding a List whose
// every member is a bare sf-string, or a single sf-string Item. Leading
// and trailing whitespace (SP / HTAB / OWS) is tolerated per RFC 9651
// section 4.2.1; empty input is an empty list.
func parseSFStringList(line string) ([]string, error) {
	trimmed := strings.Trim(line, " \t")
	if trimmed == "" {
		return nil, nil
	}

	var out []string
	for _, member := range strings.Split(trimmed, ",") {
		member = strings.Trim(member, " \t")
		if member == "" {
			return nil, fmt.Errorf("%w: empty list member", ErrStructuredField)
		}
		s, err := parseSFString(member)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// parseSFString parses exactly one sf-string: DQUOTE *sf-quoted DQUOTE.
func parseSFString(item string) (string, error) {
	if len(item) < 2 || item[0] != '"' || item[len(item)-1] != '"' {
		return "", fmt.Errorf("%w: item is not an sf-string", ErrStructuredField)
	}

	var b strings.Builder
	i := 1
	last := len(item) - 1
	for i < last {
		c := item[i]
		switch {
		case c == '\\':
			// "\" DQUOTE / "\" "\" only (RFC 9651 section 4.2.2).
			if i+1 >= last || (item[i+1] != '"' && item[i+1] != '\\') {
				return "", fmt.Errorf("%w: invalid backslash escape", ErrStructuredField)
			}
			b.WriteByte(item[i+1])
			i += 2
		case c == 0x20, c == 0x21, c >= 0x23 && c <= 0x5B, c >= 0x5D && c <= 0x7E:
			b.WriteByte(c)
			i++
		default:
			return "", fmt.Errorf("%w: invalid character %q in sf-string", ErrStructuredField, c)
		}
	}
	if i != last {
		// An unescaped DQUOTE terminated the scan mid-item.
		return "", fmt.Errorf("%w: unescaped double quote in sf-string", ErrStructuredField)
	}

	s := b.String()
	if s == "" {
		return "", fmt.Errorf("%w: empty sf-string", ErrStructuredField)
	}
	return s, nil
}

// formatSFString renders one sf-string, escaping DQUOTE and backslash.
func formatSFString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range []byte(s) {
		switch c {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}
