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

// Client metadata policy for CIMD resolution: OpenID Federation 1.0
// section 6.1.3.1 standard metadata policy operators, applied to a
// Client ID Metadata Document between the client_id match and the
// section 4.1 enforcement of ToClient — the policy-applied document is
// what the credential and key-material restrictions validate.
//
// The policy is operator configuration at assembly level (like
// AllowlistFilter entries): one global JSON object keyed by RFC 7591
// client-metadata parameter names, applied to every CIMD resolution.
// A policy violation fails the whole client (fail-closed): to the
// caller the result is an unknown client, exactly like an unfetchable
// or malformed document.
//
// Operator semantics are quoted from the vendored final spec
// (docs/rfcs/openid-federation-1_0.txt, section 6.1.3.1):
//
//   - value     (§6.1.3.1.1, order First):      "The metadata parameter
//     MUST be assigned the value of the operator. When the value of the
//     operator is null, the metadata parameter MUST be removed."
//   - add       (§6.1.3.1.2, After value):       "The value or values of
//     this operator MUST be added to the metadata parameter. Values that
//     are already present in the metadata parameter MUST NOT be added
//     another time. If the metadata parameter is absent, it MUST be
//     initialized with the value of this operator."
//   - default   (§6.1.3.1.3, After add):         "If the metadata parameter
//     is absent, it MUST be set to the value of the operator. If the
//     metadata parameter is present, this operator has no effect."
//   - one_of    (§6.1.3.1.4, After default):     "If the metadata parameter
//     is present, its value MUST be one of those listed in the operator
//     value."
//   - subset_of (§6.1.3.1.5, After one_of):      "If the metadata parameter
//     is present, it is assigned the intersection between the values of
//     the operator and the metadata parameter. Note that the resulting
//     intersection may thus be an empty array []."
//   - superset_of (§6.1.3.1.6, After subset_of): "If the metadata parameter
//     is present, its values MUST contain those specified in the operator
//     value. By mathematically defining supersets, equality is included."
//   - essential (§6.1.3.1.7, Last):              "If the value of this
//     operator is true, then the metadata parameter MUST be present."
//
// The essential+subset_of matrix of spec Table 1 is implemented exactly:
// intersection for present values, error when absent+essential, skip when
// absent+voluntary. The scope parameter special case of §6.1.3.1.8
// ("regarded and processed as a string array by policy operators") is
// handled by the space-separated-list policy fields.
package cimd

import (
	"encoding/json"
	"fmt"
	"strings"
)

// PolicyEntry is the operator set for one metadata parameter
// (spec section 6.1.3: "A policy entry is represented by a JSON object
// and consists of one or more operators").
//
// Operator values carry json.RawMessage because value/default accept
// string, number, boolean, or array (value additionally null), while
// add/one_of/subset_of/superset_of are arrays and essential is boolean;
// validation happens at application time per operator.
type PolicyEntry struct {
	// Value uses a non-pointer RawMessage because JSON null is a legal
	// operator value for it ("the metadata parameter MUST be removed",
	// spec 6.1.3.1.1) — a pointer would erase the null/absent
	// distinction on decode.
	Value      json.RawMessage  `json:"value,omitempty"`
	Add        *json.RawMessage `json:"add,omitempty"`
	Default    *json.RawMessage `json:"default,omitempty"`
	OneOf      *json.RawMessage `json:"one_of,omitempty"`
	SubsetOf   *json.RawMessage `json:"subset_of,omitempty"`
	SupersetOf *json.RawMessage `json:"superset_of,omitempty"`
	Essential  *bool            `json:"essential,omitempty"`
}

// Policy is a client metadata policy: metadata parameter names
// (RFC 7591 client-metadata JSON names) mapped to their policy entries.
// The map form preserves the exact wire shape and rejects duplicate
// JSON member names on decode, as the spec data structure requires
// (single-level here: the Entity-Type layer of the spec is the AS's
// oauth_client role, fixed by this application).
type Policy map[string]PolicyEntry

// DecodePolicy parses a client metadata policy JSON object.
func DecodePolicy(b []byte) (Policy, error) {
	var p Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("cimd: unable to decode policy: %w", err)
	}
	return p, nil
}

// empty reports whether the entry carries no operator at all.
func (e PolicyEntry) empty() bool {
	return len(e.Value) == 0 && e.Add == nil && e.Default == nil &&
		e.OneOf == nil && e.SubsetOf == nil && e.SupersetOf == nil && e.Essential == nil
}

// apply applies the entry's operators to the raw metadata value in the
// spec-defined order (value, add, default, one_of, subset_of,
// superset_of, essential — spec section 6.1.3.1 orders), returning the
// resulting raw value and whether the parameter must remain present.
// A nil result with present=false removes the parameter. An error is a
// policy failure: the client is rejected.
//
//nolint:gocritic // unnamedResult advisory only; naming the results breaks the := below
func (e PolicyEntry) apply(key string, current json.RawMessage) (json.RawMessage, bool, error) {
	// The application order is fixed by the operator sections of the
	// spec: value First, add After value, default After add (modifiers);
	// one_of After default, subset_of After one_of, superset_of After
	// subset_of (checkers, on the present value only); essential Last.
	current, err := e.applyModifiers(key, current)
	if err != nil {
		return nil, false, err
	}
	current, err = e.applyCheckers(key, current)
	if err != nil {
		return nil, false, err
	}
	if e.Essential != nil && *e.Essential && current == nil {
		// essential true: MUST be present (spec 6.1.3.1.7).
		return nil, false, fmt.Errorf("cimd: policy essential on %q: parameter is absent", key)
	}
	return current, current != nil, nil
}

// applyModifiers runs the value-add-default phase (spec section
// 6.1.3.1: value First, add After value, default After add).
func (e PolicyEntry) applyModifiers(key string, current json.RawMessage) (json.RawMessage, error) {
	if len(e.Value) > 0 {
		// value: assign; null removes (spec 6.1.3.1.1).
		if isJSONNull(e.Value) {
			current = nil
		} else {
			current = e.Value
		}
	}

	if e.Add != nil {
		next, err := opAdd(current, *e.Add)
		if err != nil {
			return nil, fmt.Errorf("cimd: policy add on %q: %w", key, err)
		}
		current = next
	}

	if e.Default != nil && current == nil {
		// default: fill absent only (spec 6.1.3.1.3).
		current = *e.Default
	}

	return current, nil
}

// applyCheckers runs the one_of-subset_of-superset_of phase on the
// present value (spec section 6.1.3.1 orders: After default/one_of/
// subset_of respectively); absent parameters are skipped.
func (e PolicyEntry) applyCheckers(key string, current json.RawMessage) (json.RawMessage, error) {
	if current == nil {
		return nil, nil
	}

	if e.OneOf != nil {
		if err := opOneOf(current, *e.OneOf); err != nil {
			return nil, fmt.Errorf("cimd: policy one_of on %q: %w", key, err)
		}
	}

	if e.SubsetOf != nil {
		next, err := opSubsetOf(current, *e.SubsetOf)
		if err != nil {
			return nil, fmt.Errorf("cimd: policy subset_of on %q: %w", key, err)
		}
		current = next
	}

	if e.SupersetOf != nil {
		if err := opSupersetOf(current, *e.SupersetOf); err != nil {
			return nil, fmt.Errorf("cimd: policy superset_of on %q: %w", key, err)
		}
	}

	return current, nil
}

// Apply applies the policy to a raw CIMD document (the JSON object as
// fetched, keyed by RFC 7591 parameter names) and returns the
// policy-applied document. Unknown-to-the-policy parameters pass
// through untouched; policy entries naming parameters the document does
// not carry are still applied (default/essential can add or require
// them). The client_id match invariant is preserved by rejecting any
// policy entry that names client_id: the operator could rewrite the
// identifier the document was fetched from, breaking draft section 4's
// simple string comparison.
func (p Policy) Apply(doc map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	if doc == nil {
		doc = map[string]json.RawMessage{}
	}
	out := make(map[string]json.RawMessage, len(doc)+len(p))
	for k, v := range doc {
		out[k] = v
	}

	for key, entry := range p {
		if entry.empty() {
			continue
		}
		if key == "client_id" {
			return nil, fmt.Errorf("cimd: policy on %q is forbidden: it would rewrite the client identifier match", key)
		}

		result, present, err := entry.apply(key, out[key])
		if err != nil {
			return nil, err
		}
		if present {
			out[key] = result
		} else {
			delete(out, key)
		}
	}

	return out, nil
}

// applyPolicyToDocument decodes the raw document, applies the policy,
// and re-decodes the result into the typed Document. The two decode
// passes keep the policy JSON-generic (RFC 7591 names) while the typed
// struct stays the single source of field truth.
func applyPolicyToDocument(raw []byte, p Policy) (*Document, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("cimd: unable to decode document fields: %w", err)
	}

	applied, err := p.Apply(fields)
	if err != nil {
		return nil, err
	}

	next, err := json.Marshal(applied)
	if err != nil {
		return nil, fmt.Errorf("cimd: unable to encode policy-applied document: %w", err)
	}

	doc, err := DecodeDocument(next)
	if err != nil {
		return nil, fmt.Errorf("cimd: policy-applied document is invalid: %w", err)
	}
	return doc, nil
}

// -----------------------------------------------------------------------------
// Operator mechanics over raw JSON values.

// isJSONNull reports whether a raw JSON value is null.
func isJSONNull(v json.RawMessage) bool {
	return string(v) == "null"
}

// asStringArray decodes a raw value that must be a JSON array of
// strings (the mandatory operator shape for add/one_of/subset_of/
// superset_of values, and the array side of metadata values).
func asStringArray(v json.RawMessage) ([]string, error) {
	var arr []string
	if err := json.Unmarshal(v, &arr); err != nil {
		return nil, fmt.Errorf("expected an array of strings, got %s", jsonType(v))
	}
	return arr, nil
}

// jsonType names the JSON type of a raw value for error messages.
func jsonType(v json.RawMessage) string {
	switch v[0] {
	case '{':
		return "object"
	case '[':
		return "array"
	case '"':
		return "string"
	case 't', 'f':
		return "boolean"
	case 'n':
		return "null"
	default:
		return "number"
	}
}

// opAdd implements the add operator (spec 6.1.3.1.2): union into an
// array, dedup, initialize when absent.
func opAdd(current, add json.RawMessage) (json.RawMessage, error) {
	addVals, err := asStringArray(add)
	if err != nil {
		return nil, fmt.Errorf("operator value: %w", err)
	}
	if current == nil {
		return json.Marshal(addVals)
	}

	curVals, err := asStringArray(current)
	if err != nil {
		return nil, fmt.Errorf("metadata value: %w", err)
	}

	seen := make(map[string]struct{}, len(curVals)+len(addVals))
	merged := make([]string, 0, len(curVals)+len(addVals))
	for _, v := range curVals {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			merged = append(merged, v)
		}
	}
	for _, v := range addVals {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			merged = append(merged, v)
		}
	}
	return json.Marshal(merged)
}

// opOneOf implements the one_of operator (spec 6.1.3.1.4): the present
// value MUST be one of the listed values.
func opOneOf(current, oneOf json.RawMessage) error {
	allowed, err := asStringArray(oneOf)
	if err != nil {
		return fmt.Errorf("operator value: %w", err)
	}

	var scalar string
	if err := json.Unmarshal(current, &scalar); err != nil {
		return fmt.Errorf("metadata value must be a string for one_of, got %s", jsonType(current))
	}

	for _, a := range allowed {
		if a == scalar {
			return nil
		}
	}
	return fmt.Errorf("value %q is not among the allowed values", scalar)
}

// opSubsetOf implements the subset_of operator (spec 6.1.3.1.5 and
// Table 1): assign the intersection; the result may be empty. The
// absent+voluntary case is handled by the caller (apply skips absent
// parameters); absent+essential errors in apply's essential step.
func opSubsetOf(current, subset json.RawMessage) (json.RawMessage, error) {
	subVals, err := asStringArray(subset)
	if err != nil {
		return nil, fmt.Errorf("operator value: %w", err)
	}

	// scope is a space-separated string processed as an array of values
	// by policy operators (spec 6.1.3.1.8).
	if isStringCurrent(current) {
		return applySubsetToSpaceList(current, subVals)
	}

	curVals, err := asStringArray(current)
	if err != nil {
		return nil, fmt.Errorf("metadata value: %w", err)
	}

	allowed := make(map[string]struct{}, len(subVals))
	for _, v := range subVals {
		allowed[v] = struct{}{}
	}
	inter := make([]string, 0, len(curVals))
	seen := make(map[string]struct{}, len(curVals))
	for _, v := range curVals {
		if _, ok := allowed[v]; ok {
			if _, d := seen[v]; !d {
				seen[v] = struct{}{}
				inter = append(inter, v)
			}
		}
	}
	return json.Marshal(inter)
}

// isStringCurrent reports whether the raw metadata value is a JSON
// string (the space-separated-list form, e.g. scope).
func isStringCurrent(v json.RawMessage) bool {
	return len(v) > 0 && v[0] == '"'
}

// applySubsetToSpaceList applies subset_of to a space-separated string
// (the scope special case of spec 6.1.3.1.8): the parameter is processed
// as a string array; the output is a space-separated string of the
// surviving values, order preserved.
func applySubsetToSpaceList(current json.RawMessage, subVals []string) (json.RawMessage, error) {
	var s string
	if err := json.Unmarshal(current, &s); err != nil {
		return nil, err
	}
	allowed := make(map[string]struct{}, len(subVals))
	for _, v := range subVals {
		allowed[v] = struct{}{}
	}
	out := make([]string, 0, len(s))
	seen := make(map[string]struct{})
	for _, tok := range strings.Fields(s) {
		if _, ok := allowed[tok]; ok {
			if _, d := seen[tok]; !d {
				seen[tok] = struct{}{}
				out = append(out, tok)
			}
		}
	}
	return json.Marshal(strings.Join(out, " "))
}

// opSupersetOf implements the superset_of operator (spec 6.1.3.1.6):
// the present values MUST contain the listed values (equality included).
func opSupersetOf(current, superset json.RawMessage) error {
	supVals, err := asStringArray(superset)
	if err != nil {
		return fmt.Errorf("operator value: %w", err)
	}

	if isStringCurrent(current) {
		var s string
		if uerr := json.Unmarshal(current, &s); uerr != nil {
			return uerr
		}
		present := make(map[string]struct{})
		for _, tok := range strings.Fields(s) {
			present[tok] = struct{}{}
		}
		for _, want := range supVals {
			if _, ok := present[want]; !ok {
				return fmt.Errorf("space-separated value is missing %q", want)
			}
		}
		return nil
	}

	curVals, err := asStringArray(current)
	if err != nil {
		return fmt.Errorf("metadata value: %w", err)
	}
	present := make(map[string]struct{}, len(curVals))
	for _, v := range curVals {
		present[v] = struct{}{}
	}
	for _, want := range supVals {
		if _, ok := present[want]; !ok {
			return fmt.Errorf("array value is missing %q", want)
		}
	}
	return nil
}
