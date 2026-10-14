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
// (RFC 7591 client-metadata JSON names) mapped to their policy entries
// (single-level here: the Entity-Type layer of the spec is the AS's
// oauth_client role, fixed by this application). Validate enforces the
// spec's allowed operator combinations (section 6.1.3) and the null
// operator-value rules at decode time; duplicate JSON member names in
// the raw body are last-wins per encoding/json and are NOT detected —
// a strict token-walk would be needed if the policy ever becomes
// remotely sourced.
type Policy map[string]PolicyEntry

// DecodePolicy parses a client metadata policy JSON object. A null or
// non-object body is an error: a malformed policy must fail loud, not
// silently resolve into a pass-through (the policy is the deployment's
// security control).
func DecodePolicy(b []byte) (Policy, error) {
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" || trimmed == jsonNull {
		return nil, fmt.Errorf("cimd: policy body is empty or null")
	}
	var p Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("cimd: unable to decode policy: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

// scopeParameter is the single metadata parameter whose value is a
// space-separated string list processed as an array by policy
// operators (spec 6.1.3.1.8).
const scopeParameter = "scope"

const jsonNull = "null"

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
		// value: assign; null removes (spec 6.1.3.1.1). The scope
		// parameter's array form is assigned as the space-separated
		// string the Document expects (spec 6.1.3.1.8).
		switch {
		case isJSONNull(e.Value):
			current = nil
		case key == scopeParameter:
			next, verr := scopeSpaceForm(e.Value)
			if verr != nil {
				return nil, fmt.Errorf("cimd: policy value on %q: %w", key, verr)
			}
			current = next
		default:
			current = e.Value
		}
	}

	if e.Add != nil {
		next, err := opAdd(key, current, *e.Add)
		if err != nil {
			return nil, fmt.Errorf("cimd: policy add on %q: %w", key, err)
		}
		current = next
	}

	if e.Default != nil && current == nil {
		// default: fill absent only (spec 6.1.3.1.3). An operator MUST
		// NOT output a null metadata parameter (spec line 2332): null is
		// a legal value only for the value operator (6.1.3.1.1). The
		// scope parameter's array form is assigned as the
		// space-separated string (spec 6.1.3.1.8).
		if isJSONNull(*e.Default) {
			return nil, fmt.Errorf("cimd: policy default on %q: null is not a valid operator value", key)
		}
		if key == "scope" {
			next, derr := scopeSpaceForm(*e.Default)
			if derr != nil {
				return nil, fmt.Errorf("cimd: policy default on %q: %w", key, derr)
			}
			current = next
		} else {
			current = *e.Default
		}
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
		next, err := opSubsetOf(key, current, *e.SubsetOf)
		if err != nil {
			return nil, fmt.Errorf("cimd: policy subset_of on %q: %w", key, err)
		}
		current = next
	}

	if e.SupersetOf != nil {
		if err := opSupersetOf(key, current, *e.SupersetOf); err != nil {
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
	// Fold-variant member smuggling: the typed Document decode matches
	// struct fields case-insensitively (Go's Unicode simple-fold, last
	// occurrence wins), so a hostile document carrying a fold-variant of
	// a parameter name (e.g. U+017F long-s for "s", U+212A Kelvin sign
	// for "k") could sort after the exact key and silently overwrite the
	// policy-applied value at the typed decode. Reject any two member
	// names that fold-match while differing byte-wise; the raw-key seam
	// is the only place both spellings are visible.
	if err := rejectFoldVariantMembers(doc); err != nil {
		return nil, err
	}
	out := make(map[string]json.RawMessage, len(doc)+len(p))
	for k, v := range doc {
		out[k] = v
	}

	for key, entry := range p {
		if entry.empty() {
			continue
		}
		if strings.EqualFold(key, "client_id") {
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
	return string(v) == jsonNull
}

// maxArrayEntries bounds how many elements a single metadata or operator
// array may carry into a policy merge. Metadata documents are fetched
// client-controlled JSON of at most DefaultMaxResponseBytes; this cap keeps
// the merge memory deterministic (map/slice sizing in opAdd and the scope
// list union) even if the upstream document size cap is ever raised.
const maxArrayEntries = 512

// asStringArray decodes a raw value that must be a JSON array of
// strings (the mandatory operator shape for add/one_of/subset_of/
// superset_of values, and the array side of metadata values). Arrays
// longer than maxArrayEntries are rejected: a client-controlled array
// must never size server-side merge allocations without a bound.
func asStringArray(v json.RawMessage) ([]string, error) {
	var arr []string
	if err := json.Unmarshal(v, &arr); err != nil {
		return nil, fmt.Errorf("expected an array of strings, got %s", jsonType(v))
	}
	if len(arr) > maxArrayEntries {
		return nil, fmt.Errorf("array of %d entries exceeds the maximum of %d", len(arr), maxArrayEntries)
	}
	return arr, nil
}

// jsonType names the JSON type of a raw value for error messages.
func jsonType(v json.RawMessage) string {
	if len(v) == 0 {
		return "empty"
	}
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
// array, dedup, initialize when absent. The scope parameter's
// space-separated string form is processed as a string array per spec
// 6.1.3.1.8 — and only scope: other scalar-string values are a type
// error, not a token list.
func opAdd(key string, current, add json.RawMessage) (json.RawMessage, error) {
	addVals, err := asStringArray(add)
	if err != nil {
		return nil, fmt.Errorf("operator value: %w", err)
	}
	if current == nil {
		return json.Marshal(addVals)
	}

	if key == scopeParameter && isStringCurrent(current) {
		return addSpaceList(current, addVals)
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

// scopeSpaceForm serializes an array operator value into the
// space-separated string form the scope parameter carries (spec
// 6.1.3.1.8); a non-array value is a type error.
func scopeSpaceForm(v json.RawMessage) (json.RawMessage, error) {
	vals, err := asStringArray(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(strings.Join(vals, " "))
}

// addSpaceList unions addVals into a space-separated string value (the
// scope special case of spec 6.1.3.1.8): tokens deduped, order
// preserved, output re-joined as a space-separated string.
func addSpaceList(current json.RawMessage, addVals []string) (json.RawMessage, error) {
	var s string
	if err := json.Unmarshal(current, &s); err != nil {
		return nil, err
	}
	toks := strings.Fields(s)
	if len(toks)+len(addVals) > maxArrayEntries {
		return nil, fmt.Errorf("scope list of %d tokens exceeds the maximum of %d", len(toks)+len(addVals), maxArrayEntries)
	}
	seen := make(map[string]struct{}, len(toks)+len(addVals))
	out := make([]string, 0, len(toks)+len(addVals))
	for _, tok := range toks {
		if _, ok := seen[tok]; !ok {
			seen[tok] = struct{}{}
			out = append(out, tok)
		}
	}
	for _, tok := range addVals {
		if _, ok := seen[tok]; !ok {
			seen[tok] = struct{}{}
			out = append(out, tok)
		}
	}
	return json.Marshal(strings.Join(out, " "))
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
func opSubsetOf(key string, current, subset json.RawMessage) (json.RawMessage, error) {
	subVals, err := asStringArray(subset)
	if err != nil {
		return nil, fmt.Errorf("operator value: %w", err)
	}

	// The scope parameter's space-separated string form is processed as
	// a string array by policy operators (spec 6.1.3.1.8 — scope
	// specifically). Any other scalar string is a type error: silently
	// token-splitting it (and blanking the value on empty intersection)
	// would corrupt e.g. token_endpoint_auth_method.
	if isStringCurrent(current) {
		if key != scopeParameter {
			return nil, fmt.Errorf("metadata value is a string; only the scope parameter is processed as a space-separated list")
		}
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
func opSupersetOf(key string, current, superset json.RawMessage) error {
	supVals, err := asStringArray(superset)
	if err != nil {
		return fmt.Errorf("operator value: %w", err)
	}

	if isStringCurrent(current) {
		if key != scopeParameter {
			return fmt.Errorf("metadata value is a string; only the scope parameter is processed as a space-separated list")
		}
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

// rejectFoldVariantMembers fails when the raw document carries two
// member names that are Unicode simple-fold equal but byte-different.
// The typed Document decode (and the clientregistration path) matches
// JSON member names case-insensitively under last-occurrence-wins, so
// a fold variant of a parameter name could silently overwrite the
// policy-applied value at the typed decode. The raw-key seam is the
// only place both spellings are visible at once.
func rejectFoldVariantMembers(doc map[string]json.RawMessage) error {
	if len(doc) < 2 {
		return nil
	}
	folded := make(map[string]string, len(doc))
	for k := range doc {
		// Canonical fold is ToUpper-then-ToLower: a plain ToLower misses
		// the U+017F long-s (already lowercase; folds to "s" only via
		// its uppercase S). strings.EqualFold would also work pairwise
		// but the canonical map is O(n).
		f := strings.ToLower(strings.ToUpper(k))
		if first, ok := folded[f]; ok {
			return fmt.Errorf("cimd: document carries fold-variant duplicate members %q and %q", first, k)
		}
		folded[f] = k
	}
	return nil
}

// Validate enforces the spec's operator-combination rules (section
// 6.1.3: "Combinations that are not allowed MUST produce a policy
// error") and the JSON value-type rules of each operator definition
// (lines 2305-2310). It runs from DecodePolicy so an invalid policy
// fails at configuration load, not at first use.
//
// Rules (spec section references in parentheses):
//   - value+add:      the values of add MUST be a subset of value (2371)
//   - value+default:  allowed only if value is not null (2374)
//   - value+one_of:   the value of value MUST be among one_of (2376)
//   - value+subset_of: values of value MUST be a subset of subset_of (2379)
//   - value+superset_of: values of value MUST be a superset (2382)
//   - value+essential: allowed unless value is null AND essential true (2385)
//   - add+subset_of:  values of add MUST be a subset of subset_of (2428)
//   - one_of:         combines only with value/default/essential (2501-2508)
//   - subset_of+superset_of: subset_of MUST be a superset of superset_of (2557)
//   - default/add/superset_of operator values MUST NOT be null
//     (operators MUST NOT output null parameters, line 2332; null is a
//     legal operator value only for value, line 2367).
func (p Policy) Validate() error {
	for key, e := range p {
		// The client identifier match (draft section 4) is an invariant a
		// policy must not rewrite — rejected at configuration load, and
		// re-checked fold-insensitively (the typed decode is
		// case-insensitive, so a "client_iD" entry is the same attack).
		if strings.EqualFold(key, "client_id") {
			return fmt.Errorf("cimd: policy on %q is forbidden: it would rewrite the client identifier match", key)
		}
		if err := e.validate(key); err != nil {
			return err
		}
	}
	return nil
}

// validate runs the null-value and combination checks for one entry
// (both phases per spec section 6.1.3).
func (e PolicyEntry) validate(key string) error {
	if err := e.validateNulls(key); err != nil {
		return err
	}
	return e.validateCombinations(key)
}

// validateNulls rejects null operator values: null is a legal operator
// value only for value (spec line 2367; operators MUST NOT output null
// metadata parameters, line 2332).
func (e PolicyEntry) validateNulls(key string) error {
	if isJSONNull(e.Value) {
		if e.Default != nil {
			return fmt.Errorf("cimd: policy on %q: value null combines with default only when value is not null", key)
		}
		if e.Essential != nil && *e.Essential {
			return fmt.Errorf("cimd: policy on %q: value null cannot combine with essential true", key)
		}
	}
	if e.Default != nil && isJSONNull(*e.Default) {
		return fmt.Errorf("cimd: policy on %q: default must not be null", key)
	}
	if e.Add != nil && isJSONNull(*e.Add) {
		return fmt.Errorf("cimd: policy on %q: add must not be null", key)
	}
	if e.SupersetOf != nil && isJSONNull(*e.SupersetOf) {
		return fmt.Errorf("cimd: policy on %q: superset_of must not be null", key)
	}
	if e.OneOf != nil && isJSONNull(*e.OneOf) {
		return fmt.Errorf("cimd: policy on %q: one_of must not be null", key)
	}
	if e.SubsetOf != nil && isJSONNull(*e.SubsetOf) {
		return fmt.Errorf("cimd: policy on %q: subset_of must not be null", key)
	}
	return nil
}

// validateCombinations enforces the allowed-operator-combination rules
// of spec section 6.1.3 (each operator section's "Combination with
// other operators" clauses; line citations in each check).
func (e PolicyEntry) validateCombinations(key string) error {
	// one_of combines only with value, default, essential (spec 2501-2508).
	if e.OneOf != nil && (e.Add != nil || e.SubsetOf != nil || e.SupersetOf != nil) {
		return fmt.Errorf("cimd: policy on %q: one_of combines only with value, default and essential", key)
	}
	// value+one_of: the value must be among the one_of values (2376).
	if len(e.Value) > 0 && !isJSONNull(e.Value) && e.OneOf != nil {
		var val string
		if err := json.Unmarshal(e.Value, &val); err == nil {
			allowed, aerr := asStringArray(*e.OneOf)
			if aerr == nil && !containsString(allowed, val) {
				return fmt.Errorf("cimd: policy on %q: value %q is not among the one_of values", key, val)
			}
		}
	}
	// add ⊆ value (2371) and add ⊆ subset_of (2428): array-membership.
	if e.Add != nil {
		if err := e.validateAddSubset(key); err != nil {
			return err
		}
	}
	// value ⊆ subset_of (2379), value ⊇ superset_of (2382), and
	// subset_of ⊇ superset_of (2557): the array-containment matrix.
	return e.validateContainment(key)
}

// validateAddSubset enforces add ⊆ value (spec 2371) and add ⊆
// subset_of (spec 2428).
func (e PolicyEntry) validateAddSubset(key string) error {
	addVals, err := asStringArray(*e.Add)
	if err != nil {
		return fmt.Errorf("cimd: policy on %q: add %w", key, err)
	}
	if len(e.Value) > 0 && !isJSONNull(e.Value) {
		if valVals, verr := asStringArray(e.Value); verr == nil && !allContained(valVals, addVals) {
			return fmt.Errorf("cimd: policy on %q: add values must be a subset of the value values", key)
		}
	}
	if e.SubsetOf != nil {
		if subVals, serr := asStringArray(*e.SubsetOf); serr == nil && !allContained(subVals, addVals) {
			return fmt.Errorf("cimd: policy on %q: add values must be a subset of the subset_of values", key)
		}
	}
	return nil
}

// validateContainment enforces the array-containment combination
// rules: value ⊆ subset_of (2379), value ⊇ superset_of (2382), and
// subset_of ⊇ superset_of (2557).
func (e PolicyEntry) validateContainment(key string) error {
	if len(e.Value) > 0 && !isJSONNull(e.Value) {
		valVals, verr := asStringArray(e.Value)
		if verr == nil {
			if e.SubsetOf != nil {
				if subVals, serr := asStringArray(*e.SubsetOf); serr == nil && !allContained(subVals, valVals) {
					return fmt.Errorf("cimd: policy on %q: value values must be a subset of the subset_of values", key)
				}
			}
			if e.SupersetOf != nil {
				if supVals, serr := asStringArray(*e.SupersetOf); serr == nil && !allContained(valVals, supVals) {
					return fmt.Errorf("cimd: policy on %q: value values must be a superset of the superset_of values", key)
				}
			}
		}
	}
	if e.SubsetOf != nil && e.SupersetOf != nil {
		if subVals, serr := asStringArray(*e.SubsetOf); serr == nil {
			if supVals, uerr := asStringArray(*e.SupersetOf); uerr == nil && !allContained(subVals, supVals) {
				return fmt.Errorf("cimd: policy on %q: subset_of values must be a superset of the superset_of values", key)
			}
		}
	}
	return nil
}

// containsString reports whether the list contains the value.
func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// allContained reports whether every element of subset appears in
// superset (array membership for the combination rules).
func allContained(superset, subset []string) bool {
	set := make(map[string]struct{}, len(superset))
	for _, s := range superset {
		set[s] = struct{}{}
	}
	for _, s := range subset {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}

// UnmarshalJSON decodes a policy entry, rejecting explicit JSON null
// operator values for the pointer-typed operators: encoding/json
// decodes null into a nil pointer, making `{"default": null}`
// indistinguishable from an absent default — and the spec forbids null
// operator values for everything except value (line 2367; operators
// MUST NOT output null parameters, line 2332). value is exempt: null
// is its documented removal semantic (6.1.3.1.1).
func (e *PolicyEntry) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	for op, v := range raw {
		switch op {
		case "value", "essential":
			// value: null is the documented removal operator; essential
			// decodes null as the zero false — both handled elsewhere.
		case "add", "default", "one_of", "subset_of", "superset_of":
			if string(v) == jsonNull {
				return fmt.Errorf("cimd: policy operator %q must not be null", op)
			}
		default:
			// Unknown operator member: the policy is operator-authored
			// security configuration, not a third-party federation chain
			// — a typo must fail loud (the spec's ignore-unknown-operators
			// allowance fits remote policies, not local config).
			return fmt.Errorf("cimd: unknown policy operator %q", op)
		}
	}
	type plain PolicyEntry
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	*e = PolicyEntry(p)
	return nil
}
