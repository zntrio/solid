// Licensed to SolID under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. SolID licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. See the License for the
// specific language governing permissions and limitations
// under the License.

package cimd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mustPolicy decodes a JSON policy, failing the test on error.
func mustPolicy(t *testing.T, s string) Policy {
	t.Helper()
	p, err := DecodePolicy([]byte(s))
	require.NoError(t, err)
	return p
}

// applyTo decodes a JSON document, applies the policy, and returns the
// raw result as a generic map.
func applyTo(t *testing.T, policy Policy, doc string) (map[string]json.RawMessage, error) {
	t.Helper()
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(doc), &fields))
	return policy.Apply(fields)
}

// mustApply applies and re-marshals to a JSON string for assertions.
func mustApply(t *testing.T, policy Policy, doc string) string {
	t.Helper()
	out, err := applyTo(t, policy, doc)
	require.NoError(t, err)
	b, err := json.Marshal(out)
	require.NoError(t, err)
	return string(b)
}

func TestPolicyValueAssigns(t *testing.T) {
	p := mustPolicy(t, `{"token_endpoint_auth_method": {"value": "private_key_jwt"}}`)
	out := mustApply(t, p, `{"token_endpoint_auth_method": "none"}`)
	assert.Contains(t, out, `"private_key_jwt"`)
}

func TestPolicyValueNullRemoves(t *testing.T) {
	// Spec 6.1.3.1.1: "When the value of the operator is null, the
	// metadata parameter MUST be removed."
	p := mustPolicy(t, `{"scope": {"value": null}}`)
	out := mustApply(t, p, `{"scope": "openid profile"}`)
	assert.NotContains(t, out, "scope")
}

func TestPolicyValueInitializesAbsent(t *testing.T) {
	p := mustPolicy(t, `{"response_types": {"value": ["code"]}}`)
	out := mustApply(t, p, `{}`)
	assert.Contains(t, out, `"response_types":["code"]`)
}

func TestPolicyAddUnionsAndDedups(t *testing.T) {
	// Spec 6.1.3.1.2: values already present MUST NOT be added again;
	// absent parameter initialized with the operator value.
	p := mustPolicy(t, `{"redirect_uris": {"add": ["https://two.example.com/cb", "https://one.example.com/cb"]}}`)
	out := mustApply(t, p, `{"redirect_uris": ["https://one.example.com/cb"]}`)
	assert.Contains(t, out, `"https://one.example.com/cb"`)
	assert.Contains(t, out, `"https://two.example.com/cb"`)
	assert.Equal(t, 2, strings.Count(out, "https://"))
}

func TestPolicyAddInitializesAbsent(t *testing.T) {
	p := mustPolicy(t, `{"contacts": {"add": ["admin@example.com"]}}`)
	out := mustApply(t, p, `{}`)
	assert.Contains(t, out, `"contacts":["admin@example.com"]`)
}

func TestPolicyDefaultFillsAbsentOnly(t *testing.T) {
	// Spec 6.1.3.1.3: "If the metadata parameter is present, this
	// operator has no effect."
	p := mustPolicy(t, `{"subject_type": {"default": "pairwise"}}`)
	out := mustApply(t, p, `{}`)
	assert.Contains(t, out, `"subject_type":"pairwise"`)

	out = mustApply(t, p, `{"subject_type": "public"}`)
	assert.Contains(t, out, `"subject_type":"public"`)
}

func TestPolicyOneOfAcceptsAndRejects(t *testing.T) {
	// Spec 6.1.3.1.4: "If the metadata parameter is present, its value
	// MUST be one of those listed in the operator value."
	p := mustPolicy(t, `{"token_endpoint_auth_method": {"one_of": ["private_key_jwt", "none"]}}`)

	out := mustApply(t, p, `{"token_endpoint_auth_method": "none"}`)
	assert.Contains(t, out, `"none"`)

	// absent: no error (essential governs absence)
	out = mustApply(t, p, `{}`)
	assert.NotContains(t, out, "token_endpoint_auth_method")

	_, err := applyTo(t, p, `{"token_endpoint_auth_method": "client_secret_basic"}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "one_of")
}

func TestPolicySubsetOfIntersection(t *testing.T) {
	// Spec 6.1.3.1.5 + Table 1: intersection, possibly empty.
	p := mustPolicy(t, `{"grant_types": {"subset_of": ["authorization_code", "refresh_token"]}}`)

	out := mustApply(t, p, `{"grant_types": ["authorization_code", "password", "refresh_token"]}`)
	assert.Contains(t, out, `"grant_types":["authorization_code","refresh_token"]`)

	// empty intersection survives (Table 1 rows 1-2)
	out = mustApply(t, p, `{"grant_types": ["password"]}`)
	assert.Contains(t, out, `"grant_types":[]`)

	// absent + voluntary: skipped (Table 1 last row)
	out = mustApply(t, p, `{}`)
	assert.NotContains(t, out, "grant_types")
}

func TestPolicySubsetOfEssentialAbsentErrors(t *testing.T) {
	// Table 1 row: essential true + no parameter -> error.
	p := mustPolicy(t, `{"grant_types": {"subset_of": ["authorization_code"], "essential": true}}`)
	_, err := applyTo(t, p, `{}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "essential")
}

func TestPolicySupersetOf(t *testing.T) {
	// Spec 6.1.3.1.6: values MUST contain those specified; equality
	// included.
	p := mustPolicy(t, `{"grant_types": {"superset_of": ["authorization_code"]}}`)

	out := mustApply(t, p, `{"grant_types": ["authorization_code", "refresh_token"]}`)
	assert.Contains(t, out, "authorization_code")

	out = mustApply(t, p, `{"grant_types": ["authorization_code"]}`)
	assert.Contains(t, out, "authorization_code")

	_, err := applyTo(t, p, `{"grant_types": ["refresh_token"]}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "superset_of")
}

func TestPolicyEssentialTrueRequiresPresence(t *testing.T) {
	p := mustPolicy(t, `{"jwks_uri": {"essential": true}}`)
	_, err := applyTo(t, p, `{"client_name": "x"}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "essential")

	// present: fine
	out := mustApply(t, p, `{"jwks_uri": "https://example.com/jwks"}`)
	assert.Contains(t, out, "jwks_uri")
}

func TestPolicyScopeSpaceSeparatedList(t *testing.T) {
	// Spec 6.1.3.1.8: scope is "regarded and processed as a string array
	// by policy operators"; the output is a space-separated string.
	p := mustPolicy(t, `{"scope": {"subset_of": ["openid", "profile", "email"]}}`)
	out := mustApply(t, p, `{"scope": "openid profile"}`)
	assert.Contains(t, out, `"scope":"openid profile"`)

	out = mustApply(t, p, `{"scope": "openid address admin"}`)
	assert.Contains(t, out, `"scope":"openid"`)

	p2 := mustPolicy(t, `{"scope": {"superset_of": ["openid"]}}`)
	_, err := applyTo(t, p2, `{"scope": "profile email"}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "superset_of")
}

func TestPolicyOrderValueShortCircuitsCheckersViaApplication(t *testing.T) {
	// value+one_of combination (spec 6.1.3.1.4: "the value of value MUST
	// be among the one_of values") is enforced at policy validation
	// (decode) time — an invalid policy fails loud before it is ever
	// applied.
	_, err := DecodePolicy([]byte(`{"token_endpoint_auth_method": {"value": "client_secret_basic", "one_of": ["private_key_jwt"]}}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "one_of")

	// The same combination with a conforming value decodes and applies.
	p := mustPolicy(t, `{"token_endpoint_auth_method": {"value": "private_key_jwt", "one_of": ["private_key_jwt", "none"]}}`)
	out := mustApply(t, p, `{}`)
	assert.Contains(t, out, `"private_key_jwt"`)
}

func TestPolicyClientIDEntryForbidden(t *testing.T) {
	// Rejected at policy decode (configuration load), not first use.
	_, err := DecodePolicy([]byte(`{"client_id": {"value": "https://attacker.example.com/doc"}}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client identifier match")
}

func TestPolicyUnknownParametersPassThrough(t *testing.T) {
	p := mustPolicy(t, `{"subject_type": {"default": "pairwise"}}`)
	out := mustApply(t, p, `{"client_name": "Example", "logo_uri": "https://example.com/logo.png"}`)
	assert.Contains(t, out, "client_name")
	assert.Contains(t, out, "logo_uri")
}

func TestPolicyEmptyEntryNoOp(t *testing.T) {
	p := mustPolicy(t, `{"scope": {}}`)
	out := mustApply(t, p, `{"scope": "openid"}`)
	assert.Contains(t, out, `"scope":"openid"`)
}

func TestPolicyFoldVariantMemberSmugglingRejected(t *testing.T) {
	// Unicode fold-orbit duplicate member names (e.g. U+017F long-s for
	// "s") decode case-insensitively with last-occurrence-wins into the
	// typed Document, silently overwriting the policy-applied value.
	// The raw-key seam rejects them before application.
	p := mustPolicy(t, `{"grant_types": {"subset_of": ["client_credentials"]}}`)
	_, err := applyTo(t, p, `{
	  "client_id": "https://c.example.org/x",
	  "grant_types": ["client_credentials"],
	  "grant_typeſ": ["urn:ietf:params:oauth:grant-type:device_code"]
	}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fold-variant")
}

func TestPolicyClientIDGuardFoldInsensitive(t *testing.T) {
	_, err := DecodePolicy([]byte(`{"client_iD": {"value": "https://evil.example.com/x"}}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client identifier match")
}

func TestPolicyCombinationValidation(t *testing.T) {
	// Spec 6.1.3: "Combinations that are not allowed MUST produce a
	// policy error" — enforced at decode time.
	for name, policy := range map[string]string{
		"add not subset of value":               `{"x": {"value": ["a"], "add": ["b"]}}`,
		"add not subset of subset_of":           `{"x": {"add": ["z"], "subset_of": ["a"]}}`,
		"value not subset of subset_of":         `{"x": {"value": ["z"], "subset_of": ["a"]}}`,
		"value not superset of superset_of":     `{"x": {"value": ["a"], "superset_of": ["a", "b"]}}`,
		"value not in one_of":                   `{"x": {"value": "z", "one_of": ["a", "b"]}}`,
		"value null + essential true":           `{"x": {"value": null, "essential": true}}`,
		"value null + default":                  `{"x": {"value": null, "default": "a"}}`,
		"one_of + subset_of":                    `{"x": {"one_of": ["a"], "subset_of": ["a"]}}`,
		"default null":                          `{"x": {"default": null}}`,
		"subset_of not superset of superset_of": `{"x": {"subset_of": ["a"], "superset_of": ["a", "b"]}}`,
	} {
		_, err := DecodePolicy([]byte(policy))
		require.Error(t, err, "%s must be rejected", name)
	}

	// Conforming combinations decode.
	mustPolicy(t, `{"x": {"value": ["a"], "add": ["a"], "essential": true}}`)
	mustPolicy(t, `{"x": {"value": "a", "one_of": ["a", "b"], "essential": true}}`)
	mustPolicy(t, `{"x": {"add": ["a"], "subset_of": ["a", "b"], "superset_of": ["b"]}}`)
}

func TestPolicyDecodeRejectsNullAndEmptyBody(t *testing.T) {
	// A malformed policy must fail loud, not silently resolve into a
	// pass-through: the policy is the deployment's security control.
	for name, body := range map[string]string{
		"null body":  `null`,
		"empty body": ``,
		"  body":     `   `,
	} {
		_, err := DecodePolicy([]byte(body))
		require.Error(t, err, "%s must be rejected", name)
	}
}

func TestPolicySubsetOfScalarNonScopeIsTypeError(t *testing.T) {
	// Only scope is processed as a space-separated list (spec
	// 6.1.3.1.8); a scalar string under any other parameter is a type
	// error — never silently blanked into a weaker-but-valid value.
	p := mustPolicy(t, `{"token_endpoint_auth_method": {"subset_of": ["private_key_jwt"]}}`)
	_, err := applyTo(t, p, `{"token_endpoint_auth_method": "none"}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "space-separated")

	p2 := mustPolicy(t, `{"client_name": {"superset_of": ["Evil"]}}`)
	_, err = applyTo(t, p2, `{"client_name": "Evil Ltd"}`)
	require.Error(t, err)
}

func TestPolicyScopeAddStringForm(t *testing.T) {
	// Spec 6.1.3.1.8: scope is processed as a string array by policy
	// operators — add unions tokens and re-emits the space-separated
	// string.
	p := mustPolicy(t, `{"scope": {"add": ["email"]}}`)
	out := mustApply(t, p, `{"scope": "openid profile"}`)
	assert.Contains(t, out, `"scope":"openid profile email"`)
}

func TestPolicyValueArrayForScope(t *testing.T) {
	// Array-valued value/default on scope must round-trip as the
	// space-separated string the Document expects.
	p := mustPolicy(t, `{"scope": {"value": ["openid", "email"]}}`)
	out := mustApply(t, p, `{"scope": "openid"}`)
	assert.Contains(t, out, `"scope":"openid email"`)
}

func TestPolicyRejectsOversizedArray(t *testing.T) {
	// A client-controlled metadata array must never size server-side
	// merge allocations without a bound: an array longer than
	// maxArrayEntries is a policy failure (the client is unknown).
	tooMany := strings.Repeat(`"x",`, maxArrayEntries) + `"x"`
	p := mustPolicy(t, `{"contacts": {"add": ["admin@example.com"]}}`)
	_, err := applyTo(t, p, `{"contacts": [`+tooMany+`]}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds the maximum")
}

func TestPolicyAcceptsArrayAtCap(t *testing.T) {
	// Exactly maxArrayEntries is the boundary: accepted, merged.
	atCap := strings.Repeat(`"x",`, maxArrayEntries-1) + `"x"`
	p := mustPolicy(t, `{"contacts": {"add": ["admin@example.com"]}}`)
	out, err := applyTo(t, p, `{"contacts": [`+atCap+`]}`)
	require.NoError(t, err)
	assert.Contains(t, string(out["contacts"]), "admin@example.com")
}

func TestPolicyRejectsOversizedScopeTokenList(t *testing.T) {
	// The scope special case merges a space-separated string (spec
	// 6.1.3.1.8): the token count is capped like array entries so a
	// hostile scope string cannot bypass the array bound.
	toks := strings.Repeat("x ", maxArrayEntries) + "x"
	p := mustPolicy(t, `{"scope": {"add": ["email"]}}`)
	_, err := applyTo(t, p, `{"scope": "`+toks+`"}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds the maximum")
}
