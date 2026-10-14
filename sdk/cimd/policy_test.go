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
	// value applies First; one_of then validates the ASSIGNED value
	// (spec 6.1.3.1.4 combination: "the value of value MUST be among the
	// one_of values" — the operator application enforces it on the wire).
	p := mustPolicy(t, `{"token_endpoint_auth_method": {"value": "client_secret_basic", "one_of": ["private_key_jwt"]}}`)
	_, err := applyTo(t, p, `{}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "one_of")
}

func TestPolicyClientIDEntryForbidden(t *testing.T) {
	p := mustPolicy(t, `{"client_id": {"value": "https://attacker.example.com/doc"}}`)
	_, err := applyTo(t, p, `{"client_id": "https://example.com/client.json"}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client_id")
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
