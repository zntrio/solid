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

import "zntr.io/solid/sdk/token"

// -----------------------------------------------------------------------------
// draft-forten-oauth-sd-jwt-access-token-00 token-class profiles.

// Profile describes one token class carrying selectively disclosable
// claims: the draft-forten access-token profile and the ID-token
// generalization are two instances. The profile is format-agnostic: the
// same descriptor drives the JWT (draft-forten) and CWT (SD-CWT based)
// serialization adapters.
type Profile struct {
	// Name is a stable identifier ("access_token", "id_token").
	Name string

	// BaseTyp is the token base type used to derive the typ header
	// (token.HeaderType(base, "JWT") -> "<base>+jwt"; ... "CWT" ->
	// "application/<base>+cwt").
	BaseTyp string

	// ExpectedTyp is the exact typ the verifier enforces on the JWT
	// serialization ("at+jwt" / "id+jwt"); the CWT adapters map it to the
	// COSE media-type form ("application/at+cwt" /
	// "application/id+cwt"). RFC 8725 section 3.11 explicit-typ: an
	// exact match, so cross-profile typ confusion is rejected.
	ExpectedTyp string

	// ProtectedClaims are the claim names that MUST NOT be selectively
	// disclosable for this token class: everything a relying party
	// validates to trust the token stays in the signed payload
	// (draft-forten section 3 / OIDC Core section 2).
	ProtectedClaims map[string]struct{}
}

// stringSet builds a claim-name set.
func stringSet(names ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(names))
	for _, n := range names {
		out[n] = struct{}{}
	}
	return out
}

var AccessTokenProfile = Profile{
	Name:        "access_token",
	BaseTyp:     token.TypeAccessToken,
	ExpectedTyp: "at+jwt",
	ProtectedClaims: stringSet(
		// Draft-forten section 3: RFC 9068 protocol claims stay in the
		// payload — "a resource server MUST NOT read an undisclosed
		// claim as permission". The same clause extends to any claim
		// whose absence would widen what the token permits, such as
		// act with everything nested in it (RFC 8693 delegation).
		"iss", "sub", "aud", "exp", "nbf", "iat", "jti",
		"client_id", "cnf", "scope", "authorization_details",
		"act", "may_act",
	),
}

// IDTokenProfile generalizes the draft-forten selective-disclosure
// posture to OIDC Core ID tokens: the claims an RP validates are
// protected, user claims (email, name, address, ...) are the disclosable
// ones. No standard mints SD ID tokens today — this profile is an SDK
// surface for assemblies; the repo posture (no id_token in the
// authorization code flow) is untouched.
var IDTokenProfile = Profile{
	Name:        "id_token",
	BaseTyp:     token.TypeIDToken,
	ExpectedTyp: "id+jwt",
	ProtectedClaims: stringSet(
		// OIDC Core section 2: iss, sub, aud, exp, iat and every
		// validation-relevant claim stay in the signed payload.
		"iss", "sub", "aud", "exp", "nbf", "iat", "jti",
		"nonce", "auth_time", "azp", "acr", "amr",
		"at_hash", "c_hash", "sid", "cnf",
		// OIDC Core section 10 / RFC 8693: may_act / act name the
		// (authorized) actor — permission claims, never disclosable.
		"may_act", "act",
	),
}

// -----------------------------------------------------------------------------
// draft-forten wire constants.

const (
	// FieldDisclosures is the HTTP field carrying the presented
	// Disclosures: a Structured Fields List of Strings (RFC 9651),
	// draft-forten section 4.
	FieldDisclosures = "SD-JWT-Disclosures"

	// FieldKeyBinding is the HTTP field carrying the optional key
	// binding JWT: a Structured Fields Item that is a String,
	// draft-forten section 4.
	FieldKeyBinding = "SD-JWT-Key-Binding"

	// ResponseParameterDisclosures is the token response parameter
	// carrying the Disclosures of the access token (draft-forten
	// section 4).
	ResponseParameterDisclosures = "disclosures"

	// ResponseParameterIDTokenDisclosures is the reserved name for
	// carrying the Disclosures of an SD ID token in a token response
	// once a grant handler mints one. No RFC defines ID-token
	// disclosure carriage; the repo generalization mirrors the
	// draft-forten `disclosures` semantics under a parallel name.
	// No server surface emits it today.
	ResponseParameterIDTokenDisclosures = "id_token_disclosures"

	// TypeKeyBindingJWT is the typ of the key binding JWT
	// (draft-forten section 4).
	TypeKeyBindingJWT = "kb+jwt"

	// HashAlg is the disclosure digest hash algorithm: sha-256 only
	// (draft-forten section 4, RFC 9901 section 4.2.3).
	HashAlg = "sha-256"
)
