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

// Package sdjwt implements the RFC 9901 Selective Disclosure for JWT
// wire format on top of the wire-agnostic sdk/sdtoken core: the JSON
// disclosure codec, _sd / "..." placement, compact serialization, and
// the Issuer / Holder / Verifier role assemblies.
package sdjwt

import (
	"context"
)

const (
	// TypeKeyBinding is the KB-JWT typ header value (RFC 9901 section
	// 4.3): exact match, REQUIRED.
	TypeKeyBinding = "kb+jwt"

	// ClaimSDAlg is the hash algorithm claim name ("_sd_alg").
	ClaimSDAlg = "_sd_alg"

	// ClaimSD is the per-level digest array claim name ("_sd").
	ClaimSD = "_sd"

	// ClaimSDHash is the KB-JWT sd_hash claim name.
	ClaimSDHash = "sd_hash"

	// arrayElementKey is the redacted-array-element marker key ("...",
	// RFC 9901 section 4.2.4.2).
	arrayElementKey = "..."
)

// HashAlgorithm names a disclosure digest hash algorithm. Only sha-256
// is supported: both specs MUST support it, and the project posture
// rejects everything else rather than negotiating down.
type HashAlgorithm string

// HashSHA256 is the single supported hash algorithm (RFC 9901
// section 4.2.3; both spec profiles are sha-256-only here).
const HashSHA256 HashAlgorithm = "sha-256"

// SDJWT is a parsed RFC 9901 section 4 compact serialization.
type SDJWT struct {
	// IssuerSignedJWT is the first component.
	IssuerSignedJWT string
	// Disclosures are the base64url disclosure components, in order.
	Disclosures []string
	// KeyBindingJWT is the trailing component: "" when the presentation
	// carries no KB-JWT, a JWT for SD-JWT+KB.
	KeyBindingJWT string
}

// Parse splits a raw SD-JWT / SD-JWT+KB compact serialization
// (RFC 9901 section 4): the last component is "" (plain SD-JWT) or a
// JWT (SD-JWT+KB); anything else is an error.
func Parse(raw string) (SDJWT, error) {
	// Check argument
	if raw == "" {
		return SDJWT{}, ErrInvalidSDJWT
	}

	// Split on tildes.
	parts := splitTilde(raw)
	if len(parts) < 2 {
		return SDJWT{}, ErrInvalidSDJWT
	}

	// First component must be a JWT.
	jwtPart := parts[0]
	if !isCompactJWT(jwtPart) {
		return SDJWT{}, ErrInvalidSDJWT
	}

	// The last component is either empty (SD-JWT, trailing "~") or a
	// KB-JWT (SD-JWT+KB).
	last := parts[len(parts)-1]
	switch {
	case last == "":
		// SD-JWT: JWT~D1~...~Dn~ (possibly n == 0: JWT~)
		return SDJWT{
			IssuerSignedJWT: jwtPart,
			Disclosures:     parts[1 : len(parts)-1],
			KeyBindingJWT:   "",
		}, nil
	case isCompactJWT(last):
		// SD-JWT+KB: JWT~D1~...~Dn~KB
		return SDJWT{
			IssuerSignedJWT: jwtPart,
			Disclosures:     parts[1 : len(parts)-1],
			KeyBindingJWT:   last,
		}, nil
	default:
		return SDJWT{}, ErrInvalidSDJWT
	}
}

// Serialize reassembles the compact serialization, following the
// RFC 9901 section 4 trailing-tilde rules: a trailing "~" with no
// KB-JWT, none with one.
func (s SDJWT) Serialize() string {
	out := s.IssuerSignedJWT
	for _, d := range s.Disclosures {
		out += "~" + d
	}
	if s.KeyBindingJWT == "" {
		return out + "~"
	}
	return out + "~" + s.KeyBindingJWT
}

// splitTilde splits on "~" like strings.Split but tolerates an empty
// trailing component: "a~b~" -> ["a", "b", ""].
func splitTilde(raw string) []string {
	var parts []string
	start := 0
	for i := range len(raw) {
		if raw[i] == '~' {
			parts = append(parts, raw[start:i])
			start = i + 1
		}
	}
	parts = append(parts, raw[start:])
	return parts
}

// isCompactJWT syntactically checks for a three-dot-separated JWT.
func isCompactJWT(s string) bool {
	if s == "" {
		return false
	}
	dots := 0
	for i := range len(s) {
		if s[i] == '.' {
			dots++
		}
	}
	return dots == 2
}

//go:generate mockgen -destination mock/issuer.gen.go -package mock zntr.io/solid/sdk/sdtoken/sdjwt Issuer

// Issuer creates SD-JWTs (RFC 9901 section 5.1 Issuer role).
type Issuer interface {
	// Issue creates an SD-JWT for the given claims: selectively
	// disclosable positions are marked with sdtoken.Disclosable /
	// sdtoken.DisclosableElement values. It returns the compact-serialized
	// SD-JWT (all disclosures, trailing "~") and the disclosure list in
	// deterministic walk order.
	Issue(ctx context.Context, claims map[string]any, opts ...IssueOption) (sdjwt string, disclosures []string, err error)
}

//go:generate mockgen -destination mock/holder.gen.go -package mock zntr.io/solid/sdk/sdtoken/sdjwt Holder

// Holder consumes issued SD-JWTs and builds presentations (RFC 9901
// section 7.2 Holder role).
type Holder interface {
	// Present builds an SD-JWT presentation from a selected subset of
	// the issued disclosures.
	Present(issued string, selected ...string) (string, error)

	// KeyBind attaches a KB-JWT to a presentation, returning SD-JWT+KB.
	// sd_hash is computed over the presentation as presented (including
	// its trailing "~").
	KeyBind(presentation, nonce, audience string, issuedAt int64) (string, error)
}

//go:generate mockgen -destination mock/verifier.gen.go -package mock zntr.io/solid/sdk/sdtoken/sdjwt Verifier

// Verifier processes SD-JWT / SD-JWT+KB presentations (RFC 9901
// sections 7.1 and 7.3).
type Verifier interface {
	// Verify validates the presentation (signature, key binding,
	// temporal claims) and returns the Processed SD-JWT Payload.
	Verify(ctx context.Context, presentation string) (map[string]any, error)
}
