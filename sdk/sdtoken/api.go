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

// Package sdtoken implements the wire-agnostic core of selective
// disclosure credentials: disclosure generation (forgery) and processing
// for redaction markers, salts, digests and decoys, with a deterministic
// claim-tree walk and a nesting-validation fixpoint engine. The
// serialization formats (RFC 9901 SD-JWT, draft-ietf-spice-sd-cwt-08
// SD-CWT) plug in through the FormatAdapter interface; this package
// deliberately imports no JOSE or CBOR machinery.
package sdtoken

// Disclosable marks a map value as selectively disclosable (object
// property form; RFC 9901 section 4.2.1 / draft-ietf-spice-sd-cwt-08
// section 4.1 map form). The original map key names the claim; the
// key+value move into the disclosure.
type Disclosable struct {
	Value any
}

// DisclosableElement marks an array element as selectively disclosable
// (RFC 9901 section 4.2.2 / draft-ietf-spice-sd-cwt-08 section 4.1
// element form).
type DisclosableElement struct {
	Value any
}

// DecodedDisclosure is a parsed wire disclosure.
//
// ClaimKey == nil marks the array-element form (2-element array); non-nil
// marks the map form (3-element array). IsDecoy marks the 1-element decoy
// form (draft-ietf-spice-sd-cwt-08 section 10; decoy disclosures only
// exist on the CBOR side — RFC 9901 decoys are bare digests with no
// disclosure at all).
type DecodedDisclosure struct {
	// Salt is the 128-bit salt (RFC 9901 section 9.3 / draft section 6.1).
	Salt []byte
	// ClaimKey is the disclosed claim key: string (JSON) or
	// uint64/int64/string (CBOR). nil for the element form.
	ClaimKey any
	// Value is the disclosed claim value.
	Value any
	// Digest is the normalized lookup key: base64url(sha256(wireEncoding))
	// (both formats; the raw digest bytes only exist on the CBOR wire).
	Digest string
	// IsDecoy marks the 1-element decoy disclosure form.
	IsDecoy bool
	// Wire is the exact serialized form the digest was computed over.
	Wire []byte
}

// SiteKind describes the placement of a redaction site.
type SiteKind int

const (
	// KindMap: the digest sits in the level-local digest array (_sd /
	// redacted_claim_keys) and stands for a redacted map key+value pair.
	KindMap SiteKind = iota
	// KindElement: the digest sits inside an array as a redacted element
	// ({"...": digest} / tag 60(bstr)).
	KindElement
)

// RedactionSite describes one place a digest is embedded in a claim tree.
type RedactionSite struct {
	// Kind is the site placement.
	Kind SiteKind
	// Digest is the normalized digest lookup key.
	Digest string
	// Parent is the map containing the digest array (KindMap) or the
	// array holding the redacted element (KindElement).
	Parent any
	// Index is the index into the digest array (KindMap) / the element
	// array (KindElement).
	Index int
	// ClaimKey is reserved for future use (always nil today).
	ClaimKey any
}

// FormatAdapter adapts the core walk and processing engine to one
// serialization format. Implemented by the JSON (SD-JWT) and CBOR
// (SD-CWT) format packages.
type FormatAdapter interface {
	// ClaimTreeDigestSites enumerates every RedactionSite at any depth of
	// the decoded claim tree (JSON: "_sd" arrays + {"...": digest}
	// elements; CBOR: simple(59) arrays + tag-60 elements).
	ClaimTreeDigestSites(root any) ([]RedactionSite, error)

	// InsertMapClaim inserts key/value at the site's parent map. A key
	// collision MUST return ErrClaimCollision.
	InsertMapClaim(site RedactionSite, key, value any) error

	// ReplaceElement swaps the array element at the site for the
	// disclosed value.
	ReplaceElement(site RedactionSite, value any) error

	// RemoveElement deletes an undisclosed redacted element from its
	// array.
	RemoveElement(site RedactionSite) error

	// StripDigestContainer removes the digest-array entry (_sd /
	// redacted_claim_keys) from its parent map once processing at that
	// level completes.
	StripDigestContainer(site RedactionSite) error
}
