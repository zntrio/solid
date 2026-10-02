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

// Package sdcwt implements the draft-ietf-spice-sd-cwt-08 Selective
// Disclosure CBOR Web Token wire format on top of the wire-agnostic
// sdk/sdtoken core: the CBOR disclosure codec, redacted_claim_keys
// (simple 59) / tag-60 element placement, COSE_Sign1 SD-CWT and KBT
// issuance, and the Issuer / Holder / Verifier role assemblies.
package sdcwt

import (
	"context"
)

const (
	// MediaTypeSdCWT is the SD-CWT typ protected header value (draft
	// section 4): SHOULD be the integer 293.
	MediaTypeSdCWT uint = 293

	// MediaTypeKbCWT is the SD-CWT Key Binding Token typ protected
	// header value (draft section 4).
	MediaTypeKbCWT uint = 294

	// HeaderLabelSdClaims is the unprotected sd_claims header label:
	// an array of bstr-encoded Salted Disclosed Claims (draft section 7).
	HeaderLabelSdClaims int64 = 17

	// HeaderLabelSdAlg is the protected sd_alg header label (draft
	// section 9): -16 designates sha-256.
	HeaderLabelSdAlg int64 = 170

	// HashAlgSHA256 is the only supported disclosure hash algorithm
	// (COSE algorithm -16, sha-256): both spec profiles are
	// sha-256-only here, everything else is rejected.
	HashAlgSHA256 int64 = -16

	// ClaimKeyCnf is the COSE confirmation claim key (RFC 8747).
	ClaimKeyCnf = 8

	// ClaimKeyCwtCoseKey is the cnf nested COSE_Key key (1).
	ClaimKeyCwtCoseKey = 1

	// ClaimKeyAud is the CWT audience claim key (3).
	ClaimKeyAud = 3

	// ClaimKeyExp is the CWT expiration claim key (4).
	ClaimKeyExp = 4

	// ClaimKeyNbf is the CWT not-before claim key (5).
	ClaimKeyNbf = 5

	// ClaimKeyIat is the CWT issued-at claim key (6).
	ClaimKeyIat = 6

	// ClaimKeyCti is the CWT token id claim key (7).
	ClaimKeyCti = 7

	// ClaimKeyCnonce is the SD-CWT KBT cnonce claim key (39).
	ClaimKeyCnonce = 39
)

// saltedClaimSaltLen is the mandatory disclosure salt length: 128 bits
// (draft section 6.1).
const saltedClaimSaltLen = 16

//go:generate mockgen -destination mock/issuer.gen.go -package mock zntr.io/solid/sdk/sdtoken/sdcwt Issuer

// Issuer creates SD-CWTs (draft-ietf-spice-sd-cwt-08 Issuer role).
type Issuer interface {
	// Issue creates an SD-CWT for the given claims: selectively
	// disclosable positions are marked with sdtoken.Disclosable /
	// sdtoken.DisclosableElement values. It returns the COSE_Sign1
	// SD-CWT bytes and the disclosure list (bstr-encoded Salted
	// Disclosed Claims, walk order; decoy disclosures appended).
	Issue(ctx context.Context, claims map[any]any, opts ...IssueOption) (sdcwt []byte, disclosures [][]byte, err error)
}

//go:generate mockgen -destination mock/holder.gen.go -package mock zntr.io/solid/sdk/sdtoken/sdcwt Holder

// Holder consumes issued SD-CWTs and builds presentations and key
// binding tokens (draft Holder role).
type Holder interface {
	// Present rebuilds the SD-CWT with only the selected disclosures
	// in sd_claims.
	Present(issued []byte, selected [][]byte) ([]byte, error)

	// KeyBind builds the KBT (a COSE_Sign1 key binding token, draft
	// section 8) embedding the presentation.
	KeyBind(presentation []byte, audience string, cnonce []byte, opts ...KeyBindOption) ([]byte, error)
}

//go:generate mockgen -destination mock/verifier.gen.go -package mock zntr.io/solid/sdk/sdtoken/sdcwt Verifier

// Verifier processes SD-CWT KBTs (draft section 9).
type Verifier interface {
	// Verify validates the KBT and returns the Validated Disclosed
	// Claims Set.
	Verify(ctx context.Context, kbt []byte) (map[any]any, error)
}
