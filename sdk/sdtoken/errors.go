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

import "errors"

// Selective disclosure processing errors, shared by every serialization
// format (RFC 9901 section 7.1, draft-ietf-spice-sd-cwt-08 section 9).
var (
	// ErrInvalidDisclosure marks a structurally invalid disclosure: wrong
	// arity for its redaction site, invalid salt, or a reserved claim key.
	ErrInvalidDisclosure = errors.New("invalid disclosure")

	// ErrClaimCollision marks a disclosed claim key colliding with an
	// existing plaintext claim key at the same level.
	ErrClaimCollision = errors.New("disclosed claim key collides with an existing claim")

	// ErrDuplicateDigest marks the same digest appearing twice in the
	// disclosure input.
	ErrDuplicateDigest = errors.New("duplicate disclosure digest")

	// ErrUnreferencedDisclosure marks a disclosure whose digest matches no
	// redaction site: under holder semantics this is a completeness
	// violation, under verifier semantics an unsolicited disclosure.
	ErrUnreferencedDisclosure = errors.New("disclosure does not match any redaction site")

	// ErrUnmatchedDigest marks (holder semantics) a redaction site whose
	// digest has no matching disclosure where one is required.
	ErrUnmatchedDigest = errors.New("redaction site has no matching disclosure")

	// ErrUnsupportedHashAlgorithm marks a hash algorithm outside the
	// sha-256-only posture of both specs.
	ErrUnsupportedHashAlgorithm = errors.New("unsupported hash algorithm")

	// ErrReservedClaimKey marks a claim key using a reserved redaction
	// marker name in a context where it would be ambiguous.
	ErrReservedClaimKey = errors.New("reserved claim key")
)
