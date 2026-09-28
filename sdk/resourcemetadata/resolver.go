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

package resourcemetadata

import (
	"context"
	"fmt"

	discoveryv1 "zntr.io/solid/api/oidc/discovery/v1"
)

// Fetcher retrieves the raw Protected Resource Metadata document body at a
// URL. It is transport-agnostic; the hardened HTTP presentation adapter is
// sdk/httpfetch (httpfetch.Fetcher satisfies this interface structurally).
type Fetcher interface {
	Fetch(ctx context.Context, documentURL string) ([]byte, error)
}

// SignedMetadataVerifier verifies a signed_metadata JWT (RFC 9728
// section 2.2). Implementations validate the JWS signature against keys
// belonging to the issuer and trust the issuer; a nil error means accepted.
type SignedMetadataVerifier interface {
	Verify(ctx context.Context, resource string, signedMetadata string) error
}

// Resolver resolves a protected resource identifier into validated
// Protected Resource Metadata (RFC 9728 section 3).
type Resolver interface {
	Resolve(ctx context.Context, resourceIdentifier string) (*discoveryv1.ProtectedResourceMetadata, error)
}

// -----------------------------------------------------------------------------

// DefaultMaxDocumentBytes caps fetched metadata document bodies. Metadata
// documents are small; the RFC gives no size guidance, so this is a
// defensive limit with headroom for multi-language members.
const DefaultMaxDocumentBytes int64 = 64 * 1024

type resolver struct {
	fetcher          Fetcher
	metadataVerifier SignedMetadataVerifier
	maxDocumentBytes int64
}

// NewResolver builds a Resolver over the given Fetcher.
//
//   - metadataVerifier == nil → fail-closed: a document carrying
//     signed_metadata is rejected (RFC 9728 sections 2.2 and 3.3 treat an
//     unverifiable attestation as an error; an unverifiable attestation is
//     neither silently trusted nor silently dropped).
//   - maxDocumentBytes <= 0 → DefaultMaxDocumentBytes. The cap is enforced
//     on the resolver itself, independently of the Fetcher, as defense in
//     depth.
func NewResolver(fetcher Fetcher, metadataVerifier SignedMetadataVerifier, maxDocumentBytes int64) Resolver {
	if maxDocumentBytes <= 0 {
		maxDocumentBytes = DefaultMaxDocumentBytes
	}
	return &resolver{
		fetcher:          fetcher,
		metadataVerifier: metadataVerifier,
		maxDocumentBytes: maxDocumentBytes,
	}
}

// Resolve implements the Protected Resource Metadata consumer flow
// (RFC 9728 section 3): build the well-known URL from the identifier, fetch
// the document, decode and validate it, then enforce the section 3.3
// impersonation countermeasure.
func (r *resolver) Resolve(ctx context.Context, resourceIdentifier string) (*discoveryv1.ProtectedResourceMetadata, error) {
	// Well-known URL construction (sections 3 and 3.1).
	u, err := WellKnownURL(resourceIdentifier, WellKnownSuffix)
	if err != nil {
		return nil, err
	}

	// Fetch the raw document.
	b, err := r.fetcher.Fetch(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("resourcemetadata: unable to fetch document at %q: %w", u, err)
	}

	// Resolver-level size cap, defense in depth: the resolver accepts any
	// Fetcher implementation, including ones that do not cap bodies.
	if int64(len(b)) > r.maxDocumentBytes {
		return nil, fmt.Errorf("resourcemetadata: document at %q is %d bytes, exceeding the %d byte limit", u, len(b), r.maxDocumentBytes)
	}

	// Decode and defensively validate (section 2).
	md, err := DecodeProtectedResourceMetadata(b)
	if err != nil {
		return nil, err
	}

	// Impersonation countermeasure (section 3.3, threat model section 7.3):
	// metadata fetched at a well-known URL derived from identifier X MUST
	// NOT be used when it claims to describe resource Y. Comparison is
	// simple string comparison (code-point comparison).
	if md.GetResource() != resourceIdentifier {
		return nil, fmt.Errorf("resourcemetadata: resource %q does not match expected resource identifier %q", md.GetResource(), resourceIdentifier)
	}

	// signed_metadata handling (section 2.2): fail-closed without a
	// verifier; with one, the verifier's decision is honored. When verified,
	// the plain document is returned as-is; merging signed claims over
	// plain values is consumer policy.
	if v := md.GetSignedMetadata(); v != "" {
		if r.metadataVerifier == nil {
			return nil, fmt.Errorf("resourcemetadata: document for %q carries signed_metadata but no verifier is configured", resourceIdentifier)
		}
		if err := r.metadataVerifier.Verify(ctx, resourceIdentifier, v); err != nil {
			return nil, fmt.Errorf("resourcemetadata: signed_metadata verification failed: %w", err)
		}
	}

	return md, nil
}
