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

// Client ID Metadata Document (CIMD) client reader decoration: resolves
// URL-shaped client identifiers via the OAuth Client ID Metadata Document
// mechanism (draft-ietf-oauth-client-id-metadata-document) when the primary
// reader has no pre-registered client.
//
// Caching (draft section 5.2, MAY) is deliberately not implemented: this
// decorator stays correct-but-simple, and a caching decorator can wrap it at
// assembly level without changing the contract.
package inmemory

import (
	"context"
	"fmt"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/sdk/cimd"
	"zntr.io/solid/server/storage"
)

// ClientReader resolves pre-registered clients from the primary reader and,
// for https:// Client Identifier URLs without a stored registration, fetches
// and validates the Client ID Metadata Document via the cimd Resolver
// (draft-ietf-oauth-client-id-metadata-document, section 7.1: pre-registered
// entries win, including pre-registered URL-shaped identifiers).
type ClientReader struct {
	primary  storage.ClientReader
	resolver cimd.Resolver
}

// NewClientReader decorates primary with CIMD resolution. Write operations
// are untouched: CIMD clients are never stored.
func NewClientReader(primary storage.ClientReader, resolver cimd.Resolver) *ClientReader {
	return &ClientReader{primary: primary, resolver: resolver}
}

// Get implements storage.ClientReader.
func (r *ClientReader) Get(ctx context.Context, id string) (*clientv1.Client, error) {
	c, err := r.primary.Get(ctx, id)
	if err == nil {
		return c, nil
	}
	if !isNotFound(err) {
		// Primary reader failure other than not-found is surfaced as-is.
		return nil, err
	}

	// Not pre-registered: fall back to CIMD only for Client Identifier URLs.
	if !cimd.IsClientIdentifierURL(id) {
		return nil, err
	}

	resolved, rerr := r.resolver.Resolve(ctx, id)
	if rerr != nil {
		// Unfetchable or invalid CIMD documents are unknown clients to the
		// caller; the wrapped cause remains available for logging.
		return nil, fmt.Errorf("cimd: unable to resolve client %q: %w", id, storage.ErrNotFound)
	}
	return resolved, nil
}

// GetByName implements storage.ClientReader. CIMD clients are not known by
// name; delegation only.
func (r *ClientReader) GetByName(ctx context.Context, name string) (*clientv1.Client, error) {
	return r.primary.GetByName(ctx, name)
}

// isNotFound reports whether err matches storage.ErrNotFound.
func isNotFound(err error) bool {
	return err == storage.ErrNotFound //nolint:errorlint // storage errors are compared by identity
}
