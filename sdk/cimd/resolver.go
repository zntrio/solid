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

package cimd

import (
	"context"
	"fmt"
	"strings"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/server/storage"
)

// -----------------------------------------------------------------------------

// Fetcher retrieves the raw Client ID Metadata Document body for a Client
// Identifier URL. It is transport-agnostic; the hardened HTTP presentation
// adapter is sdk/httpfetch (httpfetch.Fetcher satisfies this interface
// structurally).
//
//go:generate mockgen -destination mock/fetcher.gen.go -package mock zntr.io/solid/sdk/cimd Fetcher

type Fetcher interface {
	Fetch(ctx context.Context, clientIdentifierURL string) ([]byte, error)
}

// Resolver resolves a CIMD client identifier into a Client.
//
//go:generate mockgen -destination mock/resolver.gen.go -package mock zntr.io/solid/sdk/cimd Resolver

type Resolver interface {
	Resolve(ctx context.Context, clientID string) (*clientv1.Client, error)
}

// -----------------------------------------------------------------------------

type resolver struct {
	fetcher Fetcher
}

// NewResolver builds a pure, cache-less Resolver over the given Fetcher.
// Caching (draft section 5.2, MAY) and fetch policy belong to decorators at
// assembly level, keeping the mechanism composable.
func NewResolver(f Fetcher) Resolver {
	return &resolver{fetcher: f}
}

// Resolve implements the Client Information Discovery flow (draft section 5):
// fetch the document at the Client Identifier URL and validate it (section 4)
// before mapping it to an internal Client.
func (r *resolver) Resolve(ctx context.Context, clientID string) (*clientv1.Client, error) {
	if clientID == "" {
		return nil, storage.ErrNotFound
	}

	// Non-CIMD identifiers are out of scope (draft section 3).
	if !IsClientIdentifierURL(clientID) {
		return nil, fmt.Errorf("cimd: %q is not a client identifier url: %w", clientID, storage.ErrNotFound)
	}

	// Fetch the raw document.
	b, err := r.fetcher.Fetch(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("cimd: unable to fetch document: %w", err)
	}

	// Decode the JSON document.
	doc, err := DecodeDocument(b)
	if err != nil {
		return nil, err
	}

	// The document's client_id MUST match the Client Identifier URL using
	// simple string comparison (draft section 4).
	if doc.ClientID != clientID {
		return nil, fmt.Errorf("cimd: document client_id %q does not match client identifier url", doc.ClientID)
	}

	// Credential and key material restrictions (draft section 4.1) and
	// mapping to the internal representation.
	return doc.ToClient()
}

// AllowlistFilter resolves only the client identifiers explicitly allowed
// by the authorization server; anything else is refused before any
// document fetch happens. The authorization server MUST be explicitly
// authorized to pull a Client ID Metadata Document from a remote host:
// CIMD resolution is a server-side fetch triggered by an unauthenticated
// client identifier value, so the host surface must be pinned by the
// operator, not by the caller.
type AllowlistFilter struct {
	next Resolver
	// allowed holds the exact Client Identifier URLs (or URL prefixes
	// ending in "/") the authorization server is authorized to resolve.
	allowed []string
}

// NewAllowlistFilter decorates next so only explicitly allowed client
// identifiers reach it. Entries are matched by simple string comparison, or
// as URL prefixes when they end in a slash (host-level grants, e.g.
// "https://partner.example.org/").
func NewAllowlistFilter(next Resolver, allowed ...string) *AllowlistFilter {
	return &AllowlistFilter{next: next, allowed: allowed}
}

// Resolve implements Resolver: it refuses identifiers that are not
// explicitly allowed before delegating.
func (f *AllowlistFilter) Resolve(ctx context.Context, clientID string) (*clientv1.Client, error) {
	if clientID == "" {
		return nil, storage.ErrNotFound
	}
	if !cimdAllowed(f.allowed, clientID) {
		return nil, fmt.Errorf("cimd: %q is not an authorized client identifier url: %w", clientID, storage.ErrNotFound)
	}
	return f.next.Resolve(ctx, clientID)
}

var _ Resolver = (*AllowlistFilter)(nil)

// cimdAllowed reports whether id matches one of the allowlist entries, by
// exact string comparison or as a URL prefix for entries ending in a slash.
func cimdAllowed(allowed []string, id string) bool {
	for _, a := range allowed {
		if a == id {
			return true
		}
		if strings.HasSuffix(a, "/") && strings.HasPrefix(id, a) {
			return true
		}
	}
	return false
}
