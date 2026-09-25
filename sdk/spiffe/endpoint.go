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

package spiffe

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"zntr.io/solid/sdk/jwk"
)

// -----------------------------------------------------------------------------

// BundleFetcher retrieves the raw SPIFFE bundle document body at a given
// bundle endpoint URL. It is transport-agnostic; the hardened HTTP
// presentation adapter is sdk/httpfetch (httpfetch.Fetcher satisfies this
// interface structurally, WebPKI flavor per draft section 6.1).
type BundleFetcher interface {
	Fetch(ctx context.Context, bundleEndpointURL string) ([]byte, error)
}

// bundleDocument is the wire format served by a SPIFFE bundle endpoint: a
// JWKS (RFC 7517) with the SPIFFE extension members spiffe_sequence and
// spiffe_refresh_hint (seconds) as defined by SPIFFE Federation.
type bundleDocument struct {
	Keys              json.RawMessage `json:"keys"`
	SpiffeSequence    int64           `json:"spiffe_sequence"`
	SpiffeRefreshHint int64           `json:"spiffe_refresh_hint"`
}

type cacheEntry struct {
	set         jwk.Set
	fetchedAt   time.Time
	refreshHint time.Duration
}

type endpointBundleSource struct {
	endpoints       map[string]string
	fetcher         BundleFetcher
	refreshInterval time.Duration
	now             func() time.Time

	mu    sync.Mutex
	cache map[string]cacheEntry
}

// NewBundleEndpointSource builds a BundleSource over explicitly configured
// SPIFFE bundle endpoints (draft section 6.1). Endpoints are keyed by trust
// domain identifier: a bundle endpoint cannot be derived from an SVID and
// MUST be configured out of band.
//
// Bundles are fetched lazily and cached; a cached bundle is re-fetched when
// now - lastFetch >= max(spiffe_refresh_hint, refreshInterval). The
// refreshInterval is the assembly's defensive floor for the draft's SHOULD
// poll guidance: a hint below it (or absent) is clamped up to it. On a
// failed refresh the last known good bundle is still served.
func NewBundleEndpointSource(endpoints map[string]string, fetcher BundleFetcher, refreshInterval time.Duration) BundleSource {
	copied := make(map[string]string, len(endpoints))
	for td, ep := range endpoints {
		copied[td] = ep
	}
	if refreshInterval <= 0 {
		refreshInterval = time.Hour
	}
	return &endpointBundleSource{
		endpoints:       copied,
		fetcher:         fetcher,
		refreshInterval: refreshInterval,
		now:             time.Now,
		cache:           make(map[string]cacheEntry),
	}
}

// Get returns the (cached) trust bundle for the trust domain, refreshing it
// when the refresh hint (or the minimum refresh interval) has expired.
func (s *endpointBundleSource) Get(ctx context.Context, trustDomain string) (jwk.Set, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	endpoint, ok := s.endpoints[trustDomain]
	if !ok {
		return nil, fmt.Errorf("spiffe: no bundle endpoint configured for trust domain %q", trustDomain)
	}

	entry, cached := s.cache[trustDomain]
	now := s.now()

	// Serve from cache while fresh.
	if cached && now.Sub(entry.fetchedAt) < s.refreshAfter(entry.refreshHint) {
		return entry.set, nil
	}

	// Re-fetch (first fetch or expired hint).
	set, hint, err := s.fetch(ctx, endpoint)
	if err != nil {
		if cached {
			// Serve the last known good bundle; the endpoint being
			// transiently unavailable must not break client authentication.
			return entry.set, nil
		}
		return nil, fmt.Errorf("spiffe: unable to fetch bundle for trust domain %q: %w", trustDomain, err)
	}

	s.cache[trustDomain] = cacheEntry{
		set:         set,
		fetchedAt:   now,
		refreshHint: hint,
	}
	return set, nil
}

// refreshAfter resolves the effective refresh period for a cached bundle:
// the larger of the bundle's spiffe_refresh_hint and the configured minimum
// refresh interval.
func (s *endpointBundleSource) refreshAfter(hint time.Duration) time.Duration {
	if hint > s.refreshInterval {
		return hint
	}
	return s.refreshInterval
}

// fetch retrieves and parses a bundle endpoint document.
func (s *endpointBundleSource) fetch(ctx context.Context, endpoint string) (jwk.Set, time.Duration, error) {
	b, err := s.fetcher.Fetch(ctx, endpoint)
	if err != nil {
		return nil, 0, err
	}

	var doc bundleDocument
	if err = json.Unmarshal(b, &doc); err != nil {
		return nil, 0, fmt.Errorf("invalid bundle document: %w", err)
	}
	if len(doc.Keys) == 0 {
		return nil, 0, fmt.Errorf("bundle document has no keys")
	}

	set, err := jwk.Parse(doc.Keys)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid bundle keys: %w", err)
	}
	if set.Len() == 0 {
		return nil, 0, fmt.Errorf("bundle document has no keys")
	}

	// spiffe_refresh_hint is in seconds; 0 or missing means "no hint", the
	// configured minimum refresh interval applies.
	hint := time.Duration(doc.SpiffeRefreshHint) * time.Second
	return set, hint, nil
}

var _ BundleSource = (*endpointBundleSource)(nil)
