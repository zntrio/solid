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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fetchFunc adapts a function to BundleFetcher.
type fetchFunc func(ctx context.Context, url string) ([]byte, error)

func (f fetchFunc) Fetch(ctx context.Context, url string) ([]byte, error) {
	return f(ctx, url)
}

// bundleJSON renders a bundle endpoint document in the draft section 6.1.1
// shape.
func bundleJSON(t *testing.T, refreshHint int64) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	k, err := jwxjwk.Import(key.Public())
	require.NoError(t, err)
	require.NoError(t, k.Set(jwxjwk.KeyUsageKey, KeyUseJWTSVID))
	b, err := json.Marshal(k)
	require.NoError(t, err)
	doc := map[string]any{
		"keys":                json.RawMessage(b),
		"spiffe_sequence":     10,
		"spiffe_refresh_hint": refreshHint,
	}
	out, err := json.Marshal(doc)
	require.NoError(t, err)
	return out
}

func TestEndpointBundleSource(t *testing.T) {
	t.Run("first fetch parses and caches", func(t *testing.T) {
		calls := 0
		src := NewBundleEndpointSource(
			map[string]string{"example.org": "https://bundle.example.com/bundle.json"},
			fetchFunc(func(_ context.Context, _ string) ([]byte, error) {
				calls++
				return bundleJSON(t, 300), nil
			}),
			time.Hour,
		).(*endpointBundleSource)

		set, err := src.Get(context.Background(), "example.org")
		require.NoError(t, err)
		assert.Equal(t, 1, set.Len())
		assert.Equal(t, 1, calls)

		// Second Get is served from cache (no new fetch).
		set2, err := src.Get(context.Background(), "example.org")
		require.NoError(t, err)
		assert.Same(t, set, set2)
		assert.Equal(t, 1, calls)
	})

	t.Run("refresh after refresh hint expiry", func(t *testing.T) {
		calls := 0
		src := NewBundleEndpointSource(
			map[string]string{"example.org": "https://bundle.example.com/bundle.json"},
			fetchFunc(func(_ context.Context, _ string) ([]byte, error) {
				calls++
				return bundleJSON(t, 1), nil
			}),
			time.Hour,
		).(*endpointBundleSource)

		now := time.Now()
		src.now = func() time.Time { return now }

		_, err := src.Get(context.Background(), "example.org")
		require.NoError(t, err)
		assert.Equal(t, 1, calls)

		// Hint (1s) < min interval (1h): still cached.
		_, err = src.Get(context.Background(), "example.org")
		require.NoError(t, err)
		assert.Equal(t, 1, calls)

		// After 1h the min interval expires -> refetch.
		now = now.Add(time.Hour)
		_, err = src.Get(context.Background(), "example.org")
		require.NoError(t, err)
		assert.Equal(t, 2, calls)
	})

	t.Run("hint above interval controls refresh", func(t *testing.T) {
		calls := 0
		src := NewBundleEndpointSource(
			map[string]string{"example.org": "https://bundle.example.com/bundle.json"},
			fetchFunc(func(_ context.Context, _ string) ([]byte, error) {
				calls++
				return bundleJSON(t, 3600), nil
			}),
			time.Minute,
		).(*endpointBundleSource)

		now := time.Now()
		src.now = func() time.Time { return now }

		_, err := src.Get(context.Background(), "example.org")
		require.NoError(t, err)
		assert.Equal(t, 1, calls)

		// Min interval (1m) expired but hint (1h) not: cached.
		now = now.Add(2 * time.Minute)
		_, err = src.Get(context.Background(), "example.org")
		require.NoError(t, err)
		assert.Equal(t, 1, calls)

		// Hint expired -> refetch.
		now = now.Add(time.Hour)
		_, err = src.Get(context.Background(), "example.org")
		require.NoError(t, err)
		assert.Equal(t, 2, calls)
	})

	t.Run("missing refresh hint uses interval", func(t *testing.T) {
		calls := 0
		src := NewBundleEndpointSource(
			map[string]string{"example.org": "https://bundle.example.com/bundle.json"},
			fetchFunc(func(_ context.Context, _ string) ([]byte, error) {
				calls++
				return bundleJSON(t, 0), nil
			}),
			time.Minute,
		).(*endpointBundleSource)

		now := time.Now()
		src.now = func() time.Time { return now }

		_, err := src.Get(context.Background(), "example.org")
		require.NoError(t, err)
		// Interval expired -> refetch.
		now = now.Add(2 * time.Minute)
		_, err = src.Get(context.Background(), "example.org")
		require.NoError(t, err)
		assert.Equal(t, 2, calls)
	})

	t.Run("fetch failure serves stale bundle", func(t *testing.T) {
		calls := 0
		failing := false
		src := NewBundleEndpointSource(
			map[string]string{"example.org": "https://bundle.example.com/bundle.json"},
			fetchFunc(func(_ context.Context, _ string) ([]byte, error) {
				calls++
				if failing {
					return nil, errors.New("endpoint down")
				}
				return bundleJSON(t, 1), nil
			}),
			time.Minute,
		).(*endpointBundleSource)

		now := time.Now()
		src.now = func() time.Time { return now }

		good, err := src.Get(context.Background(), "example.org")
		require.NoError(t, err)

		now = now.Add(2 * time.Minute)
		failing = true
		stale, err := src.Get(context.Background(), "example.org")
		require.NoError(t, err)
		assert.Same(t, good, stale)
	})

	t.Run("fetch failure with no cache errors", func(t *testing.T) {
		src := NewBundleEndpointSource(
			map[string]string{"example.org": "https://bundle.example.com/bundle.json"},
			fetchFunc(func(_ context.Context, _ string) ([]byte, error) {
				return nil, errors.New("endpoint down")
			}),
			time.Minute,
		)
		_, err := src.Get(context.Background(), "example.org")
		assert.Error(t, err)
	})

	t.Run("unknown trust domain", func(t *testing.T) {
		src := NewBundleEndpointSource(
			map[string]string{"example.org": "https://bundle.example.com/bundle.json"},
			fetchFunc(func(_ context.Context, _ string) ([]byte, error) {
				t.Fatal("must not be called")
				return nil, nil
			}),
			time.Minute,
		)
		_, err := src.Get(context.Background(), "other.org")
		assert.Error(t, err)
	})

	t.Run("invalid bundle document", func(t *testing.T) {
		src := NewBundleEndpointSource(
			map[string]string{"example.org": "https://bundle.example.com/bundle.json"},
			fetchFunc(func(_ context.Context, _ string) ([]byte, error) {
				return []byte(`{"keys":[]}`), nil
			}),
			time.Minute,
		)
		_, err := src.Get(context.Background(), "example.org")
		assert.Error(t, err)
	})
}
