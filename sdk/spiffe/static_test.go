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
	"testing"

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"zntr.io/solid/sdk/jwk"
)

func TestStaticBundleSource(t *testing.T) {
	newSet := func(t *testing.T) jwk.Set {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		k, err := jwxjwk.Import(key.Public())
		require.NoError(t, err)
		set := jwxjwk.NewSet()
		require.NoError(t, set.Set("keys", []jwxjwk.Key{k}))
		return set
	}

	t.Run("known trust domain", func(t *testing.T) {
		set := newSet(t)
		src := NewStaticBundleSource(map[string]jwk.Set{"example.org": set})
		got, err := src.Get(context.Background(), "example.org")
		require.NoError(t, err)
		assert.Equal(t, 1, got.Len())
	})

	t.Run("unknown trust domain", func(t *testing.T) {
		src := NewStaticBundleSource(map[string]jwk.Set{"example.org": newSet(t)})
		_, err := src.Get(context.Background(), "other.org")
		assert.Error(t, err)
	})

	t.Run("input map is copied", func(t *testing.T) {
		original := map[string]jwk.Set{"example.org": newSet(t)}
		src := NewStaticBundleSource(original)
		original["evil.org"] = newSet(t)
		_, err := src.Get(context.Background(), "evil.org")
		assert.Error(t, err)
	})
}
