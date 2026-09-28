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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWellKnownURL(t *testing.T) {
	t.Run("default suffix on bare host", func(t *testing.T) {
		got, err := WellKnownURL("https://resource.example.com", "")
		require.NoError(t, err)
		assert.Equal(t, "https://resource.example.com/.well-known/oauth-protected-resource", got)
	})

	t.Run("default suffix on host with trailing slash", func(t *testing.T) {
		got, err := WellKnownURL("https://resource.example.com/", "")
		require.NoError(t, err)
		assert.Equal(t, "https://resource.example.com/.well-known/oauth-protected-resource", got)
	})

	t.Run("path is preserved after insertion", func(t *testing.T) {
		got, err := WellKnownURL("https://resource.example.com/resource1", "")
		require.NoError(t, err)
		assert.Equal(t, "https://resource.example.com/.well-known/oauth-protected-resource/resource1", got)
	})

	t.Run("port is preserved", func(t *testing.T) {
		got, err := WellKnownURL("https://127.0.0.1:8085", "")
		require.NoError(t, err)
		assert.Equal(t, "https://127.0.0.1:8085/.well-known/oauth-protected-resource", got)
	})

	t.Run("query is preserved", func(t *testing.T) {
		got, err := WellKnownURL("https://resource.example.com/resource1?tenant=a", "")
		require.NoError(t, err)
		assert.Equal(t, "https://resource.example.com/.well-known/oauth-protected-resource/resource1?tenant=a", got)
	})

	t.Run("multi-tenant path and query combined", func(t *testing.T) {
		got, err := WellKnownURL("https://resource.example.com/tenant1/api?version=2", "")
		require.NoError(t, err)
		assert.Equal(t, "https://resource.example.com/.well-known/oauth-protected-resource/tenant1/api?version=2", got)
	})

	t.Run("custom suffix", func(t *testing.T) {
		got, err := WellKnownURL("https://resource.example.com", "oauth-protected-resource")
		require.NoError(t, err)
		assert.Equal(t, "https://resource.example.com/.well-known/oauth-protected-resource", got)
	})

	t.Run("custom suffix with slash is rejected", func(t *testing.T) {
		_, err := WellKnownURL("https://resource.example.com", "a/b")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must not contain")
	})

	t.Run("http scheme is rejected", func(t *testing.T) {
		_, err := WellKnownURL("http://resource.example.com", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "https scheme")
	})

	t.Run("empty scheme is rejected", func(t *testing.T) {
		_, err := WellKnownURL("resource.example.com", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "https scheme")
	})

	t.Run("fragment is rejected", func(t *testing.T) {
		_, err := WellKnownURL("https://resource.example.com/resource1#frag", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "fragment")
	})

	t.Run("empty fragment marker is rejected", func(t *testing.T) {
		_, err := WellKnownURL("https://resource.example.com#", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "fragment")
	})

	t.Run("empty identifier is rejected", func(t *testing.T) {
		_, err := WellKnownURL("", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "https scheme")
	})
}
