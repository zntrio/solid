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

func TestDecodeProtectedResourceMetadata(t *testing.T) {
	t.Run("full document round-trips", func(t *testing.T) {
		doc := `{
			"resource": "https://resource.example.com/",
			"authorization_servers": ["https://as.example.com"],
			"jwks_uri": "https://resource.example.com/jwks",
			"scopes_supported": ["read", "write"],
			"resource_name": "Example Resource",
			"bearer_methods_supported": ["header"],
			"tls_client_certificate_bound_access_tokens": true,
			"authorization_details_types_supported": ["payment"],
			"dpop_signing_alg_values_supported": ["ES256"],
			"dpop_bound_access_tokens_required": false
		}`
		md, err := DecodeProtectedResourceMetadata([]byte(doc))
		require.NoError(t, err)
		assert.Equal(t, "https://resource.example.com/", md.GetResource())
		assert.Equal(t, []string{"https://as.example.com"}, md.GetAuthorizationServers())
		assert.Equal(t, "https://resource.example.com/jwks", md.GetJwksUri())
		assert.Equal(t, []string{"read", "write"}, md.GetScopesSupported())
		require.NotNil(t, md.ResourceName)
		assert.Equal(t, "Example Resource", md.GetResourceName())
		assert.True(t, md.GetTlsClientCertificateBoundAccessTokens())
		assert.Equal(t, []string{"payment"}, md.GetAuthorizationDetailsTypesSupported())
		assert.Equal(t, []string{"ES256"}, md.GetDpopSigningAlgValuesSupported())
		assert.False(t, md.GetDpopBoundAccessTokensRequired())
	})

	t.Run("unknown members are ignored", func(t *testing.T) {
		doc := `{"resource": "https://resource.example.com/", "resource_name#fr": "Exemple", "future_member": 42}`
		md, err := DecodeProtectedResourceMetadata([]byte(doc))
		require.NoError(t, err)
		assert.Equal(t, "https://resource.example.com/", md.GetResource())
	})

	t.Run("missing resource member is rejected", func(t *testing.T) {
		_, err := DecodeProtectedResourceMetadata([]byte(`{"jwks_uri": "https://resource.example.com/jwks"}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), `"resource"`)
	})

	t.Run("non-https resource is rejected", func(t *testing.T) {
		_, err := DecodeProtectedResourceMetadata([]byte(`{"resource": "http://resource.example.com/"}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "https scheme")
	})

	t.Run("resource with fragment is rejected", func(t *testing.T) {
		_, err := DecodeProtectedResourceMetadata([]byte(`{"resource": "https://resource.example.com/#frag"}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "fragment")
	})

	t.Run("scopes_supported JSON name decodes into ScopesSupported", func(t *testing.T) {
		doc := `{"resource": "https://resource.example.com/", "scopes_supported": ["timestamp:read"]}`
		md, err := DecodeProtectedResourceMetadata([]byte(doc))
		require.NoError(t, err)
		assert.Equal(t, []string{"timestamp:read"}, md.ScopesSupported)
	})

	t.Run("http jwks_uri is rejected", func(t *testing.T) {
		_, err := DecodeProtectedResourceMetadata([]byte(`{"resource": "https://resource.example.com/", "jwks_uri": "http://resource.example.com/jwks"}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "jwks_uri")
	})

	t.Run("none signing alg is rejected", func(t *testing.T) {
		_, err := DecodeProtectedResourceMetadata([]byte(`{"resource": "https://resource.example.com/", "resource_signing_alg_values_supported": ["ES256", "none"]}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "none")
	})

	t.Run("invalid JSON is rejected", func(t *testing.T) {
		_, err := DecodeProtectedResourceMetadata([]byte(`{not-json`))
		require.Error(t, err)
	})
}
