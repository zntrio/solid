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

package httpkit_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptoRand "crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"

	discoveryv1 "zntr.io/solid/api/oidc/discovery/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token"
	"zntr.io/solid/sdk/token/jwt"
	"zntr.io/solid/server/httpkit"
)

// metadataSigner builds a signing serializer for the metadata handler.
func metadataSigner(t *testing.T) token.Serializer {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P384(), cryptoRand.Reader)
	require.NoError(t, err)
	signingKey, err := jwxjwk.Import(key)
	require.NoError(t, err)
	require.NoError(t, signingKey.Set(jwxjwk.AlgorithmKey, "ES384"))
	require.NoError(t, signingKey.Set(jwxjwk.KeyUsageKey, "sig"))
	// The signer requires an identifiable key (kid) to build the JWT header.
	require.NoError(t, signingKey.Set(jwxjwk.KeyIDKey, "metadata-test-key"))

	return jwt.ServerMetadata("ES384", jwk.KeyProviderFunc(func(context.Context) (jwk.Key, error) {
		return signingKey, nil
	}))
}

// TestMetadataServesSignedSuppliedDocument asserts the handler serves the
// assembler-supplied metadata document with a non-empty signed_metadata
// value attached, without mutating the supplied document (concurrent
// requests must not share signed state through it).
func TestMetadataServesSignedSuppliedDocument(t *testing.T) {
	md := &discoveryv1.ServerMetadata{
		Issuer:                 "https://as.example.org",
		AuthorizationEndpoint:  "https://as.example.org/authorize",
		TokenEndpoint:          "https://as.example.org/token",
		ResponseTypesSupported: []string{oidc.ResponseTypeCode},
	}

	srv := httptest.NewServer(httpkit.Metadata(md, metadataSigner(t)))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/.well-known/oauth-authorization-server")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var served map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&served))
	require.Equal(t, "https://as.example.org", served["issuer"])
	require.NotEmpty(t, served["signed_metadata"], "the handler must attach signed_metadata")

	// The supplied document must not be mutated: it carries no
	// signed_metadata value after serving.
	require.Empty(t, md.SignedMetadata, "the assembler-supplied document must not be mutated")
}
