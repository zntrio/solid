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

package handlers_test

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

	"zntr.io/solid/examples/authorizationserver/handlers"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token"
	"zntr.io/solid/sdk/token/jwt"
)

// signKey builds a signing key for the metadata signer.
func signKey(t *testing.T) token.Serializer {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P384(), cryptoRand.Reader)
	require.NoError(t, err)
	signingKey, err := jwxjwk.Import(key)
	require.NoError(t, err)
	require.NoError(t, signingKey.Set(jwxjwk.AlgorithmKey, "ES384"))
	require.NoError(t, signingKey.Set(jwxjwk.KeyUsageKey, "sig"))
	require.NoError(t, signingKey.Set(jwxjwk.KeyIDKey, "details-test-key"))

	return jwt.ServerMetadata("ES384", jwk.KeyProviderFunc(func(context.Context) (jwk.Key, error) {
		return signingKey, nil
	}))
}

// TestMetadataAdvertisesAuthorizationDetailsTypes asserts the discovery
// document advertises authorization_details_types_supported with the
// example's registered type (RFC 9396 section 10).
func TestMetadataAdvertisesAuthorizationDetailsTypes(t *testing.T) {
	srv := httptest.NewServer(handlers.Metadata("https://as.example.org", signKey(t)))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/.well-known/oauth-authorization-server")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var md map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&md))

	v, ok := md["authorization_details_types_supported"]
	require.True(t, ok, "authorization_details_types_supported missing from discovery document")
	types, isArr := v.([]any)
	require.True(t, isArr, "authorization_details_types_supported must be a JSON array")
	require.Len(t, types, 1)
	require.Equal(t, "payment_initiation", types[0])
}
