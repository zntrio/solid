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

	"zntr.io/solid/examples/authorizationserver/handlers"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token/jwt"
)

// TestMetadataAdvertisesCIMDSupport asserts the discovery document advertises
// client_id_metadata_document_supported, as REQUIRED by the OAuth Client ID
// Metadata Document draft (draft-ietf-oauth-client-id-metadata-document,
// section 5) for authorization servers publishing RFC 8414 metadata.
func TestMetadataAdvertisesCIMDSupport(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), cryptoRand.Reader)
	if err != nil {
		t.Fatalf("unable to generate signing key: %v", err)
	}
	signingKey, err := jwxjwk.Import(key)
	if err != nil {
		t.Fatalf("unable to import signing key: %v", err)
	}
	if err := signingKey.Set(jwxjwk.AlgorithmKey, "ES384"); err != nil {
		t.Fatalf("unable to set signing key algorithm: %v", err)
	}
	if err := signingKey.Set(jwxjwk.KeyUsageKey, "sig"); err != nil {
		t.Fatalf("unable to set signing key usage: %v", err)
	}
	// The signer requires an identifiable key (kid) to build the JWT header.
	if err := signingKey.Set(jwxjwk.KeyIDKey, "metadata-test-key"); err != nil {
		t.Fatalf("unable to set signing key id: %v", err)
	}
	signer := jwt.ServerMetadata("ES384", jwk.KeyProviderFunc(func(context.Context) (jwk.Key, error) {
		return signingKey, nil
	}))

	srv := httptest.NewServer(handlers.Metadata("https://as.example.org", signer))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var md map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&md); err != nil {
		t.Fatalf("unable to decode metadata: %v", err)
	}

	v, ok := md["client_id_metadata_document_supported"]
	if !ok {
		t.Fatal("client_id_metadata_document_supported missing from discovery document")
	}
	adv, isBool := v.(bool)
	if !isBool || !adv {
		t.Errorf("client_id_metadata_document_supported = %v, want true", v)
	}
}
