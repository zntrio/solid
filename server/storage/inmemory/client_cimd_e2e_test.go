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

package inmemory_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/cimd"
	"zntr.io/solid/sdk/httpfetch"
	"zntr.io/solid/server/storage"
	"zntr.io/solid/server/storage/inmemory"
)

const e2eJWKS = `{"keys":[{"kty":"EC","crv":"P-256","kid":"e2e-1","use":"sig","x":"usWxHK2PmwdRMx5tCYESucbsKLUeYS2tK5AFpfMz1sc","y":"AYexF3Xl0Lo0Ol7BsaNvfW4H9OpNQ0JC6T6i5jX6CqA"}]}`

// newCIMDServer starts a TLS test server serving a Client ID Metadata
// Document whose client_id is the absolute URL the resolver fetched.
func newCIMDServer(t *testing.T, docJSON func(clientID string) string) *httptest.Server {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reconstruct the absolute URL the client fetched (r.URL is
		// path-only on the server side).
		_, _ = w.Write([]byte(docJSON("https://" + r.Host + r.URL.RequestURI())))
	}))
	return ts
}

func TestClientReaderCIMDEndToEnd(t *testing.T) {
	validDoc := func(clientID string) string {
		return `{"client_id":"` + clientID + `","token_endpoint_auth_method":"private_key_jwt","grant_types":["client_credentials"],"jwks":` + e2eJWKS + `}`
	}

	t.Run("ResolveWithoutRegistration", func(t *testing.T) {
		ts := newCIMDServer(t, validDoc)
		defer ts.Close()

		resolver := cimd.NewResolver(httpfetch.NewTestFetcher(ts.Client(), 0))
		clients := inmemory.NewClientReader(inmemory.Clients(), resolver)

		clientID := ts.URL + "/cimd.json"
		c, err := clients.Get(context.Background(), clientID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.ClientId != clientID {
			t.Errorf("client_id = %q, want %q", c.ClientId, clientID)
		}
		if c.TokenEndpointAuthMethod != oidc.AuthMethodPrivateKeyJWT {
			t.Errorf("token_endpoint_auth_method = %q", c.TokenEndpointAuthMethod)
		}
		if len(c.Jwks) == 0 {
			t.Error("jwks not populated")
		}
		if c.ClientType != clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL {
			t.Errorf("client_type = %v", c.ClientType)
		}
	})

	t.Run("MismatchedClientIDIsNotFound", func(t *testing.T) {
		ts := newCIMDServer(t, func(string) string {
			return `{"client_id":"https://other.example.org/cimd.json","token_endpoint_auth_method":"private_key_jwt","jwks":` + e2eJWKS + `}`
		})
		defer ts.Close()

		resolver := cimd.NewResolver(httpfetch.NewTestFetcher(ts.Client(), 0))
		clients := inmemory.NewClientReader(inmemory.Clients(), resolver)

		_, err := clients.Get(context.Background(), ts.URL+"/cimd.json")
		if !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("expected storage.ErrNotFound, got %v", err)
		}
	})

	t.Run("ForbiddenSecretIsNotFound", func(t *testing.T) {
		ts := newCIMDServer(t, func(clientID string) string {
			return `{"client_id":"` + clientID + `","client_secret":"s3cr3t"}`
		})
		defer ts.Close()

		resolver := cimd.NewResolver(httpfetch.NewTestFetcher(ts.Client(), 0))
		clients := inmemory.NewClientReader(inmemory.Clients(), resolver)

		_, err := clients.Get(context.Background(), ts.URL+"/cimd.json")
		if !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("expected storage.ErrNotFound, got %v", err)
		}
	})
}
