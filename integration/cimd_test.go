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

package integration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/sdk/cimd"
	"zntr.io/solid/sdk/httpfetch"
	"zntr.io/solid/server/storage"
	"zntr.io/solid/server/storage/inmemory"
)

// -----------------------------------------------------------------------------
// Adversarial tests for the OAuth Client ID Metadata Document mechanism
// (draft-ietf-oauth-client-id-metadata-document-02). Each test plays an
// attacker publishing a hostile or malformed Client ID Metadata Document (or
// hostile client identifier) and asserts the corresponding draft-mandated
// countermeasure fires.
// -----------------------------------------------------------------------------

// cimdJWKS is a public-only ES256 JWK Set for CIMD documents.
var cimdJWKS = []byte(`{"keys":[{"kty":"EC","use":"sig","crv":"P-256","kid":"cimd-1","x":"h6jud8ozOJ93MvHZCxvGZnOVHLeTX-3K9LkAvKy1RSs","y":"yY0UQDLFPM8OAgkOYfotwzXCGXtBYinBk1EURJQ7ONk","alg":"ES256"}]}`)

// newCIMDHarness builds the CIMD-aware client reader over an in-memory primary
// store and a resolver fetching through the given TLS test server.
func newCIMDHarness(t *testing.T, ts *httptest.Server) storage.ClientReader {
	t.Helper()
	resolver := cimd.NewResolver(httpfetch.NewTestFetcher(ts.Client(), 0))
	return inmemory.NewClientReader(inmemory.Clients(), resolver)
}

// cimdTestServer starts a TLS server serving the document built by doc for
// every request; doc receives the absolute URL that was fetched.
func cimdTestServer(t *testing.T, doc func(fetchedURL string) string) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(doc("https://" + r.Host + r.URL.RequestURI())))
	}))
}

func TestCIMDClientIDMismatch(t *testing.T) {
	// Attacker (A1) hosts a document claiming another entity's identity:
	// the document client_id must match the fetched URL (draft section 4).
	ts := cimdTestServer(t, func(string) string {
		return `{"client_id":"https://victim.example.org/cimd.json","token_endpoint_auth_method":"private_key_jwt","jwks":` + string(cimdJWKS) + `}`
	})
	defer ts.Close()

	clients := newCIMDHarness(t, ts)
	_, err := clients.Get(context.Background(), ts.URL+"/cimd.json")
	require.True(t, errors.Is(err, storage.ErrNotFound), "mismatched client_id must resolve as unknown client, got %v", err)
}

func TestCIMDClientSecretExfiltration(t *testing.T) {
	// Attacker publishes a shared secret in the document (draft section 4.1);
	// solid refuses symmetric credentials from CIMD.
	t.Run("client_secret", func(t *testing.T) {
		ts := cimdTestServer(t, func(url string) string {
			return `{"client_id":"` + url + `","client_secret":"attacker-secret"}`
		})
		defer ts.Close()

		clients := newCIMDHarness(t, ts)
		_, err := clients.Get(context.Background(), ts.URL+"/cimd.json")
		require.ErrorIs(t, err, storage.ErrNotFound)
	})

	t.Run("client_secret_expires_at", func(t *testing.T) {
		ts := cimdTestServer(t, func(url string) string {
			return `{"client_id":"` + url + `","client_secret_expires_at":2000000000}`
		})
		defer ts.Close()

		clients := newCIMDHarness(t, ts)
		_, err := clients.Get(context.Background(), ts.URL+"/cimd.json")
		require.ErrorIs(t, err, storage.ErrNotFound)
	})

	for _, method := range []string{"client_secret_post", "client_secret_basic", "client_secret_jwt"} {
		t.Run("auth_method_"+method, func(t *testing.T) {
			ts := cimdTestServer(t, func(url string) string {
				return `{"client_id":"` + url + `","token_endpoint_auth_method":"` + method + `"}`
			})
			defer ts.Close()

			clients := newCIMDHarness(t, ts)
			_, err := clients.Get(context.Background(), ts.URL+"/cimd.json")
			require.ErrorIs(t, err, storage.ErrNotFound)
		})
	}
}

func TestCIMDPrivateKeyLeak(t *testing.T) {
	// Attacker tricks the AS into trusting (or storing) a private key
	// published in the document (draft section 4.1: private key material
	// MUST NOT be included).
	docs := map[string]string{
		"ec_private_d": `{"client_id":"%s","token_endpoint_auth_method":"private_key_jwt","jwks":{"keys":[{"kty":"EC","crv":"P-256","x":"h6jud8ozOJ93MvHZCxvGZnOVHLeTX-3K9LkAvKy1RSs","y":"yY0UQDLFPM8OAgkOYfotwzXCGXtBYinBk1EURJQ7ONk","d":"olYJLJ3aiTyP44YXs0R3g1qChRKnYnk7GDxffQhAgL8"}]}}`,
		"rsa_private":  `{"client_id":"%s","token_endpoint_auth_method":"private_key_jwt","jwks":{"keys":[{"kty":"RSA","n":"0vx7agoebGcQSuuP6hT2aQ","e":"AQAB","d":"X4cTteJW9tZk"}]}}`,
		"oct_key":      `{"client_id":"%s","token_endpoint_auth_method":"private_key_jwt","jwks":{"keys":[{"kty":"oct","k":"GS3UDzpaD7KU4bdq"}]}}`,
	}
	for name, doc := range docs {
		t.Run(name, func(t *testing.T) {
			ts := cimdTestServer(t, func(url string) string {
				return sprintf(doc, url)
			})
			defer ts.Close()

			clients := newCIMDHarness(t, ts)
			_, err := clients.Get(context.Background(), ts.URL+"/cimd.json")
			require.ErrorIs(t, err, storage.ErrNotFound)
		})
	}
}

func TestCIMDNon200AndRedirects(t *testing.T) {
	// Attacker serves redirects (to intercept or launder the fetch) or error
	// statuses; draft section 4 requires 200 OK and section 5 forbids
	// redirects.
	t.Run("redirect_302", func(t *testing.T) {
		final := cimdTestServer(t, func(url string) string {
			return `{"client_id":"` + url + `","token_endpoint_auth_method":"private_key_jwt","jwks":` + string(cimdJWKS) + `}`
		})
		defer final.Close()
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Redirect(w, httptest.NewRequest(http.MethodGet, final.URL+"/cimd.json", nil), final.URL+"/cimd.json", http.StatusFound)
		}))
		defer ts.Close()

		clients := newCIMDHarness(t, ts)
		_, err := clients.Get(context.Background(), ts.URL+"/cimd.json")
		require.ErrorIs(t, err, storage.ErrNotFound)
	})

	for _, code := range []int{301, 404, 500} {
		t.Run("status_"+itoa(code), func(t *testing.T) {
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(code)
			}))
			defer ts.Close()

			clients := newCIMDHarness(t, ts)
			_, err := clients.Get(context.Background(), ts.URL+"/cimd.json")
			require.ErrorIs(t, err, storage.ErrNotFound)
		})
	}
}

func TestCIMDOversizeDocument(t *testing.T) {
	// Attacker serves an oversized document to exhaust AS resources (draft
	// section 8.7 recommends a 5 kB maximum).
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, 64*1024))
	}))
	defer ts.Close()

	clients := newCIMDHarness(t, ts)
	_, err := clients.Get(context.Background(), ts.URL+"/cimd.json")
	require.ErrorIs(t, err, storage.ErrNotFound)
}

func TestCIMDHostileIdentifierShapes(t *testing.T) {
	// Attacker uses identifier shapes that must never trigger a fetch.
	for _, id := range []string{
		"http://client.example.org/cimd.json",     // not https
		"https://user@client.example.org/cimd",    // userinfo
		"https://client.example.org",              // no path
		"https://client.example.org/../cimd.json", // dot segment
		"https://client.example.org/cimd#frag",    // fragment
	} {
		t.Run("reject_"+id, func(t *testing.T) {
			require.False(t, cimd.IsClientIdentifierURL(id))
		})
	}
}

func TestCIMDSSRFSpecialUseDestinations(t *testing.T) {
	// Attacker (A2) points the AS at internal infrastructure through the
	// fetch (draft section 8.6); every special-use destination must be
	// refused before any connection is made. The loopback test servers used
	// elsewhere in this suite prove the guard matters.
	f := httpfetch.New(nil, 0)
	for _, id := range []string{
		"https://127.0.0.1/cimd.json",
		"https://10.0.0.5/cimd.json",
		"https://192.168.1.10/cimd.json",
		"https://192.0.2.7/cimd.json",
		"https://169.254.169.254/cimd.json", // cloud metadata endpoint
		"https://[::1]/cimd.json",
		"https://[fc00::1]/cimd.json",
	} {
		t.Run("ssrf_"+id, func(t *testing.T) {
			_, err := f.Fetch(context.Background(), id)
			require.Error(t, err)
			require.Contains(t, err.Error(), "special-use")
		})
	}
}

func TestCIMDPreRegisteredWins(t *testing.T) {
	// Draft section 7.1: a pre-registered client (even URL-shaped) must win
	// over the document an attacker replaced the URL content with.
	ts := cimdTestServer(t, func(string) string {
		// Hostile replacement document.
		return `{"client_id":"placeholder","token_endpoint_auth_method":"none"}`
	})
	defer ts.Close()

	clientID := ts.URL + "/cimd.json"
	registered := &clientv1.Client{
		ClientId:                clientID,
		ClientType:              clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		GrantTypes:              []string{"client_credentials"},
		TokenEndpointAuthMethod: "private_key_jwt",
		Jwks:                    cimdJWKS,
	}
	primary := &stubClientReader{byID: map[string]*clientv1.Client{clientID: registered}}

	resolver := cimd.NewResolver(httpfetch.NewTestFetcher(ts.Client(), 0))
	clients := inmemory.NewClientReader(primary, resolver)

	c, err := clients.Get(context.Background(), clientID)
	require.NoError(t, err)
	require.Equal(t, registered.ClientId, c.ClientId)
	require.Equal(t, "private_key_jwt", c.TokenEndpointAuthMethod)
}

// stubClientReader is a minimal pre-registration store for the CIMD tests;
// inmemory.Register assigns its own client_id, which cannot represent a
// pre-registered URL-shaped identifier.
type stubClientReader struct {
	byID map[string]*clientv1.Client
}

func (s *stubClientReader) Get(_ context.Context, id string) (*clientv1.Client, error) {
	if c, ok := s.byID[id]; ok {
		return c, nil
	}
	return nil, storage.ErrNotFound
}

func (s *stubClientReader) GetByName(_ context.Context, _ string) (*clientv1.Client, error) {
	return nil, storage.ErrNotFound
}

func TestCIMDMalformedDocument(t *testing.T) {
	for name, body := range map[string]string{
		"not_json":   `not json at all`,
		"empty":      ``,
		"missing_id": `{"token_endpoint_auth_method":"private_key_jwt"}`,
		"null_id":    `{"client_id":null}`,
	} {
		t.Run(name, func(t *testing.T) {
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer ts.Close()

			clients := newCIMDHarness(t, ts)
			_, err := clients.Get(context.Background(), ts.URL+"/cimd.json")
			require.ErrorIs(t, err, storage.ErrNotFound)
		})
	}
}

// sprintf avoids importing fmt just for one call site.
func sprintf(format string, args ...string) string {
	return strings.Replace(format, "%s", args[0], 1)
}

// itoa avoids importing strconv just for one call site.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
