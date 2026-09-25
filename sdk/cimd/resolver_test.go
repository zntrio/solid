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

package cimd

import (
	"context"
	"errors"
	"strings"
	"testing"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/server/storage"
)

// stubFetcher is a hand-rolled Fetcher fake for resolver tests.
type stubFetcher struct {
	fetch func(ctx context.Context, url string) ([]byte, error)
}

func (f *stubFetcher) Fetch(ctx context.Context, url string) ([]byte, error) {
	return f.fetch(ctx, url)
}

const validClientIDURL = "https://client.example.org/cimd.json"

func validDocumentJSON(clientID string) []byte {
	return []byte(`{
		"client_id": "` + clientID + `",
		"token_endpoint_auth_method": "private_key_jwt",
		"grant_types": ["client_credentials"],
		"redirect_uris": ["https://client.example.org/cb"],
		"jwks": ` + validES256PublicJWKS + `
	}`)
}

func TestResolver(t *testing.T) {
	t.Run("ResolveValidDocument", func(t *testing.T) {
		r := NewResolver(&stubFetcher{
			fetch: func(_ context.Context, url string) ([]byte, error) {
				if url != validClientIDURL {
					t.Errorf("fetched url = %q", url)
				}
				return validDocumentJSON(validClientIDURL), nil
			},
		})
		c, err := r.Resolve(context.Background(), validClientIDURL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.ClientId != validClientIDURL {
			t.Errorf("client_id = %q", c.ClientId)
		}
		if c.TokenEndpointAuthMethod != oidc.AuthMethodPrivateKeyJWT {
			t.Errorf("token_endpoint_auth_method = %q", c.TokenEndpointAuthMethod)
		}
		if len(c.Jwks) == 0 {
			t.Error("jwks is empty")
		}
	})

	t.Run("NonURLClientID", func(t *testing.T) {
		r := NewResolver(&stubFetcher{
			fetch: func(context.Context, string) ([]byte, error) {
				t.Fatal("fetcher must not be called for non-URL client ids")
				return nil, nil
			},
		})
		_, err := r.Resolve(context.Background(), "my-registered-client")
		if err == nil {
			t.Fatal("expected error for non-URL client id")
		}
		if !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("expected storage.ErrNotFound in chain, got %v", err)
		}
	})

	t.Run("EmptyClientID", func(t *testing.T) {
		r := NewResolver(&stubFetcher{})
		_, err := r.Resolve(context.Background(), "")
		if !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("expected storage.ErrNotFound, got %v", err)
		}
	})

	t.Run("FetchError", func(t *testing.T) {
		r := NewResolver(&stubFetcher{
			fetch: func(context.Context, string) ([]byte, error) {
				return nil, errors.New("boom")
			},
		})
		_, err := r.Resolve(context.Background(), validClientIDURL)
		if err == nil {
			t.Fatal("expected fetch error")
		}
		if !strings.Contains(err.Error(), "boom") {
			t.Errorf("expected wrapped error, got %v", err)
		}
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		r := NewResolver(&stubFetcher{
			fetch: func(context.Context, string) ([]byte, error) {
				return []byte("not json"), nil
			},
		})
		if _, err := r.Resolve(context.Background(), validClientIDURL); err == nil {
			t.Fatal("expected decode error")
		}
	})

	t.Run("ClientIDMismatch", func(t *testing.T) {
		r := NewResolver(&stubFetcher{
			fetch: func(context.Context, string) ([]byte, error) {
				return validDocumentJSON("https://other.example.org/cimd.json"), nil
			},
		})
		_, err := r.Resolve(context.Background(), validClientIDURL)
		if err == nil {
			t.Fatal("expected mismatch error")
		}
		if !strings.Contains(err.Error(), "does not match") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("ForbiddenSecret", func(t *testing.T) {
		r := NewResolver(&stubFetcher{
			fetch: func(context.Context, string) ([]byte, error) {
				return []byte(`{"client_id":"` + validClientIDURL + `","client_secret":"x"}`), nil
			},
		})
		if _, err := r.Resolve(context.Background(), validClientIDURL); err == nil {
			t.Fatal("expected forbidden secret error")
		}
	})

	t.Run("ImplementsResolver", func(t *testing.T) {
		var _ Resolver = NewResolver(&stubFetcher{})
		var _ interface{} = &clientv1.Client{}
	})
}

// -----------------------------------------------------------------------------
func TestAllowlistFilter(t *testing.T) {
	demoBody := `{"client_id":"https://client.example.org/cimd.json","token_endpoint_auth_method":"private_key_jwt","jwks":{"keys":[{"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","x":"x","y":"y"}]}}`
	fetcher := fetcherFunc(func(_ context.Context, url string) ([]byte, error) {
		if url != "https://client.example.org/cimd.json" {
			return nil, storage.ErrNotFound
		}
		return []byte(demoBody), nil
	})
	base := NewResolver(fetcher)

	t.Run("exact identifier is resolved", func(t *testing.T) {
		r := NewAllowlistFilter(base, "https://client.example.org/cimd.json")
		c, err := r.Resolve(context.Background(), "https://client.example.org/cimd.json")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.ClientId != "https://client.example.org/cimd.json" {
			t.Errorf("client_id = %q", c.ClientId)
		}
	})
	t.Run("host prefix grant resolves deeper paths", func(t *testing.T) {
		r := NewAllowlistFilter(base, "https://client.example.org/")
		if _, err := r.Resolve(context.Background(), "https://client.example.org/cimd.json"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("non allow-listed identifier is refused before fetch", func(t *testing.T) {
		r := NewAllowlistFilter(base, "https://client.example.org/cimd.json")
		_, err := r.Resolve(context.Background(), "https://attacker.example.org/cimd.json")
		if err == nil {
			t.Fatal("expected refusal for non allow-listed identifier")
		}
		if !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("error should surface as ErrNotFound, got %v", err)
		}
	})
	t.Run("different host under prefix grant of another host is refused", func(t *testing.T) {
		r := NewAllowlistFilter(base, "https://partner.example.org/")
		if _, err := r.Resolve(context.Background(), "https://client.example.org/cimd.json"); err == nil {
			t.Fatal("expected refusal for host not covered by the prefix grant")
		}
	})
	t.Run("empty identifier is not found", func(t *testing.T) {
		r := NewAllowlistFilter(base, "https://client.example.org/cimd.json")
		if _, err := r.Resolve(context.Background(), ""); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
	})
}

// fetcherFunc adapts a function to the Fetcher interface for tests.
type fetcherFunc func(ctx context.Context, clientIdentifierURL string) ([]byte, error)

func (f fetcherFunc) Fetch(ctx context.Context, clientIdentifierURL string) ([]byte, error) {
	return f(ctx, clientIdentifierURL)
}
