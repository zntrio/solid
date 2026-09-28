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
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubFetcher serves a fixed body at any URL.
type stubFetcher struct {
	body []byte
	err  error
}

func (f *stubFetcher) Fetch(_ context.Context, _ string) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.body, nil
}

// stubVerifier accepts or rejects every signed_metadata token.
type stubVerifier struct {
	err error

	lastResource       string
	lastSignedMetadata string
}

func (v *stubVerifier) Verify(_ context.Context, resource, signedMetadata string) error {
	v.lastResource = resource
	v.lastSignedMetadata = signedMetadata
	return v.err
}

func TestResolverResolve(t *testing.T) {
	identifier := "https://resource.example.com/"

	t.Run("happy path", func(t *testing.T) {
		body := `{"resource": "https://resource.example.com/", "scopes_supported": ["read"]}`
		r := NewResolver(&stubFetcher{body: []byte(body)}, nil, 0)
		md, err := r.Resolve(context.Background(), identifier)
		require.NoError(t, err)
		assert.Equal(t, identifier, md.GetResource())
		assert.Equal(t, []string{"read"}, md.GetScopesSupported())
	})

	t.Run("resource mismatch is rejected", func(t *testing.T) {
		body := `{"resource": "https://attacker.example/"}`
		r := NewResolver(&stubFetcher{body: []byte(body)}, nil, 0)
		_, err := r.Resolve(context.Background(), identifier)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "https://attacker.example/")
		assert.Contains(t, err.Error(), identifier)
	})

	t.Run("size cap is enforced by the resolver itself", func(t *testing.T) {
		big := `{"resource": "https://resource.example.com/", "junk": "` + strings.Repeat("a", 128*1024) + `"}`
		r := NewResolver(&stubFetcher{body: []byte(big)}, nil, 0)
		_, err := r.Resolve(context.Background(), identifier)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeding")
	})

	t.Run("default size cap accepts normal documents", func(t *testing.T) {
		body := `{"resource": "https://resource.example.com/", "junk": "` + strings.Repeat("a", 32*1024) + `"}`
		r := NewResolver(&stubFetcher{body: []byte(body)}, nil, 0)
		_, err := r.Resolve(context.Background(), identifier)
		require.NoError(t, err)
	})

	t.Run("custom size cap is honored", func(t *testing.T) {
		body := `{"resource": "https://resource.example.com/", "junk": "` + strings.Repeat("a", 2048) + `"}`
		r := NewResolver(&stubFetcher{body: []byte(body)}, nil, 1024)
		_, err := r.Resolve(context.Background(), identifier)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeding")
	})

	t.Run("signed_metadata without verifier is rejected", func(t *testing.T) {
		body := `{"resource": "https://resource.example.com/", "signed_metadata": "eyJhbGciOiJFUzI1NiJ9.e30.AB"}`
		r := NewResolver(&stubFetcher{body: []byte(body)}, nil, 0)
		_, err := r.Resolve(context.Background(), identifier)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no verifier is configured")
	})

	t.Run("signed_metadata verifier veto propagates", func(t *testing.T) {
		body := `{"resource": "https://resource.example.com/", "signed_metadata": "eyJhbGciOiJFUzI1NiJ9.e30.AB"}`
		verifier := &stubVerifier{err: errors.New("bad signature")}
		r := NewResolver(&stubFetcher{body: []byte(body)}, verifier, 0)
		_, err := r.Resolve(context.Background(), identifier)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "bad signature")
	})

	t.Run("signed_metadata verifier acceptance returns document", func(t *testing.T) {
		body := `{"resource": "https://resource.example.com/", "signed_metadata": "eyJhbGciOiJFUzI1NiJ9.e30.AB"}`
		verifier := &stubVerifier{}
		r := NewResolver(&stubFetcher{body: []byte(body)}, verifier, 0)
		md, err := r.Resolve(context.Background(), identifier)
		require.NoError(t, err)
		assert.Equal(t, identifier, md.GetResource())
		assert.Equal(t, identifier, verifier.lastResource)
		assert.Equal(t, "eyJhbGciOiJFUzI1NiJ9.e30.AB", verifier.lastSignedMetadata)
	})

	t.Run("fetch error propagates", func(t *testing.T) {
		r := NewResolver(&stubFetcher{err: errors.New("boom")}, nil, 0)
		_, err := r.Resolve(context.Background(), identifier)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unable to fetch")
	})

	t.Run("http identifier is rejected before fetch", func(t *testing.T) {
		f := &stubFetcher{body: []byte(`{"resource": "http://resource.example.com/"}`)}
		r := NewResolver(f, nil, 0)
		_, err := r.Resolve(context.Background(), "http://resource.example.com/")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "https scheme")
	})

	t.Run("identifier with fragment is rejected before fetch", func(t *testing.T) {
		f := &stubFetcher{body: []byte(`{}`)}
		r := NewResolver(f, nil, 0)
		_, err := r.Resolve(context.Background(), "https://resource.example.com/#x")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "fragment")
	})
}
