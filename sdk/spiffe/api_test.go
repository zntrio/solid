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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"zntr.io/solid/sdk/jwk"
)

func TestTrustDomainFromSPIFFEID(t *testing.T) {
	testCases := []struct {
		name    string
		id      string
		want    string
		wantErr bool
	}{
		{name: "valid", id: "spiffe://example.org/my-oauth-client", want: "example.org"},
		{name: "valid bare domain", id: "spiffe://example.org", want: "example.org"},
		{name: "valid nested path", id: "spiffe://prod.internal/ns/sa/app", want: "prod.internal"},
		{name: "wildcard-like path", id: "spiffe://example.org/client/*", want: "example.org"},
		{name: "empty", id: "", wantErr: true},
		{name: "bad scheme", id: "https://example.org/app", wantErr: true},
		{name: "no host", id: "spiffe:///app", wantErr: true},
		{name: "path only", id: "/my-oauth-client", wantErr: true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := TrustDomainFromSPIFFEID(tc.id)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

func TestMatchSPIFFEID(t *testing.T) {
	testCases := []struct {
		name    string
		pattern string
		id      string
		want    bool
	}{
		{name: "exact match", pattern: "spiffe://example.org/my-oauth-client", id: "spiffe://example.org/my-oauth-client", want: true},
		{name: "exact non-match", pattern: "spiffe://example.org/my-oauth-client", id: "spiffe://example.org/other-client", want: false},
		{name: "wildcard match segment", pattern: "spiffe://example.org/client/*", id: "spiffe://example.org/client/123", want: true},
		{name: "wildcard match boundary itself", pattern: "spiffe://example.org/client/*", id: "spiffe://example.org/client/", want: true},
		{name: "wildcard non-match segment boundary", pattern: "spiffe://example.org/client/*", id: "spiffe://example.org/client123", want: false},
		{name: "wildcard non-match other prefix", pattern: "spiffe://example.org/client/*", id: "spiffe://example.org/clients/123", want: false},
		{name: "wildcard non-match shorter id", pattern: "spiffe://example.org/long-path/*", id: "spiffe://example.org/lon", want: false},
		{name: "wildcard non-match domain", pattern: "spiffe://example.org/client/*", id: "spiffe://other.org/client/123", want: false},
		{name: "no wildcard partial match rejected", pattern: "spiffe://example.org/client", id: "spiffe://example.org/client/123", want: false},
		{name: "no wildcard prefix rejected", pattern: "spiffe://example.org/cli", id: "spiffe://example.org/client", want: false},
		{name: "empty pattern", pattern: "", id: "spiffe://example.org/app", want: false},
		{name: "empty id", pattern: "spiffe://example.org/app", id: "", want: false},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, MatchSPIFFEID(tc.pattern, tc.id))
		})
	}
}

// buildCert builds a self-signed certificate with the given URI SANs.
func buildCert(t *testing.T, uris []*url.URL) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		URIs:                  uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func mustURI(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
}

func TestTrustDomainFromX509SVID(t *testing.T) {
	t.Run("no URI SAN", func(t *testing.T) {
		_, ok := TrustDomainFromX509SVID(buildCert(t, nil))
		assert.False(t, ok)
	})
	t.Run("single spiffe URI SAN", func(t *testing.T) {
		cert := buildCert(t, []*url.URL{mustURI(t, "spiffe://example.org/app")})
		id, ok := TrustDomainFromX509SVID(cert)
		assert.True(t, ok)
		assert.Equal(t, "spiffe://example.org/app", id)
	})
	t.Run("two spiffe URI SANs", func(t *testing.T) {
		cert := buildCert(t, []*url.URL{
			mustURI(t, "spiffe://example.org/app"),
			mustURI(t, "spiffe://example.org/other"),
		})
		_, ok := TrustDomainFromX509SVID(cert)
		assert.False(t, ok)
	})
	t.Run("non-spiffe URI SAN", func(t *testing.T) {
		cert := buildCert(t, []*url.URL{mustURI(t, "https://example.org/app")})
		_, ok := TrustDomainFromX509SVID(cert)
		assert.False(t, ok)
	})
	t.Run("nil cert", func(t *testing.T) {
		_, ok := TrustDomainFromX509SVID(nil)
		assert.False(t, ok)
	})
}

func TestKeysByUse(t *testing.T) {
	// Build a set mixing tagged and untagged keys.
	newKey := func(use string) jwk.Key {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		k, err := jwxjwk.Import(key.Public())
		require.NoError(t, err)
		if use != "" {
			require.NoError(t, k.Set(jwxjwk.KeyUsageKey, use))
		}
		return k
	}
	all := jwxjwk.NewSet()
	require.NoError(t, all.Set("keys", []jwxjwk.Key{
		newKey(KeyUseJWTSVID),
		newKey(""),
		newKey(KeyUseX509SVID),
		newKey(KeyUseWITSVID),
		newKey(KeyUseJWTSVID),
	}))

	jwtSet, err := KeysByUse(all, KeyUseJWTSVID)
	require.NoError(t, err)
	assert.Equal(t, 2, jwtSet.Len())

	x509Set, err := KeysByUse(all, KeyUseX509SVID)
	require.NoError(t, err)
	assert.Equal(t, 1, x509Set.Len())

	// Untagged keys never match any use (strict).
	empty, err := KeysByUse(all, "unknown-use")
	require.NoError(t, err)
	assert.Equal(t, 0, empty.Len())

	_, err = KeysByUse(nil, KeyUseJWTSVID)
	assert.Error(t, err)
}
