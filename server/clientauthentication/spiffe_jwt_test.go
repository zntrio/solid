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

package clientauthentication

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"go.uber.org/mock/gomock"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/spiffe"
	spiffemock "zntr.io/solid/sdk/spiffe/mock"
	"zntr.io/solid/server/storage/inmemory"
	storagemock "zntr.io/solid/server/storage/mock"
)

const (
	expectedSpiffeAudience = "http://localhost:8080/token"
	spiffeTestSubject      = "spiffe://example.org/my-oauth-client"
)

// spiffeTrustDomainKey is the test trust domain JWT-SVID signing key; the
// mock bundle serves its public part as a jwt-svid key. spiffeOtherDomainKey
// signs assertions the bundle does not know.
var (
	spiffeTrustDomainKey jwxjwk.Key
	spiffeOtherDomainKey jwxjwk.Key
)

func init() {
	k1, err := jwxjwk.Import(generateTestECDSAKey())
	if err != nil {
		panic(err)
	}
	k2, err := jwxjwk.Import(generateTestECDSAKey())
	if err != nil {
		panic(err)
	}
	spiffeTrustDomainKey = k1
	spiffeOtherDomainKey = k2
}

// generateTestECDSAKey builds a fresh P-256 signing key for fixtures.
func generateTestECDSAKey() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}

// errNoBundle simulates a BundleSource miss.
var errNoBundle = errors.New("no bundle")

// buildSpiffeJWTSVID signs a JWT-SVID with the trust domain key.
func buildSpiffeJWTSVID(t *testing.T, audience any, subject, jti string, lifetime time.Duration, key jwxjwk.Key) string {
	t.Helper()
	var rawKey any
	if err := jwxjwk.Export(key, &rawKey); err != nil {
		t.Fatalf("unable to materialize signing key: %v", err)
	}
	now := uint64(time.Now().Unix())
	tok := gojwt.NewWithClaims(gojwt.SigningMethodES256, gojwt.MapClaims{
		"iss": subject,
		"sub": subject,
		"aud": audience,
		"exp": now + uint64(lifetime.Seconds()),
		"iat": now,
		"jti": jti,
	})
	s, err := tok.SignedString(rawKey)
	if err != nil {
		t.Fatalf("unable to sign jwt-svid: %v", err)
	}
	return s
}

// spiffeBundleSet builds a jwk.Set with the given key tagged for the use.
func spiffeBundleSet(t *testing.T, key jwxjwk.Key, use string) jwk.Set {
	t.Helper()
	pub, err := jwxjwk.PublicKeyOf(key)
	if err != nil {
		t.Fatalf("unable to derive public key: %v", err)
	}
	if err := pub.Set(jwxjwk.KeyUsageKey, use); err != nil {
		t.Fatalf("unable to set key use: %v", err)
	}
	set := jwk.NewSet()
	if err := set.Set("keys", []jwk.Key{pub}); err != nil {
		t.Fatalf("unable to build keyset: %v", err)
	}
	return set
}

func Test_spiffeJWTAuthentication_Authenticate(t *testing.T) {
	tests := []struct {
		name    string
		req     *clientv1.AuthenticateRequest
		prepare func(*storagemock.MockClientReader, *spiffemock.MockBundleSource)
		wantErr bool
		// replay means: the first call must succeed and the second must fail.
		replay bool
	}{
		{
			name: "valid",
			req: &clientv1.AuthenticateRequest{
				ClientAssertionType: new(oidc.AssertionTypeJWTSPIFFE),
				ClientAssertion:     new(buildSpiffeJWTSVID(t, expectedSpiffeAudience, spiffeTestSubject, "svid-jti-ok", 5*time.Minute, spiffeTrustDomainKey)),
			},
			prepare: func(clients *storagemock.MockClientReader, bundles *spiffemock.MockBundleSource) {
				bundles.EXPECT().Get(gomock.Any(), "example.org").Return(spiffeBundleSet(t, spiffeTrustDomainKey, spiffe.KeyUseJWTSVID), nil)
				clients.EXPECT().Get(gomock.Any(), spiffeTestSubject).Return(&clientv1.Client{
					ClientId:                spiffeTestSubject,
					SpiffeId:                spiffeTestSubject,
					TokenEndpointAuthMethod: oidc.AuthMethodSPIFFEJWT,
				}, nil)
			},
		},
		{
			name: "wrong audience",
			req: &clientv1.AuthenticateRequest{
				ClientAssertionType: new(oidc.AssertionTypeJWTSPIFFE),
				ClientAssertion:     new(buildSpiffeJWTSVID(t, "https://evil.example", spiffeTestSubject, "svid-jti-aud", 5*time.Minute, spiffeTrustDomainKey)),
			},
			prepare: func(_ *storagemock.MockClientReader, _ *spiffemock.MockBundleSource) {},
			wantErr: true,
		},
		{
			name: "multi audience rejected (sole-value rule)",
			req: &clientv1.AuthenticateRequest{
				ClientAssertionType: new(oidc.AssertionTypeJWTSPIFFE),
				ClientAssertion:     new(buildSpiffeJWTSVID(t, []string{expectedSpiffeAudience, "https://other.example"}, spiffeTestSubject, "svid-jti-multi", 5*time.Minute, spiffeTrustDomainKey)),
			},
			prepare: func(_ *storagemock.MockClientReader, _ *spiffemock.MockBundleSource) {},
			wantErr: true,
		},
		{
			name: "expired svid",
			req: &clientv1.AuthenticateRequest{
				ClientAssertionType: new(oidc.AssertionTypeJWTSPIFFE),
				ClientAssertion:     new(buildExpiredSpiffeJWTSVID(t, expectedSpiffeAudience, spiffeTestSubject, "svid-jti-exp", spiffeTrustDomainKey)),
			},
			prepare: func(_ *storagemock.MockClientReader, _ *spiffemock.MockBundleSource) {},
			wantErr: true,
		},
		{
			name: "unknown trust domain",
			req: &clientv1.AuthenticateRequest{
				ClientAssertionType: new(oidc.AssertionTypeJWTSPIFFE),
				ClientAssertion:     new(buildSpiffeJWTSVID(t, expectedSpiffeAudience, "spiffe://unknown.org/my-oauth-client", "svid-jti-unk", 5*time.Minute, spiffeTrustDomainKey)),
			},
			prepare: func(_ *storagemock.MockClientReader, bundles *spiffemock.MockBundleSource) {
				bundles.EXPECT().Get(gomock.Any(), "unknown.org").Return(nil, errNoBundle)
			},
			wantErr: true,
		},
		{
			name: "signature from wrong key",
			req: &clientv1.AuthenticateRequest{
				ClientAssertionType: new(oidc.AssertionTypeJWTSPIFFE),
				ClientAssertion:     new(buildSpiffeJWTSVID(t, expectedSpiffeAudience, spiffeTestSubject, "svid-jti-wrongkey", 5*time.Minute, spiffeOtherDomainKey)),
			},
			prepare: func(_ *storagemock.MockClientReader, bundles *spiffemock.MockBundleSource) {
				bundles.EXPECT().Get(gomock.Any(), "example.org").Return(spiffeBundleSet(t, spiffeTrustDomainKey, spiffe.KeyUseJWTSVID), nil)
			},
			wantErr: true,
		},
		{
			name: "spiffe_id mismatch",
			req: &clientv1.AuthenticateRequest{
				ClientAssertionType: new(oidc.AssertionTypeJWTSPIFFE),
				ClientAssertion:     new(buildSpiffeJWTSVID(t, expectedSpiffeAudience, spiffeTestSubject, "svid-jti-mismatch", 5*time.Minute, spiffeTrustDomainKey)),
			},
			prepare: func(clients *storagemock.MockClientReader, bundles *spiffemock.MockBundleSource) {
				bundles.EXPECT().Get(gomock.Any(), "example.org").Return(spiffeBundleSet(t, spiffeTrustDomainKey, spiffe.KeyUseJWTSVID), nil)
				clients.EXPECT().Get(gomock.Any(), spiffeTestSubject).Return(&clientv1.Client{
					ClientId: spiffeTestSubject,
					// Registered for a different workload.
					SpiffeId: "spiffe://example.org/another-workload",
				}, nil)
			},
			wantErr: true,
		},
		{
			name: "spiffe_id wildcard segment boundary non-match",
			req: &clientv1.AuthenticateRequest{
				ClientAssertionType: new(oidc.AssertionTypeJWTSPIFFE),
				ClientAssertion:     new(buildSpiffeJWTSVID(t, expectedSpiffeAudience, "spiffe://example.org/client123", "svid-jti-boundary", 5*time.Minute, spiffeTrustDomainKey)),
			},
			prepare: func(clients *storagemock.MockClientReader, bundles *spiffemock.MockBundleSource) {
				bundles.EXPECT().Get(gomock.Any(), "example.org").Return(spiffeBundleSet(t, spiffeTrustDomainKey, spiffe.KeyUseJWTSVID), nil)
				clients.EXPECT().Get(gomock.Any(), "spiffe://example.org/client123").Return(&clientv1.Client{
					ClientId: "spiffe://example.org/client123",
					// spiffe://example.org/client/* does NOT match client123.
					SpiffeId: "spiffe://example.org/client/*",
				}, nil)
			},
			wantErr: true,
		},
		{
			name: "client without spiffe_id rejected (fail closed)",
			req: &clientv1.AuthenticateRequest{
				ClientAssertionType: new(oidc.AssertionTypeJWTSPIFFE),
				ClientAssertion:     new(buildSpiffeJWTSVID(t, expectedSpiffeAudience, spiffeTestSubject, "svid-jti-nospiffe", 5*time.Minute, spiffeTrustDomainKey)),
			},
			prepare: func(clients *storagemock.MockClientReader, bundles *spiffemock.MockBundleSource) {
				bundles.EXPECT().Get(gomock.Any(), "example.org").Return(spiffeBundleSet(t, spiffeTrustDomainKey, spiffe.KeyUseJWTSVID), nil)
				clients.EXPECT().Get(gomock.Any(), spiffeTestSubject).Return(&clientv1.Client{
					ClientId: spiffeTestSubject,
				}, nil)
			},
			wantErr: true,
		},
		{
			name: "replay rejected",
			req: &clientv1.AuthenticateRequest{
				ClientAssertionType: new(oidc.AssertionTypeJWTSPIFFE),
				ClientAssertion:     new(buildSpiffeJWTSVID(t, expectedSpiffeAudience, spiffeTestSubject, "svid-jti-replay", 5*time.Minute, spiffeTrustDomainKey)),
			},
			prepare: func(clients *storagemock.MockClientReader, bundles *spiffemock.MockBundleSource) {
				bundles.EXPECT().Get(gomock.Any(), "example.org").Return(spiffeBundleSet(t, spiffeTrustDomainKey, spiffe.KeyUseJWTSVID), nil).Times(2)
				clients.EXPECT().Get(gomock.Any(), spiffeTestSubject).Return(&clientv1.Client{
					ClientId:                spiffeTestSubject,
					SpiffeId:                spiffeTestSubject,
					TokenEndpointAuthMethod: oidc.AuthMethodSPIFFEJWT,
				}, nil).Times(2)
			},
			wantErr: true,
			replay:  true,
		},
		{
			name: "wrong client_assertion_type",
			req: &clientv1.AuthenticateRequest{
				ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
				ClientAssertion:     new("x"),
			},
			prepare: func(_ *storagemock.MockClientReader, _ *spiffemock.MockBundleSource) {},
			wantErr: true,
		},
		{
			name: "missing assertion",
			req: &clientv1.AuthenticateRequest{
				ClientAssertionType: new(oidc.AssertionTypeJWTSPIFFE),
			},
			prepare: func(_ *storagemock.MockClientReader, _ *spiffemock.MockBundleSource) {},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			clients := storagemock.NewMockClientReader(ctrl)
			bundles := spiffemock.NewMockBundleSource(ctrl)
			proofs := inmemory.DPoPProofs()

			if tt.prepare != nil {
				tt.prepare(clients, bundles)
			}

			underTest := SPIFFEJWT(clients, bundles, proofs, expectedSpiffeAudience, []string{"ES256"})

			got, err := underTest.Authenticate(context.Background(), tt.req)
			if tt.replay {
				if err != nil {
					t.Fatalf("first Authenticate() call unexpectedly failed: %v", err)
				}
				got, err = underTest.Authenticate(context.Background(), tt.req)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("Authenticate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got.Client == nil {
				t.Errorf("Authenticate() = %v, want client assigned", got)
			}
			if tt.wantErr && got != nil && got.Error == nil {
				t.Errorf("Authenticate() = %v, want protocol error assigned", got)
			}
		})
	}
}

// buildExpiredSpiffeJWTSVID signs a JWT-SVID whose validity window is
// already in the past (no uint64 underflow on the lifetime).
func buildExpiredSpiffeJWTSVID(t *testing.T, audience any, subject, jti string, key jwxjwk.Key) string {
	t.Helper()
	var rawKey any
	if err := jwxjwk.Export(key, &rawKey); err != nil {
		t.Fatalf("unable to materialize signing key: %v", err)
	}
	now := uint64(time.Now().Unix())
	tok := gojwt.NewWithClaims(gojwt.SigningMethodES256, gojwt.MapClaims{
		"iss": subject,
		"sub": subject,
		"aud": audience,
		"exp": now - 60,
		"iat": now - 300,
		"jti": jti,
	})
	s, err := tok.SignedString(rawKey)
	if err != nil {
		t.Fatalf("unable to sign jwt-svid: %v", err)
	}
	return s
}

// errClientNotFound simulates a ClientReader miss.
var errClientNotFound = errors.New("client not found")
