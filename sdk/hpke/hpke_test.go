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

package hpke

import (
	"crypto/rand"
	"strings"
	"testing"

	chpke "crypto/hpke"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"zntr.io/solid/sdk/jwk"
)

// TestRegistryLabelCOSEAgreement asserts every suite resolves through both
// identifier namespaces to the same suite, and both listing helpers agree
// on the registry size.
func TestRegistryLabelCOSEAgreement(t *testing.T) {
	labels := SupportedJWELabels()
	coseIDs := SupportedCOSEAlgorithms()
	require.Len(t, labels, 11)
	require.Len(t, coseIDs, 11)

	for _, label := range labels {
		s, err := LookupLabel(label)
		require.NoError(t, err, "label %s must resolve", label)
		byCOSE, err := LookupCOSE(s.COSE)
		require.NoError(t, err, "COSE %d must resolve", s.COSE)
		assert.Same(t, s, byCOSE, "label %s and COSE %d must resolve to the same suite", label, s.COSE)
		assert.Equal(t, label, s.Label)
	}
}

// TestRegistryRejectsX448 asserts the X448-based suites are rejected with
// an error naming the stdlib crypto/ecdh limitation in both namespaces.
func TestRegistryRejectsX448(t *testing.T) {
	for _, label := range []string{"HPKE-5", "HPKE-6", "HPKE-5-KE", "HPKE-6-KE"} {
		_, err := LookupLabel(label)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "X448")
	}
	for _, id := range []int64{43, 44, 51, 52} {
		_, err := LookupCOSE(id)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "X448")
	}

	// Unregistered identifiers.
	_, err := LookupLabel("RSA-OAEP")
	require.Error(t, err)
	_, err = LookupCOSE(-37)
	require.Error(t, err)
}

// TestKeyConversionRoundTrip generates an ecdh key on every suite curve,
// imports it as a JWK, and resolves both HPKE keys back from the JWK —
// the public part must match the private key's public part.
func TestKeyConversionRoundTrip(t *testing.T) {
	for _, label := range SupportedJWELabels() {
		t.Run(label, func(t *testing.T) {
			s, err := LookupLabel(label)
			require.NoError(t, err)

			priv, err := s.Curve.GenerateKey(rand.Reader)
			require.NoError(t, err)

			// Import as a private JWK.
			privJWK, err := jwxjwk.Import(priv)
			require.NoError(t, err)
			require.NoError(t, privJWK.Set(jwk.KeyUsageKey, "enc"))
			require.NoError(t, jwk.AssignKeyID(privJWK))

			// KEM private key round-trip.
			kemPriv, err := KEMPrivateKey(privJWK, s)
			require.NoError(t, err)

			// KEM public key from the same (private) JWK.
			kemPub, err := KEMPublicKey(privJWK, s)
			require.NoError(t, err)

			// The derived public encapsulation key must encapsulate a
			// secret the decapsulation key opens (single-shot proof).
			encap, sender, err := chpke.NewSender(kemPub, s.KDF, s.AEAD, nil)
			require.NoError(t, err)
			recipient, err := chpke.NewRecipient(encap, kemPriv, s.KDF, s.AEAD, nil)
			require.NoError(t, err)
			secret := []byte("mechanism round-trip")
			ct, err := sender.Seal(nil, secret)
			require.NoError(t, err)
			pt, err := recipient.Open(nil, ct)
			require.NoError(t, err)
			assert.Equal(t, secret, pt)
		})
	}
}

// TestKeyConversionCurveMismatch asserts the suite-curve binding: a key on
// a foreign curve is rejected for both conversion paths.
func TestKeyConversionCurveMismatch(t *testing.T) {
	x25519Suite, err := LookupLabel(HPKE3)
	require.NoError(t, err)

	// P-256 key against the X25519 suite.
	p256Suite, err := LookupLabel(HPKE0)
	require.NoError(t, err)
	priv, err := p256Suite.Curve.GenerateKey(rand.Reader)
	require.NoError(t, err)
	privJWK, err := jwxjwk.Import(priv)
	require.NoError(t, err)

	_, err = KEMPublicKey(privJWK, x25519Suite)
	require.Error(t, err, "P-256 key must be rejected for the X25519 suite")
	assert.True(t, strings.Contains(err.Error(), "curve mismatch"), "error must name the curve mismatch, got: %v", err)
	_, err = KEMPrivateKey(privJWK, x25519Suite)
	require.Error(t, err)
}

// TestVerifyKeyUsage asserts the use=enc requirement.
func TestVerifyKeyUsage(t *testing.T) {
	p256Suite, err := LookupLabel(HPKE0)
	require.NoError(t, err)
	priv, err := p256Suite.Curve.GenerateKey(rand.Reader)
	require.NoError(t, err)
	privJWK, err := jwxjwk.Import(priv)
	require.NoError(t, err)

	// Absent use is accepted (defaults to encryption-eligible).
	require.NoError(t, VerifyKeyUsage(privJWK))

	// use=enc accepted.
	require.NoError(t, privJWK.Set(jwk.KeyUsageKey, "enc"))
	require.NoError(t, VerifyKeyUsage(privJWK))

	// use=sig rejected.
	require.NoError(t, privJWK.Set(jwk.KeyUsageKey, "sig"))
	require.Error(t, VerifyKeyUsage(privJWK))
}
