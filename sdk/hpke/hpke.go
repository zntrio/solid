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

// Package hpke carries the wire-agnostic HPKE mechanism shared by the
// token serialization strategies: the ciphersuite registry spanning the
// JWE labels of draft-ietf-jose-hpke-encrypt-22 and the COSE algorithm
// identifiers of draft-ietf-cose-hpke-27, and the JWK-to-HPKE key
// conversion. Both drafts select from the same underlying HPKE
// ciphersuites (RFC 9180, implemented by the Go standard library
// crypto/hpke package, Base mode — no PSK); they differ only in the
// serialization of the result.
//
// The JWE strategy lives in sdk/token/hpke, the COSE/CWT strategy in
// sdk/token/cwt; neither depends on the other, both depend on this
// package.
package hpke

import (
	"crypto/ecdh"
	"crypto/hpke"
	"fmt"
	"sort"

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"

	"zntr.io/solid/sdk/jwk"
)

// JWE "alg" labels of the HPKE suites (draft-ietf-jose-hpke-encrypt-22
// sections 5.1 and 6.2, Table 3).
const (
	// HPKE0 is DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM,
	// Integrated Encryption.
	HPKE0 = "HPKE-0"
	// HPKE1 is DHKEM(P-384, HKDF-SHA384) + HKDF-SHA384 + AES-256-GCM,
	// Integrated Encryption.
	HPKE1 = "HPKE-1"
	// HPKE2 is DHKEM(P-521, HKDF-SHA512) + HKDF-SHA512 + AES-256-GCM,
	// Integrated Encryption.
	HPKE2 = "HPKE-2"
	// HPKE3 is DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM,
	// Integrated Encryption.
	HPKE3 = "HPKE-3"
	// HPKE4 is DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20Poly1305,
	// Integrated Encryption.
	HPKE4 = "HPKE-4"
	// HPKE7 is DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM,
	// Integrated Encryption.
	HPKE7 = "HPKE-7"
	// HPKE0KE is DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM,
	// Key Encryption.
	HPKE0KE = "HPKE-0-KE"
	// HPKE1KE is DHKEM(P-384, HKDF-SHA384) + HKDF-SHA384 + AES-256-GCM,
	// Key Encryption.
	HPKE1KE = "HPKE-1-KE"
	// HPKE2KE is DHKEM(P-521, HKDF-SHA512) + HKDF-SHA512 + AES-256-GCM,
	// Key Encryption.
	HPKE2KE = "HPKE-2-KE"
	// HPKE3KE is DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM,
	// Key Encryption.
	HPKE3KE = "HPKE-3-KE"
	// HPKE7KE is DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM,
	// Key Encryption.
	HPKE7KE = "HPKE-7-KE"
)

// COSE-HPKE algorithm identifiers (draft-ietf-cose-hpke-27 section 7.2,
// IANA COSE Algorithms registry) mapped onto the same suites.
const (
	// COSEHPKE0 is HPKE-0 (Integrated Encryption).
	COSEHPKE0 = 35
	// COSEHPKE1 is HPKE-1 (Integrated Encryption).
	COSEHPKE1 = 37
	// COSEHPKE2 is HPKE-2 (Integrated Encryption).
	COSEHPKE2 = 39
	// COSEHPKE3 is HPKE-3 (Integrated Encryption).
	COSEHPKE3 = 41
	// COSEHPKE4 is HPKE-4 (Integrated Encryption).
	COSEHPKE4 = 42
	// COSEHPKE7 is HPKE-7 (Integrated Encryption).
	COSEHPKE7 = 45
	// COSEHPKE0KE is HPKE-0-KE (Key Encryption).
	COSEHPKE0KE = 46
	// COSEHPKE1KE is HPKE-1-KE (Key Encryption).
	COSEHPKE1KE = 47
	// COSEHPKE2KE is HPKE-2-KE (Key Encryption).
	COSEHPKE2KE = 48
	// COSEHPKE3KE is HPKE-3-KE (Key Encryption).
	COSEHPKE3KE = 49
	// COSEHPKE7KE is HPKE-7-KE (Key Encryption).
	COSEHPKE7KE = 53
)

// Suite describes one supported HPKE ciphersuite: the primitives resolved
// from crypto/hpke, the KEM curve, the operating mode (Integrated or Key
// Encryption) and its two wire identifiers (the JWE alg label and the COSE
// algorithm ID).
type Suite struct {
	// Label is the JWE "alg" identifier of the suite.
	Label string
	// COSE is the COSE-HPKE algorithm identifier of the suite.
	COSE int64
	// KEM is the key encapsulation mechanism.
	KEM hpke.KEM
	// KDF is the key derivation function.
	KDF hpke.KDF
	// AEAD is the authenticated encryption algorithm.
	AEAD hpke.AEAD
	// Curve is the KEM curve.
	Curve ecdh.Curve
	// KeyEncryption reports the Key Encryption operating mode.
	KeyEncryption bool
}

// suites is the registry: every suite whose KEM is available from the Go
// standard library crypto/ecdh package, keyed by JWE label and by COSE
// identifier.
//
// X448-based suites (JWE HPKE-5/6 and -KE variants; COSE 43, 44, 51, 52)
// are intentionally absent: the standard library crypto/ecdh package does
// not implement X448, so these algorithms are rejected as unsupported
// rather than silently omitted from negotiation.
var (
	suitesByLabel = map[string]*Suite{
		HPKE0:   {Label: HPKE0, COSE: COSEHPKE0, KEM: hpke.DHKEM(ecdh.P256()), KDF: hpke.HKDFSHA256(), AEAD: hpke.AES128GCM(), Curve: ecdh.P256()},
		HPKE1:   {Label: HPKE1, COSE: COSEHPKE1, KEM: hpke.DHKEM(ecdh.P384()), KDF: hpke.HKDFSHA384(), AEAD: hpke.AES256GCM(), Curve: ecdh.P384()},
		HPKE2:   {Label: HPKE2, COSE: COSEHPKE2, KEM: hpke.DHKEM(ecdh.P521()), KDF: hpke.HKDFSHA512(), AEAD: hpke.AES256GCM(), Curve: ecdh.P521()},
		HPKE3:   {Label: HPKE3, COSE: COSEHPKE3, KEM: hpke.DHKEM(ecdh.X25519()), KDF: hpke.HKDFSHA256(), AEAD: hpke.AES128GCM(), Curve: ecdh.X25519()},
		HPKE4:   {Label: HPKE4, COSE: COSEHPKE4, KEM: hpke.DHKEM(ecdh.X25519()), KDF: hpke.HKDFSHA256(), AEAD: hpke.ChaCha20Poly1305(), Curve: ecdh.X25519()},
		HPKE7:   {Label: HPKE7, COSE: COSEHPKE7, KEM: hpke.DHKEM(ecdh.P256()), KDF: hpke.HKDFSHA256(), AEAD: hpke.AES256GCM(), Curve: ecdh.P256()},
		HPKE0KE: {Label: HPKE0KE, COSE: COSEHPKE0KE, KEM: hpke.DHKEM(ecdh.P256()), KDF: hpke.HKDFSHA256(), AEAD: hpke.AES128GCM(), Curve: ecdh.P256(), KeyEncryption: true},
		HPKE1KE: {Label: HPKE1KE, COSE: COSEHPKE1KE, KEM: hpke.DHKEM(ecdh.P384()), KDF: hpke.HKDFSHA384(), AEAD: hpke.AES256GCM(), Curve: ecdh.P384(), KeyEncryption: true},
		HPKE2KE: {Label: HPKE2KE, COSE: COSEHPKE2KE, KEM: hpke.DHKEM(ecdh.P521()), KDF: hpke.HKDFSHA512(), AEAD: hpke.AES256GCM(), Curve: ecdh.P521(), KeyEncryption: true},
		HPKE3KE: {Label: HPKE3KE, COSE: COSEHPKE3KE, KEM: hpke.DHKEM(ecdh.X25519()), KDF: hpke.HKDFSHA256(), AEAD: hpke.AES128GCM(), Curve: ecdh.X25519(), KeyEncryption: true},
		HPKE7KE: {Label: HPKE7KE, COSE: COSEHPKE7KE, KEM: hpke.DHKEM(ecdh.P256()), KDF: hpke.HKDFSHA256(), AEAD: hpke.AES256GCM(), Curve: ecdh.P256(), KeyEncryption: true},
	}
	suitesByCOSE = func() map[int64]*Suite {
		m := make(map[int64]*Suite, len(suitesByLabel))
		for _, s := range suitesByLabel {
			m[s.COSE] = s
		}
		return m
	}()
)

// LookupLabel resolves a suite by its JWE "alg" label. X448-based suites
// (HPKE-5, HPKE-6, HPKE-5-KE, HPKE-6-KE) get a dedicated error naming the
// standard library limitation; anything else is an unknown algorithm.
func LookupLabel(label string) (*Suite, error) {
	if s, ok := suitesByLabel[label]; ok {
		return s, nil
	}
	switch label {
	case "HPKE-5", "HPKE-6", "HPKE-5-KE", "HPKE-6-KE":
		return nil, fmt.Errorf("unsupported HPKE algorithm %q: X448 is not available in the standard library crypto/ecdh package", label)
	case "HPKE-4-KE":
		return nil, fmt.Errorf("unknown HPKE algorithm %q: HPKE-4-KE is not registered in draft-ietf-jose-hpke-encrypt-22", label)
	default:
		return nil, fmt.Errorf("unknown HPKE algorithm %q", label)
	}
}

// LookupCOSE resolves a suite by its COSE-HPKE algorithm identifier.
// X448-based identifiers (43, 44, 51, 52) get a dedicated error naming the
// standard library limitation; anything else is an unknown algorithm.
func LookupCOSE(alg int64) (*Suite, error) {
	if s, ok := suitesByCOSE[alg]; ok {
		return s, nil
	}
	switch alg {
	case 43, 44, 51, 52:
		return nil, fmt.Errorf("unsupported COSE-HPKE algorithm %d: X448 is not available in the standard library crypto/ecdh package", alg)
	default:
		return nil, fmt.Errorf("unknown COSE-HPKE algorithm %d", alg)
	}
}

// SupportedJWELabels returns the sorted list of supported JWE "alg" labels.
func SupportedJWELabels() []string {
	labels := make([]string, 0, len(suitesByLabel))
	for label := range suitesByLabel {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	return labels
}

// SupportedCOSEAlgorithms returns the sorted list of supported COSE-HPKE
// algorithm identifiers.
func SupportedCOSEAlgorithms() []int64 {
	algs := make([]int64, 0, len(suitesByCOSE))
	for alg := range suitesByCOSE {
		algs = append(algs, alg)
	}
	sort.Slice(algs, func(i, j int) bool { return algs[i] < algs[j] })
	return algs
}

// VerifyKeyUsage rejects keys not explicitly reserved for encryption.
func VerifyKeyUsage(k jwk.Key) error {
	if use, ok := k.KeyUsage(); ok && use != "enc" {
		return fmt.Errorf("key %q is not an encryption key (use=%q)", KeyIDOf(k), use)
	}
	return nil
}

// KeyIDOf returns the key kid, or a placeholder when absent.
func KeyIDOf(k jwk.Key) string {
	if kid, ok := k.KeyID(); ok && kid != "" {
		return kid
	}
	return "<no kid>"
}

// KEMPublicKey resolves the HPKE encapsulation key of a JWK for the given
// suite. The key must be an EC or X25519 OKP key matching the suite KEM
// curve; any other key type or curve mismatch is rejected (both drafts
// require KEM key pairs dedicated to the algorithm suite). Private keys
// are accepted: the JWK public part is derived first.
func KEMPublicKey(k jwk.Key, s *Suite) (hpke.PublicKey, error) {
	ecdhPub, err := ECDHPublicKey(k, s)
	if err != nil {
		return nil, err
	}
	pk, err := hpke.NewDHKEMPublicKey(ecdhPub)
	if err != nil {
		return nil, fmt.Errorf("unable to derive HPKE public key: %w", err)
	}
	return pk, nil
}

// KEMPrivateKey resolves the HPKE decapsulation key of a JWK for the given
// suite.
func KEMPrivateKey(k jwk.Key, s *Suite) (hpke.PrivateKey, error) {
	ecdhPriv, err := ECDHPrivateKey(k, s)
	if err != nil {
		return nil, err
	}
	sk, err := hpke.NewDHKEMPrivateKey(ecdhPriv)
	if err != nil {
		return nil, fmt.Errorf("unable to derive HPKE private key: %w", err)
	}
	return sk, nil
}

// ECDHPublicKey converts a JWK to a crypto/ecdh public key bound to the
// suite curve, via the jwx Export hint conversion (the jwx EC and OKP
// exporters accept ecdh.PublicKey destinations). A private JWK yields its
// public counterpart.
func ECDHPublicKey(k jwk.Key, s *Suite) (*ecdh.PublicKey, error) {
	if kty := k.KeyType().String(); kty != "EC" && kty != "OKP" {
		return nil, fmt.Errorf("unsupported key type %q for HPKE key %q: expected EC or OKP", kty, KeyIDOf(k))
	}

	// Export public parts only: a private JWK passed through PublicKey()
	// strips the d field, and the jwx exporter for EC private keys does not
	// support public-key destinations.
	pub, err := k.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("unable to derive public key from %q: %w", KeyIDOf(k), err)
	}
	var raw ecdh.PublicKey
	if err := jwxjwk.Export(pub, &raw); err != nil {
		return nil, fmt.Errorf("unable to convert key %q to an ECDH public key: %w", KeyIDOf(k), err)
	}
	if err := checkCurve(raw.Curve(), s, KeyIDOf(k)); err != nil {
		return nil, err
	}
	return &raw, nil
}

// ECDHPrivateKey converts a JWK to a crypto/ecdh private key bound to the
// suite curve.
func ECDHPrivateKey(k jwk.Key, s *Suite) (*ecdh.PrivateKey, error) {
	if kty := k.KeyType().String(); kty != "EC" && kty != "OKP" {
		return nil, fmt.Errorf("unsupported key type %q for HPKE key %q: expected EC or OKP", kty, KeyIDOf(k))
	}
	var raw ecdh.PrivateKey
	if err := jwxjwk.Export(k, &raw); err != nil {
		return nil, fmt.Errorf("unable to convert key %q to an ECDH private key: %w", KeyIDOf(k), err)
	}
	if err := checkCurve(raw.Curve(), s, KeyIDOf(k)); err != nil {
		return nil, err
	}
	return &raw, nil
}

// checkCurve enforces that the key curve equals the suite KEM curve. The
// standard library ecdh package returns singletons from P256/P384/P521/
// X25519, so interface equality is reliable here.
func checkCurve(curve ecdh.Curve, s *Suite, kid string) error {
	if curve != s.Curve {
		return fmt.Errorf("curve mismatch for key %q: algorithm %s requires %s, got %s", kid, s.Label, s.Curve, curve)
	}
	return nil
}
