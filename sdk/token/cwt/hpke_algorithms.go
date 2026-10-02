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

package cwt

import (
	chpke "crypto/hpke"
	"encoding/base64"

	cbor "github.com/fxamacker/cbor/v2"

	"zntr.io/solid/sdk/hpke"
	"zntr.io/solid/sdk/jwk"
)

// COSE-HPKE algorithm identifiers (draft-ietf-cose-hpke-27 section 7.2,
// IANA COSE Algorithms registry), re-exported from the mechanism package
// for strategy assemblies. The identifiers map to the same HPKE
// ciphersuites as the JWE labels: every stdlib-supported suite
// (P-256/P-384/P-521/X25519 KEMs) is available; X448-based suites are
// rejected by the shared registry.
const (
	// AlgHPKE0 is HPKE-0: Integrated Encryption, DHKEM(P-256, HKDF-SHA256),
	// HKDF-SHA256, AES-128-GCM.
	AlgHPKE0 = hpke.COSEHPKE0
	// AlgHPKE1 is HPKE-1: Integrated Encryption, DHKEM(P-384, HKDF-SHA384),
	// HKDF-SHA384, AES-256-GCM.
	AlgHPKE1 = hpke.COSEHPKE1
	// AlgHPKE2 is HPKE-2: Integrated Encryption, DHKEM(P-521, HKDF-SHA512),
	// HKDF-SHA512, AES-256-GCM.
	AlgHPKE2 = hpke.COSEHPKE2
	// AlgHPKE3 is HPKE-3: Integrated Encryption, DHKEM(X25519, HKDF-SHA256),
	// HKDF-SHA256, AES-128-GCM.
	AlgHPKE3 = hpke.COSEHPKE3
	// AlgHPKE4 is HPKE-4: Integrated Encryption, DHKEM(X25519, HKDF-SHA256),
	// HKDF-SHA256, ChaCha20Poly1305.
	AlgHPKE4 = hpke.COSEHPKE4
	// AlgHPKE7 is HPKE-7: Integrated Encryption, DHKEM(P-256, HKDF-SHA256),
	// HKDF-SHA256, AES-256-GCM.
	AlgHPKE7 = hpke.COSEHPKE7
	// AlgHPKE0KE is HPKE-0-KE: Key Encryption, DHKEM(P-256, HKDF-SHA256),
	// HKDF-SHA256, AES-128-GCM.
	AlgHPKE0KE = hpke.COSEHPKE0KE
	// AlgHPKE1KE is HPKE-1-KE: Key Encryption, DHKEM(P-384, HKDF-SHA384),
	// HKDF-SHA384, AES-256-GCM.
	AlgHPKE1KE = hpke.COSEHPKE1KE
	// AlgHPKE2KE is HPKE-2-KE: Key Encryption, DHKEM(P-521, HKDF-SHA512),
	// HKDF-SHA512, AES-256-GCM.
	AlgHPKE2KE = hpke.COSEHPKE2KE
	// AlgHPKE3KE is HPKE-3-KE: Key Encryption, DHKEM(X25519, HKDF-SHA256),
	// HKDF-SHA256, AES-128-GCM.
	AlgHPKE3KE = hpke.COSEHPKE3KE
	// AlgHPKE7KE is HPKE-7-KE: Key Encryption, DHKEM(P-256, HKDF-SHA256),
	// HKDF-SHA256, AES-256-GCM.
	AlgHPKE7KE = hpke.COSEHPKE7KE
)

// COSE-HPKE header parameter labels (draft section 7.3, IANA COSE Header
// Parameters registry).
const (
	// headerLabelEK is the "ek" header parameter: the HPKE encapsulated
	// key, a bstr in the unprotected bucket.
	headerLabelEK = -4
	// headerLabelPSKID is the "psk_id" header parameter, protected-only:
	// its presence selects HPKE mode_psk, which this package rejects
	// (stdlib crypto/hpke implements Base mode only).
	headerLabelPSKID = -5
)

// CBOR tags of the COSE encryption structures (RFC 8949 / IANA CBOR Tags
// registry, COSE values): COSE_Encrypt0 is 16, COSE_Encrypt is 96.
const (
	cborTagEncrypt0 = 16
	cborTagEncrypt  = 96
)

// lookupCoseSuite resolves a COSE-HPKE algorithm identifier, delegating to
// the mechanism registry. Identifiers outside the registry — including the
// X448 suites (HPKE-5/6 and their -KE variants, 43/44/51/52) and the
// draft-27 KE-only 50 (HPKE-4-KE) — are rejected with an error naming the
// reason.
func lookupCoseSuite(alg int64) (*hpke.Suite, error) {
	return hpke.LookupCOSE(alg)
}

// SupportedCoseHPKEAlgorithms returns the sorted list of supported
// COSE-HPKE algorithm identifiers.
func SupportedCoseHPKEAlgorithms() []int64 {
	return hpke.SupportedCOSEAlgorithms()
}

// coseKEMPublicKey resolves the HPKE encapsulation key of a JWK for the
// given suite (delegated to the mechanism package key conversion).
func coseKEMPublicKey(key jwk.Key, s *hpke.Suite) (chpke.PublicKey, error) {
	return hpke.KEMPublicKey(key, s)
}

// coseKEMPrivateKey resolves the HPKE decapsulation key of a JWK for the
// given suite.
func coseKEMPrivateKey(key jwk.Key, s *hpke.Suite) (chpke.PrivateKey, error) {
	return hpke.KEMPrivateKey(key, s)
}

// encodeBase64 is the token wire encoding shared by the CWT package
// (base64url, no padding).
func encodeBase64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// decodeBase64 decodes the token wire encoding.
func decodeBase64(raw string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(raw)
}

// cborDeterministicMode is the deterministic CBOR encoding mandated by the
// draft for the Recipient_structure (RFC 8949 section 4.2.1 Core
// Deterministic Encoding Requirements): shortest-form length headers and
// canonically sorted map keys.
var cborDeterministicMode = func() cbor.EncMode {
	mode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		// CoreDetEncOptions are always valid: a failure is a programming
		// error caught at boot.
		panic(err)
	}
	return mode
}()

// cborDeterministicDecode decodes with the default decoding mode: CBOR
// decoding is not affected by the deterministic encoding rules, the
// standard Unmarshal semantics apply.
var cborDeterministicDecode = func() cbor.DecMode {
	mode, err := cbor.DecOptions{}.DecMode()
	if err != nil {
		panic(err)
	}
	return mode
}()
