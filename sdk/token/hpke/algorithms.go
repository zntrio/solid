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

// Package hpke implements the JWE token encryption strategy of
// draft-ietf-jose-hpke-encrypt-22 on top of the wire-agnostic HPKE
// mechanism package (sdk/hpke) and the Go standard library crypto/hpke
// package (RFC 9180 Base mode).
package hpke

import (
	"fmt"
	"sort"

	"zntr.io/solid/sdk/hpke"
)

// Supported JWE "alg" values (draft-ietf-jose-hpke-encrypt-22 section 5.1
// and 6.2, Table 3), re-exported from the mechanism package for strategy
// assemblies.
const (
	// HPKE0 is DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM,
	// Integrated Encryption.
	HPKE0 = hpke.HPKE0
	// HPKE1 is DHKEM(P-384, HKDF-SHA384) + HKDF-SHA384 + AES-256-GCM,
	// Integrated Encryption.
	HPKE1 = hpke.HPKE1
	// HPKE2 is DHKEM(P-521, HKDF-SHA512) + HKDF-SHA512 + AES-256-GCM,
	// Integrated Encryption.
	HPKE2 = hpke.HPKE2
	// HPKE3 is DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM,
	// Integrated Encryption.
	HPKE3 = hpke.HPKE3
	// HPKE4 is DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20Poly1305,
	// Integrated Encryption.
	HPKE4 = hpke.HPKE4
	// HPKE7 is DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM,
	// Integrated Encryption.
	HPKE7 = hpke.HPKE7
	// HPKE0KE is DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM,
	// Key Encryption.
	HPKE0KE = hpke.HPKE0KE
	// HPKE1KE is DHKEM(P-384, HKDF-SHA384) + HKDF-SHA384 + AES-256-GCM,
	// Key Encryption.
	HPKE1KE = hpke.HPKE1KE
	// HPKE2KE is DHKEM(P-521, HKDF-SHA512) + HKDF-SHA512 + AES-256-GCM,
	// Key Encryption.
	HPKE2KE = hpke.HPKE2KE
	// HPKE3KE is DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM,
	// Key Encryption.
	HPKE3KE = hpke.HPKE3KE
	// HPKE7KE is DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM,
	// Key Encryption.
	HPKE7KE = hpke.HPKE7KE
)

// Content-encryption algorithm identifiers usable as the "enc" header
// parameter in Key Encryption mode (draft section 6.1).
const (
	// EncA128GCM is the AES-128-GCM content-encryption algorithm.
	EncA128GCM = "A128GCM"
	// EncA256GCM is the AES-256-GCM content-encryption algorithm.
	EncA256GCM = "A256GCM"
)

// contentTypeJWE is the ContentType of the JWE serializer and verifiers:
// the outer serialization this package parses.
const contentTypeJWE = "JWE"

// lookupSuite resolves a suite by its JWE "alg" identifier, delegating to
// the mechanism registry. X448-based suites (HPKE-5, HPKE-6, HPKE-5-KE,
// HPKE-6-KE) get a dedicated error naming the standard library limitation;
// anything else is an unknown algorithm.
func lookupSuite(alg string) (*hpke.Suite, error) {
	return hpke.LookupLabel(alg)
}

// SupportedAlgorithms returns the sorted list of supported "alg" values.
func SupportedAlgorithms() []string {
	labels := hpke.SupportedJWELabels()
	sort.Strings(labels)
	return labels
}

// SupportedEncAlgorithms returns the content-encryption algorithms usable
// as the "enc" header parameter in Key Encryption mode.
func SupportedEncAlgorithms() []string {
	return []string{EncA128GCM, EncA256GCM}
}

// cekSizeForEnc returns the content-encryption key size in bytes of the
// given "enc" identifier.
func cekSizeForEnc(enc string) (int, error) {
	switch enc {
	case EncA128GCM:
		return 16, nil
	case EncA256GCM:
		return 32, nil
	default:
		return 0, unsupportedEncError(enc)
	}
}

// unsupportedEncError builds the error for an unsupported content-
// encryption algorithm identifier.
func unsupportedEncError(enc string) error {
	return fmt.Errorf("unsupported content-encryption algorithm %q: supported values are %s and %s", enc, EncA128GCM, EncA256GCM)
}
