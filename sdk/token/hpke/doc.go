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

// Package hpke implements the JWE token encryption strategy defined by
// draft-ietf-jose-hpke-encrypt-22, on top of the wire-agnostic HPKE
// mechanism package (sdk/hpke) and the Go standard library crypto/hpke
// package (RFC 9180 Base mode — no PSK). Both Key Management Modes of the
// draft are provided: Integrated Encryption (alg HPKE-0..4, 7: the HPKE
// ciphertext is the JWE ciphertext, IV and tag segments are empty, the
// HPKE aad is the encoded protected header) and Key Encryption (alg
// HPKE-*-KE: the CEK is HPKE-encrypted with the Recipient_structure
// info, the content layer is A128GCM/A256GCM).
//
// Supported algorithm suites (draft Tables 1 and 2), all resolved from
// crypto/hpke and crypto/ecdh:
//
//	alg        KEM                        KDF         AEAD             mode
//	HPKE-0     DHKEM(P-256, HKDF-SHA256)  HKDF-SHA256 AES-128-GCM      Integrated
//	HPKE-1     DHKEM(P-384, HKDF-SHA384)  HKDF-SHA384 AES-256-GCM      Integrated
//	HPKE-2     DHKEM(P-521, HKDF-SHA512)  HKDF-SHA512 AES-256-GCM      Integrated
//	HPKE-3     DHKEM(X25519, HKDF-SHA256) HKDF-SHA256 AES-128-GCM      Integrated
//	HPKE-4     DHKEM(X25519, HKDF-SHA256) HKDF-SHA256 ChaCha20-Poly1305 Integrated
//	HPKE-7     DHKEM(P-256, HKDF-SHA256)  HKDF-SHA256 AES-256-GCM      Integrated
//	HPKE-0-KE  DHKEM(P-256, HKDF-SHA256)  HKDF-SHA256 AES-128-GCM      KeyEnc
//	HPKE-1-KE  DHKEM(P-384, HKDF-SHA384)  HKDF-SHA384 AES-256-GCM      KeyEnc
//	HPKE-2-KE  DHKEM(P-521, HKDF-SHA512)  HKDF-SHA512 AES-256-GCM      KeyEnc
//	HPKE-3-KE  DHKEM(X25519, HKDF-SHA256) HKDF-SHA256 AES-128-GCM      KeyEnc
//	HPKE-7-KE  DHKEM(P-256, HKDF-SHA256)  HKDF-SHA256 AES-256-GCM      KeyEnc
//
// X448-based suites (HPKE-5, HPKE-6, HPKE-5-KE, HPKE-6-KE) are not
// supported: the standard library crypto/ecdh package has no X448, and
// requesting those algorithms returns an explicit error naming the
// limitation rather than silently omitting them.
//
// Security notes:
//
//   - Key separation (draft section 10.1): recipient keys MUST be
//     dedicated encryption keys (use=enc) on the curve of the chosen
//     suite; the encrypter rejects signing keys and curve mismatches.
//
//   - JWS/JWE disambiguation (draft section 8): a JWE using Integrated
//     Encryption has no enc header member, so the RFC 7516 section 9
//     last-bullet discrimination rule does not apply to it; consumers
//     must rely on the structure (5-segment JWE vs 3-segment JWS) and
//     the alg value.
//
//   - The verifier fails closed on every header rule of the draft
//     (zip, crit, psk_id, mode-specific enc/ek constraints, duplicate
//     header members, padded base64url) and never emits partial
//     plaintext; UnverifiedClaims is unavailable on encrypted tokens.
//
// Assembly with the sign-then-encrypt serializer:
//
//	serializer := token.Encryption(
//		jwt.AccessTokenSigner("ES256", keys),
//		hpke.Encrypter(hpke.HPKE7, encKeys),
//	)
//	accessTokens := token.AccessToken(serializer)
package hpke
