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

// Package cwt implements the CBOR Web Token (RFC 8392) serializer and
// verifier strategies: COSE_Sign1 signing on the go-cose algorithm
// allowlist (elliptic curves and ML-DSA only), and COSE-HPKE token
// encryption (draft-ietf-cose-hpke-27) in both operating modes.
//
// # COSE-HPKE token encryption
//
// The COSE-HPKE strategy encrypts CWTs with the HPKE ciphersuites of
// draft-ietf-cose-hpke-27 on top of the Go standard library crypto/hpke
// package (RFC 9180 Base mode — no PSK):
//
//   - Integrated Encryption (alg 35, 37, 39, 41, 42, 45 — HPKE-0..4, 7):
//     a COSE_Encrypt0 (CBOR tag 16) whose HPKE aad is the Enc_structure
//     with context "Encrypt0" (RFC 9052 section 5.3); the encapsulated
//     key rides the unprotected "ek" (label -4) header.
//
//   - Key Encryption (alg 46..49, 53 — HPKE-*-KE): a COSE_Encrypt
//     (CBOR tag 96) whose content is AEAD-encrypted under a random CEK
//     (A128GCM=1 / A256GCM=3, IV in the unprotected header); the CEK is
//     HPKE-encrypted in a single COSE_Recipient whose info is the
//     Recipient_structure ["HPKE Recipient", next_layer_alg,
//     recipient_protected, bstr extra_info] (draft section 3.3.1) with an
//     empty aad.
//
// The suite registry is the wire-agnostic mechanism package (sdk/hpke),
// shared with the JWE strategy (sdk/token/hpke,
// draft-ietf-jose-hpke-encrypt-22): every stdlib-supported KEM
// (P-256/P-384/P-521/X25519) is available, X448-based suites (COSE algs
// 43, 44, 51, 52) are rejected with an error naming the crypto/ecdh
// limitation.
//
// Security notes:
//
//   - Protected headers are bound into the HPKE key schedule: the
//     Enc_structure aad (Integrated) covers the protected header bytes,
//     and the Recipient_structure info (Key Encryption) covers the
//     recipient protected header bytes plus the next-layer content
//     algorithm — mitigating the layer-0 algorithm substitution the
//     draft section 3.3.3 describes.
//
//   - The verifier fails closed on the draft's structural rules
//     (psk_id rejected — Base mode only; exactly one recipient; ek and
//     alg present; non-empty ciphertext) and never emits partial
//     plaintext; UnverifiedClaims is unavailable on encrypted tokens.
//
//   - Recipient keys MUST be dedicated encryption keys (use=enc) on the
//     suite curve (draft section 3.4).
//
// Assembly with the sign-then-encrypt serializer:
//
//	serializer := token.Encryption(
//		cwt.AccessTokenSigner(cose.AlgorithmES256, keys),
//		cwt.CoseHPKEEncrypter(cwt.AlgHPKE7, encKeys),
//	)
//	accessTokens := token.AccessToken(serializer)
package cwt
