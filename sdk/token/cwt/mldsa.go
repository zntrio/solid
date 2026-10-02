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
	"crypto"
	"crypto/mldsa"
	"errors"
	"fmt"
	"io"

	"github.com/veraison/go-cose"

	"zntr.io/solid/sdk/jwk"
)

// ML-DSA signing support for COSE (RFC 9964), mirroring the JOSE
// implementation in sdk/jwk/mldsa.go: signing requires a
// *mldsa.PrivateKey, verification a *mldsa.PublicKey.
//
// go-cose does not know the ML-DSA algorithms (IANA COSE registry
// values -48 / -49 / -50, RFC 9964 section 8.1.1), so the signer and
// verifier below implement the public cose.Signer / cose.Verifier
// interfaces — the extension point documented by go-cose for algorithms
// the library does not support natively.
const (
	// AlgorithmMLDSA44 is the ML-DSA-44 COSE signature algorithm (RFC 9964).
	AlgorithmMLDSA44 cose.Algorithm = -48
	// AlgorithmMLDSA65 is the ML-DSA-65 COSE signature algorithm (RFC 9964).
	AlgorithmMLDSA65 cose.Algorithm = -49
	// AlgorithmMLDSA87 is the ML-DSA-87 COSE signature algorithm (RFC 9964).
	AlgorithmMLDSA87 cose.Algorithm = -50
)

// COSESignerMLDSA44 returns the ML-DSA-44 external go-cose signer.
func COSESignerMLDSA44(key *mldsa.PrivateKey) cose.Signer {
	return &coseSignerMLDSA{alg: AlgorithmMLDSA44, key: key}
}

// COSESignerMLDSA65 returns the ML-DSA-65 external go-cose signer.
func COSESignerMLDSA65(key *mldsa.PrivateKey) cose.Signer {
	return &coseSignerMLDSA{alg: AlgorithmMLDSA65, key: key}
}

// COSESignerMLDSA87 returns the ML-DSA-87 external go-cose signer.
func COSESignerMLDSA87(key *mldsa.PrivateKey) cose.Signer {
	return &coseSignerMLDSA{alg: AlgorithmMLDSA87, key: key}
}

// COSEVerifierMLDSA44 returns the ML-DSA-44 external go-cose verifier.
func COSEVerifierMLDSA44(key *mldsa.PublicKey) cose.Verifier {
	return &coseVerifierMLDSA{alg: AlgorithmMLDSA44, key: key}
}

// COSEVerifierMLDSA65 returns the ML-DSA-65 external go-cose verifier.
func COSEVerifierMLDSA65(key *mldsa.PublicKey) cose.Verifier {
	return &coseVerifierMLDSA{alg: AlgorithmMLDSA65, key: key}
}

// COSEVerifierMLDSA87 returns the ML-DSA-87 external go-cose verifier.
func COSEVerifierMLDSA87(key *mldsa.PublicKey) cose.Verifier {
	return &coseVerifierMLDSA{alg: AlgorithmMLDSA87, key: key}
}

// -----------------------------------------------------------------------------

type coseSignerMLDSA struct {
	alg cose.Algorithm
	key *mldsa.PrivateKey
}

// Algorithm implements the cose.Signer interface.
func (s *coseSignerMLDSA) Algorithm() cose.Algorithm { return s.alg }

// Sign implements the cose.Signer interface. The content is the complete
// Sig_structure bytes; ML-DSA signs it directly with the empty context
// string (RFC 9964 section 5).
func (s *coseSignerMLDSA) Sign(rand io.Reader, content []byte) ([]byte, error) {
	return s.key.Sign(rand, content, crypto.Hash(0))
}

type coseVerifierMLDSA struct {
	alg cose.Algorithm
	key *mldsa.PublicKey
}

// Algorithm implements the cose.Verifier interface.
func (v *coseVerifierMLDSA) Algorithm() cose.Algorithm { return v.alg }

// Verify implements the cose.Verifier interface. The content is the
// complete Sig_structure bytes, verified with the empty context string
// (RFC 9964 section 5).
func (v *coseVerifierMLDSA) Verify(content, signature []byte) error {
	return mldsa.Verify(v.key, content, signature, nil)
}

// -----------------------------------------------------------------------------

// coseSignerMLDSAForKey resolves the external ML-DSA go-cose signer for a
// solid ML-DSA key, mapping the key parameters to the RFC 9964 COSE
// algorithm values.
func CoseSignerMLDSAForKey(key *jwk.MLDSAKey) (cose.Signer, error) {
	priv := key.PrivateKey()
	if priv == nil {
		return nil, errors.New("ML-DSA key has no private key material")
	}
	switch key.AlgorithmName() {
	case jwk.MLDSA44:
		return COSESignerMLDSA44(priv), nil
	case jwk.MLDSA65:
		return COSESignerMLDSA65(priv), nil
	case jwk.MLDSA87:
		return COSESignerMLDSA87(priv), nil
	default:
		return nil, fmt.Errorf("unsupported ML-DSA algorithm %q", key.AlgorithmName())
	}
}

// coseVerifierMLDSAForKey resolves the external ML-DSA go-cose verifier for
// a solid ML-DSA key, mapping the key parameters to the RFC 9964 COSE
// algorithm values.
func CoseVerifierMLDSAForKey(key *jwk.MLDSAKey) (cose.Verifier, error) {
	pub := key.MLDSPublicKey()
	if pub == nil {
		return nil, errors.New("ML-DSA key has no public key material")
	}
	switch key.AlgorithmName() {
	case jwk.MLDSA44:
		return COSEVerifierMLDSA44(pub), nil
	case jwk.MLDSA65:
		return COSEVerifierMLDSA65(pub), nil
	case jwk.MLDSA87:
		return COSEVerifierMLDSA87(pub), nil
	default:
		return nil, fmt.Errorf("unsupported ML-DSA algorithm %q", key.AlgorithmName())
	}
}
