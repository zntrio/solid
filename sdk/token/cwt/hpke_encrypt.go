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
	"context"
	"crypto/aes"
	"crypto/cipher"
	chpke "crypto/hpke"
	"crypto/rand"
	"fmt"

	cbor "github.com/fxamacker/cbor/v2"

	mech "zntr.io/solid/sdk/hpke"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token"
)

// COSE content-encryption (AEAD) algorithm identifiers for the Key
// Encryption mode layer 0 (RFC 9053 IANA COSE Algorithms registry): the
// repo security posture excludes the HS* family, both AES-GCM AEADs are
// offered.
const (
	// CoseAlgA128GCM is AES-128-GCM content encryption.
	CoseAlgA128GCM = 1
	// CoseAlgA256GCM is AES-256-GCM content encryption.
	CoseAlgA256GCM = 3
)

// coseCekSizeForEnc returns the content-encryption key size in bytes of
// the given COSE AEAD identifier.
func coseCekSizeForEnc(alg int64) (int, error) {
	switch alg {
	case CoseAlgA128GCM:
		return 16, nil
	case CoseAlgA256GCM:
		return 32, nil
	default:
		return 0, fmt.Errorf("unsupported COSE content-encryption algorithm %d: supported values are 1 (A128GCM) and 3 (A256GCM)", alg)
	}
}

// coseGcmForKey returns the AES-GCM AEAD for the given CEK, COSE AEAD
// identifier and IV length: COSE carries algorithm-determined IV sizes
// (the draft's own key-encryption example uses a 16-byte IV), so the
// nonce size follows the wire value instead of the Go default 12.
func coseGcmForKey(cek []byte, alg int64, ivLen int) (cipher.AEAD, error) {
	switch alg {
	case CoseAlgA128GCM, CoseAlgA256GCM:
		block, err := aes.NewCipher(cek)
		if err != nil {
			return nil, fmt.Errorf("unable to initialize content encryption: %w", err)
		}
		aead, err := cipher.NewGCMWithNonceSize(block, ivLen)
		if err != nil {
			return nil, fmt.Errorf("unable to initialize content encryption: %w", err)
		}
		return aead, nil
	default:
		return nil, fmt.Errorf("unsupported COSE content-encryption algorithm %d", alg)
	}
}

// -----------------------------------------------------------------------------

// CoseHPKEEncrypter returns a token Encrypter producing COSE_Encrypt0
// (CBOR tag 16) objects with the given COSE-HPKE Integrated Encryption
// algorithm (draft-ietf-cose-hpke-27 section 3.2, one of AlgHPKE0..4, 7).
//
// The COSE_Encrypt0 carries the HPKE encapsulated key in the unprotected
// "ek" (label -4) header; the HPKE aad is the Enc_structure of the
// COSE_Encrypt0 (context "Encrypt0", RFC 9052 section 5.3) with empty
// external_aad, so the aad argument of the Encrypter contract is ignored:
// the ciphertext is bound to the protected header bytes on the wire.
//
// The recipient key constraints match the JWE strategy: an EC or X25519
// OKP JWK on the suite curve, reserved for encryption (use=enc).
func CoseHPKEEncrypter(alg int64, keyProvider jwk.KeyProviderFunc) token.Encrypter {
	return &coseIntegratedEncrypter{
		alg:         alg,
		keyProvider: keyProvider,
	}
}

// CoseHPKEKeyEncryptionEncrypter returns a Key Encryption mode Encrypter
// (draft section 3.3): the output is a COSE_Encrypt (CBOR tag 96) with the
// content encrypted under a random CEK with the given COSE AEAD algorithm
// (CoseAlgA128GCM or CoseAlgA256GCM), and the CEK HPKE-encrypted in a
// single COSE_Recipient whose info is the Recipient_structure
// (context "HPKE Recipient", draft section 3.3.1) and whose aad is empty.
func CoseHPKEKeyEncryptionEncrypter(alg, contentAlg int64, keyProvider jwk.KeyProviderFunc) token.Encrypter {
	return &coseKeyEncryptionEncrypter{
		alg:         alg,
		contentAlg:  contentAlg,
		keyProvider: keyProvider,
	}
}

// -----------------------------------------------------------------------------

type coseIntegratedEncrypter struct {
	alg         int64
	keyProvider jwk.KeyProviderFunc
}

// Encrypt encrypts the token with the COSE-HPKE Integrated Encryption mode.
func (e *coseIntegratedEncrypter) Encrypt(_ context.Context, _, tokenStr string, _ []byte) (string, error) {
	// Check arguments
	if e.keyProvider == nil {
		return "", fmt.Errorf("unable to encrypt with nil key provider")
	}

	// Resolve suite and primitives
	s, err := lookupCoseSuite(e.alg)
	if err != nil {
		return "", fmt.Errorf("unable to resolve COSE-HPKE algorithm: %w", err)
	}
	if s.KeyEncryption {
		return "", fmt.Errorf("COSE-HPKE algorithm %d is a Key Encryption suite: use CoseHPKEKeyEncryptionEncrypter", e.alg)
	}
	suite, err := mech.LookupLabel(s.Label)
	if err != nil {
		return "", err
	}

	// Resolve recipient public key
	key, err := e.keyProvider(context.Background())
	if err != nil {
		return "", fmt.Errorf("unable to resolve encryption key: %w", err)
	}
	err = mech.VerifyKeyUsage(key)
	if err != nil {
		return "", err
	}
	pub, err := coseKEMPublicKey(key, s)
	if err != nil {
		return "", err
	}

	// Protected header: alg (and kid when present), protected per draft
	// section 3.2. Serialized with the deterministic mode: the exact bytes
	// feed the Enc_structure.
	protected := map[int64]any{headerLabelAlg: e.alg}
	if kid, ok := key.KeyID(); ok && kid != "" {
		protected[headerLabelKid] = []byte(kid)
	}
	protectedSerialized, err := cborDeterministicMode.Marshal(protected)
	if err != nil {
		return "", fmt.Errorf("unable to encode protected header: %w", err)
	}

	// HPKE Seal with aad = Enc_structure("Encrypt0", protected, "")
	aad, err := encStructure("Encrypt0", protectedSerialized)
	if err != nil {
		return "", err
	}
	encap, sender, err := chpke.NewSender(pub, suite.KDF, suite.AEAD, nil)
	if err != nil {
		return "", fmt.Errorf("unable to initialize HPKE sender: %w", err)
	}
	ciphertext, err := sender.Seal(aad, []byte(tokenStr))
	if err != nil {
		return "", fmt.Errorf("unable to seal token: %w", err)
	}

	// COSE_Encrypt0: [ protected : bstr, unprotected : map, ciphertext ]
	encrypt0 := []any{
		protectedSerialized,
		map[int64]any{headerLabelEK: encap},
		ciphertext,
	}
	tagged, err := cborDeterministicMode.Marshal(cbor.Tag{Number: cborTagEncrypt0, Content: encrypt0})
	if err != nil {
		return "", fmt.Errorf("unable to encode COSE_Encrypt0: %w", err)
	}

	return encodeBase64(tagged), nil
}

// -----------------------------------------------------------------------------

type coseKeyEncryptionEncrypter struct {
	alg         int64
	contentAlg  int64
	keyProvider jwk.KeyProviderFunc
}

// Encrypt encrypts the token with the COSE-HPKE Key Encryption mode.
func (e *coseKeyEncryptionEncrypter) Encrypt(_ context.Context, _, tokenStr string, _ []byte) (string, error) {
	// Check arguments
	if e.keyProvider == nil {
		return "", fmt.Errorf("unable to encrypt with nil key provider")
	}
	// Resolve suite, primitives, CEK size and recipient public key.
	suite, pub, cekSize, key, err := e.resolve()
	if err != nil {
		return "", err
	}

	// Generate CEK (draft section 3.3.2) and IV.
	cek := make([]byte, cekSize)
	if _, err = rand.Read(cek); err != nil {
		return "", fmt.Errorf("unable to generate content encryption key: %w", err)
	}
	iv := make([]byte, 12)
	if _, err = rand.Read(iv); err != nil {
		return "", fmt.Errorf("unable to generate initialization vector: %w", err)
	}

	// Layer 0 protected header: the content-encryption algorithm; the IV
	// rides the unprotected bucket (label 5, RFC 9052 section 3.1).
	contentProtected, err := cborDeterministicMode.Marshal(map[int64]any{headerLabelAlg: e.contentAlg})
	if err != nil {
		return "", fmt.Errorf("unable to encode content protected header: %w", err)
	}
	contentUnprotected := map[int64]any{headerLabelIV: iv}

	// Content encryption: aad = Enc_structure("Encrypt", protected, "").
	contentAAD, err := encStructure("Encrypt", contentProtected)
	if err != nil {
		return "", err
	}
	contentAEAD, err := coseGcmForKey(cek, e.contentAlg, len(iv))
	if err != nil {
		return "", err
	}
	contentCiphertext := contentAEAD.Seal(nil, iv, []byte(tokenStr), contentAAD)

	// Encrypt the CEK to the recipient and build the COSE_Recipient
	// (draft section 3.3.2: protected alg + kid, HPKE info =
	// Recipient_structure, aad empty, ek in the unprotected bucket).
	recipient, err := sealCoseRecipient(pub, suite, e.alg, e.contentAlg, cek, key)
	if err != nil {
		return "", err
	}

	// COSE_Encrypt: [ protected : bstr, unprotected : map, ciphertext,
	// recipients : [ COSE_Recipient ] ].
	encryptMsg := []any{
		contentProtected,
		contentUnprotected,
		contentCiphertext,
		[]any{recipient},
	}
	tagged, err := cborDeterministicMode.Marshal(cbor.Tag{Number: cborTagEncrypt, Content: encryptMsg})
	if err != nil {
		return "", fmt.Errorf("unable to encode COSE_Encrypt: %w", err)
	}

	return encodeBase64(tagged), nil
}

// sealCoseRecipient HPKE-encrypts the CEK to the recipient public key and
// assembles the COSE_Recipient array: [ protected : bstr, unprotected :
// map{ek}, ciphertext ]. The HPKE info is the Recipient_structure binding
// the next-layer content algorithm and the recipient protected header
// bytes; the aad is empty (draft sections 3.3.1, 3.3.2).
func sealCoseRecipient(pub chpke.PublicKey, suite *mech.Suite, alg, contentAlg int64, cek []byte, key jwk.Key) ([]any, error) {
	// Recipient protected header: the HPKE suite alg and kid — both are
	// fed into the HPKE key schedule through the Recipient_structure.
	recipientProtected := map[int64]any{headerLabelAlg: alg}
	if kid, ok := key.KeyID(); ok && kid != "" {
		recipientProtected[headerLabelKid] = []byte(kid)
	}
	recipientProtectedSerialized, err := cborDeterministicMode.Marshal(recipientProtected)
	if err != nil {
		return nil, fmt.Errorf("unable to encode recipient protected header: %w", err)
	}

	info, err := recipientStructure(contentAlg, recipientProtectedSerialized, nil)
	if err != nil {
		return nil, err
	}
	encap, sender, err := chpke.NewSender(pub, suite.KDF, suite.AEAD, info)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize HPKE sender: %w", err)
	}
	encryptedCEK, err := sender.Seal(nil, cek)
	if err != nil {
		return nil, fmt.Errorf("unable to encrypt content encryption key: %w", err)
	}

	return []any{
		recipientProtectedSerialized,
		map[int64]any{headerLabelEK: encap},
		encryptedCEK,
	}, nil
}

// resolve resolves the HPKE suite, the recipient public key and the CEK
// size for a Key Encryption operation.
func (e *coseKeyEncryptionEncrypter) resolve() (suite *mech.Suite, pub chpke.PublicKey, cekSize int, key jwk.Key, err error) {
	suite, err = lookupCoseSuite(e.alg)
	if err != nil {
		return nil, nil, 0, nil, fmt.Errorf("unable to resolve COSE-HPKE algorithm: %w", err)
	}
	if !suite.KeyEncryption {
		return nil, nil, 0, nil, fmt.Errorf("COSE-HPKE algorithm %d is an Integrated Encryption suite: use CoseHPKEEncrypter", e.alg)
	}
	cekSize, err = coseCekSizeForEnc(e.contentAlg)
	if err != nil {
		return nil, nil, 0, nil, fmt.Errorf("unable to resolve content-encryption algorithm: %w", err)
	}

	key, err = e.keyProvider(context.Background())
	if err != nil {
		return nil, nil, 0, nil, fmt.Errorf("unable to resolve encryption key: %w", err)
	}
	err = mech.VerifyKeyUsage(key)
	if err != nil {
		return nil, nil, 0, nil, err
	}
	pub, err = coseKEMPublicKey(key, suite)
	if err != nil {
		return nil, nil, 0, nil, err
	}
	return suite, pub, cekSize, key, nil
}

// -----------------------------------------------------------------------------

// COSE header parameter labels (RFC 9052 section 3.1): alg, kid and iv.
const (
	headerLabelAlg = 1
	headerLabelKid = 4
	headerLabelIV  = 5
)

// encStructure builds the RFC 9052 section 5.3 Enc_structure:
//
//	[ context : tstr, protected : bstr, external_aad : bstr ]
func encStructure(contextText string, protected []byte) ([]byte, error) {
	return cborDeterministicMode.Marshal([]any{contextText, protected, []byte{}})
}

// recipientStructure builds the draft section 3.3.1 Recipient_structure:
//
//	[ "HPKE Recipient", next_layer_alg, recipient_protected,
//	  recipient_extra_info ]
//
// with recipient_extra_info defaulting to the empty byte string. The
// encoding is deterministic (RFC 8949 section 4.2.1).
func recipientStructure(nextLayerAlg int64, recipientProtected, extraInfo []byte) ([]byte, error) {
	if extraInfo == nil {
		extraInfo = []byte{}
	}
	return cborDeterministicMode.Marshal([]any{"HPKE Recipient", nextLayerAlg, recipientProtected, extraInfo})
}
