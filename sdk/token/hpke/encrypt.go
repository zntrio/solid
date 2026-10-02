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
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hpke"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token"
)

// recipientInfoPrefix is the fixed context prefix of the Key Encryption
// mode Recipient_structure used as the HPKE info parameter (draft section
// 6.1): ASCII("JOSE-HPKE rcpt").
var recipientInfoPrefix = []byte("JOSE-HPKE rcpt")

// recipientSeparator is the 0xFF field separator of the
// Recipient_structure.
var recipientSeparator = []byte{0xFF}

// Encrypter returns a token Encrypter producing JWE compact
// serializations with the given HPKE Integrated Encryption algorithm
// (draft-ietf-jose-hpke-encrypt-22, one of HPKE-0..4 and 7).
//
// The resulting JWE carries the HPKE encapsulated secret as its encrypted
// key segment, an empty IV and an empty authentication tag (draft section
// 5); the HPKE aad is the encoded protected header, so the aad argument of
// the Encrypter contract is ignored: Integrated Encryption is already
// bound to the on-the-wire protected header byte sequence.
//
// The recipient key MUST be a public (or private) EC or X25519 OKP JWK
// whose curve matches the algorithm suite, reserved for encryption
// (use=enc).
func Encrypter(alg string, keyProvider jwk.KeyProviderFunc) token.Encrypter {
	return &integratedEncrypter{
		alg:         alg,
		keyProvider: keyProvider,
	}
}

// KeyEncryptionEncrypter returns a Key Encryption mode Encrypter; enc
// selects the content-encryption algorithm (A128GCM or A256GCM, draft
// section 6). The CEK is encrypted to the recipient with HPKE (info =
// Recipient_structure, aad empty), and the token plaintext is encrypted
// with the CEK under the standard JWE content layer.
//
// The recipient key constraints are the same as for Encrypter.
func KeyEncryptionEncrypter(alg, enc string, keyProvider jwk.KeyProviderFunc) token.Encrypter {
	return &keyEncryptionEncrypter{
		alg:         alg,
		enc:         enc,
		keyProvider: keyProvider,
	}
}

// -----------------------------------------------------------------------------

type integratedEncrypter struct {
	alg         string
	keyProvider jwk.KeyProviderFunc
}

// Encrypt encrypts the token with the HPKE Integrated Encryption mode.
func (e *integratedEncrypter) Encrypt(_ context.Context, _, tokenStr string, _ []byte) (string, error) {
	// Check arguments
	if e.keyProvider == nil {
		return "", fmt.Errorf("unable to encrypt with nil key provider")
	}

	// Resolve suite
	s, err := lookupSuite(e.alg)
	if err != nil {
		return "", fmt.Errorf("unable to resolve HPKE algorithm: %w", err)
	}
	if s.KeyEncryption {
		return "", fmt.Errorf("algorithm %q is a Key Encryption suite: use KeyEncryptionEncrypter", e.alg)
	}

	// Resolve recipient public key
	key, err := e.keyProvider(context.Background())
	if err != nil {
		return "", fmt.Errorf("unable to resolve encryption key: %w", err)
	}
	err = verifyKeyUsage(key)
	if err != nil {
		return "", err
	}
	pub, err := kemPublicKey(key, s)
	if err != nil {
		return "", err
	}

	// Build the protected header: the exact emitted bytes are the HPKE aad
	// (draft section 5, the HPKE aad parameter is the Additional
	// Authenticated Data value of section 7.1 step 15, which is the
	// ASCII-encoded protected header segment in the compact serialization).
	header := struct {
		Alg string `json:"alg"`
		Kid string `json:"kid,omitempty"`
	}{
		Alg: s.Label,
	}
	if kid, ok := key.KeyID(); ok && kid != "" {
		header.Kid = kid
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("unable to encode protected header: %w", err)
	}
	protectedSegment := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Encapsulate + seal: single-recipient, single-use context, so the
	// sequence counter starts at zero for both sides.
	encap, sender, err := hpke.NewSender(pub, s.KDF, s.AEAD, nil)
	if err != nil {
		return "", fmt.Errorf("unable to initialize HPKE sender: %w", err)
	}
	ciphertext, err := sender.Seal([]byte(protectedSegment), []byte(tokenStr))
	if err != nil {
		return "", fmt.Errorf("unable to seal token: %w", err)
	}

	// Compact serialization: BASE64URL(header) '.' BASE64URL(encap) '.' '' '.'
	// BASE64URL(ciphertext) '.' '' — empty IV and tag segments (draft
	// section 5).
	var sb strings.Builder
	sb.WriteString(protectedSegment)
	sb.WriteByte('.')
	sb.WriteString(base64.RawURLEncoding.EncodeToString(encap))
	sb.WriteString("..")
	sb.WriteString(base64.RawURLEncoding.EncodeToString(ciphertext))
	sb.WriteByte('.')

	return sb.String(), nil
}

// -----------------------------------------------------------------------------

type keyEncryptionEncrypter struct {
	alg         string
	enc         string
	keyProvider jwk.KeyProviderFunc
}

// Encrypt encrypts the token with the HPKE Key Encryption mode.
func (e *keyEncryptionEncrypter) Encrypt(_ context.Context, _, tokenStr string, _ []byte) (string, error) {
	// Check arguments
	if e.keyProvider == nil {
		return "", fmt.Errorf("unable to encrypt with nil key provider")
	}

	// Resolve suite and content-encryption key size from the enc value.
	s, err := lookupSuite(e.alg)
	if err != nil {
		return "", fmt.Errorf("unable to resolve HPKE algorithm: %w", err)
	}
	if !s.KeyEncryption {
		return "", fmt.Errorf("algorithm %q is an Integrated Encryption suite: use Encrypter", e.alg)
	}
	cekSize, err := cekSizeForEnc(e.enc)
	if err != nil {
		return "", fmt.Errorf("unable to resolve content-encryption algorithm: %w", err)
	}

	// Resolve recipient public key
	key, err := e.keyProvider(context.Background())
	if err != nil {
		return "", fmt.Errorf("unable to resolve encryption key: %w", err)
	}
	err = verifyKeyUsage(key)
	if err != nil {
		return "", err
	}
	pub, err := kemPublicKey(key, s)
	if err != nil {
		return "", err
	}

	// Generate a random CEK (draft section 7.1 step 2) and IV.
	cek := make([]byte, cekSize)
	if _, err = rand.Read(cek); err != nil {
		return "", fmt.Errorf("unable to generate content encryption key: %w", err)
	}
	iv := make([]byte, 12) // AES-GCM standard nonce size
	if _, err = rand.Read(iv); err != nil {
		return "", fmt.Errorf("unable to generate initialization vector: %w", err)
	}

	// Encapsulate the CEK with HPKE: info = Recipient_structure
	// ("JOSE-HPKE rcpt" 0xFF enc 0xFF, empty recipient_extra_info), aad
	// empty (draft section 6).
	encap, sender, err := hpke.NewSender(pub, s.KDF, s.AEAD, recipientStructure(e.enc))
	if err != nil {
		return "", fmt.Errorf("unable to initialize HPKE sender: %w", err)
	}
	encryptedKey, err := sender.Seal(nil, cek)
	if err != nil {
		return "", fmt.Errorf("unable to encrypt content encryption key: %w", err)
	}

	// Build the protected header (ek carries the encapsulated secret).
	protectedSegment, err := encodeKeyEncryptionHeader(s.Label, e.enc, encap, key)
	if err != nil {
		return "", err
	}

	// Content encryption: the JWE AAD is the ASCII-encoded protected header
	// (draft section 7.1 step 15; the compact serialization carries no
	// separate aad member), the AEAD is AES-GCM with the CEK.
	sealed, err := sealContent(cek, e.enc, iv, tokenStr, protectedSegment)
	if err != nil {
		return "", err
	}

	// Compact serialization: BASE64URL(header) '.' BASE64URL(encrypted_key)
	// '.' BASE64URL(iv) '.' BASE64URL(ct) '.' BASE64URL(tag).
	var sb strings.Builder
	sb.WriteString(protectedSegment)
	sb.WriteByte('.')
	sb.WriteString(base64.RawURLEncoding.EncodeToString(encryptedKey))
	sb.WriteByte('.')
	sb.WriteString(base64.RawURLEncoding.EncodeToString(iv))
	sb.WriteByte('.')
	sb.WriteString(base64.RawURLEncoding.EncodeToString(sealed.ct))
	sb.WriteByte('.')
	sb.WriteString(base64.RawURLEncoding.EncodeToString(sealed.tag))

	return sb.String(), nil
}

// keyEncryptionHeader is the protected header of a Key Encryption JWE.
type keyEncryptionHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
	Enc string `json:"enc"`
	EK  string `json:"ek"`
}

// encodeKeyEncryptionHeader builds and base64url-encodes the protected
// header of a Key Encryption JWE.
func encodeKeyEncryptionHeader(alg, enc string, encap []byte, key jwk.Key) (string, error) {
	header := keyEncryptionHeader{
		Alg: alg,
		Enc: enc,
		EK:  base64.RawURLEncoding.EncodeToString(encap),
	}
	if kid, ok := key.KeyID(); ok && kid != "" {
		header.Kid = kid
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("unable to encode protected header: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(headerJSON), nil
}

// sealedContent holds the split ciphertext and tag of the content layer.
type sealedContent struct {
	ct  []byte
	tag []byte
}

// sealContent encrypts the token plaintext with the CEK under the JWE AAD
// (the encoded protected header segment) and splits ciphertext and tag.
func sealContent(cek []byte, enc string, iv []byte, tokenStr, protectedSegment string) (*sealedContent, error) {
	contentAEAD, err := gcmForKey(cek, enc)
	if err != nil {
		return nil, err
	}
	sealed := contentAEAD.Seal(nil, iv, []byte(tokenStr), []byte(protectedSegment))
	overhead := contentAEAD.Overhead()
	return &sealedContent{
		ct:  sealed[:len(sealed)-overhead],
		tag: sealed[len(sealed)-overhead:],
	}, nil
}

// recipientStructure builds the draft section 6.1 Recipient_structure with
// an empty recipient_extra_info:
//
//	ASCII("JOSE-HPKE rcpt") || 0xFF || ASCII(enc) || 0xFF
func recipientStructure(enc string) []byte {
	info := make([]byte, 0, len(recipientInfoPrefix)+1+len(enc)+1)
	info = append(info, recipientInfoPrefix...)
	info = append(info, recipientSeparator...)
	info = append(info, enc...)
	info = append(info, recipientSeparator...)
	return info
}

// gcmForKey returns the AES-GCM AEAD for the given CEK and enc identifier.
func gcmForKey(cek []byte, enc string) (cipher.AEAD, error) {
	switch enc {
	case EncA128GCM, EncA256GCM:
		block, err := aes.NewCipher(cek)
		if err != nil {
			return nil, fmt.Errorf("unable to initialize content encryption: %w", err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("unable to initialize content encryption: %w", err)
		}
		return aead, nil
	default:
		return nil, fmt.Errorf("unsupported content-encryption algorithm %q", enc)
	}
}
