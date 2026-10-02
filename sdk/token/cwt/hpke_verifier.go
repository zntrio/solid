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
	chpke "crypto/hpke"
	"errors"
	"fmt"
	"math"

	cbor "github.com/fxamacker/cbor/v2"

	mech "zntr.io/solid/sdk/hpke"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token"
)

// CoseHPKEVerifier returns a COSE-HPKE decrypting verifier for CWTs
// (draft-ietf-cose-hpke-27, both operating modes). It implements
// token.Verifier: Claims decrypts the COSE_Encrypt0 / COSE_Encrypt
// object, then delegates signature verification of the inner serialized
// token to the provided inner verifier (e.g. the COSE_Sign1 CWT verifier
// of a sign-then-encrypt assembly).
//
// The key set MUST contain the recipient encryption keys (use=enc). The
// token kid header, when present, routes key resolution but is never
// trusted beyond that.
func CoseHPKEVerifier(keySetProvider jwk.KeySetProviderFunc, inner token.Verifier) token.Verifier {
	return &coseHPKEVerifier{
		keySetProvider: keySetProvider,
		inner:          inner,
	}
}

// -----------------------------------------------------------------------------

type coseHPKEVerifier struct {
	keySetProvider jwk.KeySetProviderFunc
	inner          token.Verifier
}

// coseEncrypt0 is a decoded COSE_Encrypt0 (tag 16):
// [ protected : bstr, unprotected : map, ciphertext : bstr ].
type coseEncrypt0 struct {
	Protected   []byte
	Unprotected map[int64]any
	Ciphertext  []byte
}

// coseRecipient is a decoded COSE_Recipient.
type coseRecipient struct {
	Protected   []byte
	Unprotected map[int64]any
	Ciphertext  []byte
}

// coseEncrypt is a decoded COSE_Encrypt (tag 96): [ protected : bstr,
// unprotected : map, ciphertext : bstr, recipients : [COSE_Recipient] ].
type coseEncrypt struct {
	Protected   []byte
	Unprotected map[int64]any
	Ciphertext  []byte
	Recipients  []coseRecipient
}

// coseDecoded is the mode-normalized view of a decoded COSE-HPKE token.
type coseDecoded struct {
	raw            string // original base64url wire form
	encrypt0       *coseEncrypt0
	encrypt        *coseEncrypt
	alg            int64  // COSE-HPKE suite alg (Encrypt0 or Recipient layer)
	ek             []byte // HPKE encapsulated key
	protectedBytes []byte // protected header bytes of the encrypting layer
	iv             []byte // content layer IV (Key Encryption mode)
}

// Parse decodes the COSE-HPKE token structure and returns a token.Token
// adapter exposing the header-derived values; claims stay unavailable
// until the ciphertext is decrypted and the inner token verified.
func (v *coseHPKEVerifier) Parse(raw string) (token.Token, error) {
	decoded, err := v.decode(raw)
	if err != nil {
		return nil, err
	}
	return &coseHPKEToken{
		verifier: v,
		decoded:  decoded,
	}, nil
}

// Verify decrypts the COSE-HPKE token.
func (v *coseHPKEVerifier) Verify(raw string) error {
	_, err := v.decrypt(raw)
	return err
}

// ContentType returns the outer serialization this verifier parses.
func (v *coseHPKEVerifier) ContentType() string {
	return "COSE_Encrypt"
}

// Claims decrypts the COSE-HPKE token, then delegates claim extraction and
// signature verification of the inner token to the inner verifier.
func (v *coseHPKEVerifier) Claims(ctx context.Context, raw string, claims any) error {
	plaintext, err := v.decrypt(raw)
	if err != nil {
		return err
	}
	if v.inner == nil {
		return errors.New("cwt/hpke: no inner verifier configured")
	}
	return v.inner.Claims(ctx, string(plaintext), claims)
}

// decode parses the base64url wire form into a COSE_Encrypt0 or
// COSE_Encrypt and applies the draft's structural validation.
func (v *coseHPKEVerifier) decode(raw string) (*coseDecoded, error) {
	if v.keySetProvider == nil {
		return nil, errors.New("cwt/hpke: nil key set provider")
	}

	data, err := decodeBase64(raw)
	if err != nil {
		return nil, errors.New("cwt/hpke: unable to decode token")
	}

	var tag cbor.Tag
	err = cborDeterministicDecode.Unmarshal(data, &tag)
	if err != nil {
		return nil, fmt.Errorf("cwt/hpke: unable to decode token: %w", err)
	}

	var decoded *coseDecoded
	switch tag.Number {
	case cborTagEncrypt0:
		decoded, err = decodeCoseEncrypt0(tag.Content)
	case cborTagEncrypt:
		decoded, err = decodeCoseEncrypt(tag.Content)
	default:
		return nil, fmt.Errorf("cwt/hpke: unexpected CBOR tag %d: expected COSE_Encrypt0 (16) or COSE_Encrypt (96)", tag.Number)
	}
	if err != nil {
		return nil, err
	}
	decoded.raw = raw
	return decoded, nil
}

// decodeCoseEncrypt0 decodes and validates a COSE_Encrypt0 content
// (draft section 3.2): protected alg, ek in the unprotected bucket,
// psk_id rejected (Base mode only).
func decodeCoseEncrypt0(content any) (*coseDecoded, error) {
	fields, err := decodeCoseArray(content, 3, "COSE_Encrypt0")
	if err != nil {
		return nil, err
	}
	protected, okP := fields[0].([]byte)
	unprotected, okU := asHeaderMap(fields[1])
	ciphertext, okC := fields[2].([]byte)
	if !okP || !okU || !okC {
		return nil, errors.New("cwt/hpke: malformed COSE_Encrypt0 fields")
	}

	alg, err := protectedAlg(protected)
	if err != nil {
		return nil, err
	}
	err = rejectPskID(protected)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 {
		return nil, errors.New("cwt/hpke: empty ciphertext")
	}
	ek, err := unprotectedEK(unprotected)
	if err != nil {
		return nil, err
	}

	return &coseDecoded{
		encrypt0: &coseEncrypt0{
			Protected:   protected,
			Unprotected: unprotected,
			Ciphertext:  ciphertext,
		},
		alg:            alg,
		ek:             ek,
		protectedBytes: protected,
	}, nil
}

// decodeCoseEncrypt decodes and validates a COSE_Encrypt content (draft
// section 3.3): layer-0 AEAD alg with IV, exactly one COSE_Recipient whose
// protected alg is the COSE-HPKE suite with ek in its unprotected bucket.
func decodeCoseEncrypt(content any) (*coseDecoded, error) {
	fields, err := decodeCoseArray(content, 4, "COSE_Encrypt")
	if err != nil {
		return nil, err
	}
	protected, okP := fields[0].([]byte)
	unprotected, okU := asHeaderMap(fields[1])
	ciphertext, okC := fields[2].([]byte)
	if !okP || !okU || !okC {
		return nil, errors.New("cwt/hpke: malformed COSE_Encrypt fields")
	}

	// Layer 0 validation: alg is the AEAD, IV present, ciphertext
	// non-empty, psk_id rejected.
	contentLayer, err := validateCoseContentLayer(protected, unprotected, ciphertext)
	if err != nil {
		return nil, err
	}

	// Recipient layer: exactly one COSE_Recipient, protected alg is the
	// COSE-HPKE suite with ek in its unprotected bucket.
	recipient, rAlg, ek, err := decodeCoseRecipient(fields[3])
	if err != nil {
		return nil, err
	}

	return &coseDecoded{
		encrypt: &coseEncrypt{
			Protected:   protected,
			Unprotected: unprotected,
			Ciphertext:  ciphertext,
			Recipients:  []coseRecipient{*recipient},
		},
		alg:            rAlg,
		ek:             ek,
		protectedBytes: recipient.Protected,
		iv:             contentLayer.iv,
	}, nil
}

// coseContentLayer carries the validated layer-0 properties.
type coseContentLayer struct {
	iv []byte
}

// validateCoseContentLayer validates the layer-0 header of a
// COSE_Encrypt: the AEAD alg resolves, the IV is present, the ciphertext
// is non-empty and no psk_id header is present.
func validateCoseContentLayer(protected []byte, unprotected map[int64]any, ciphertext []byte) (*coseContentLayer, error) {
	contentAlg, err := protectedAlg(protected)
	if err != nil {
		return nil, err
	}
	err = rejectPskID(protected)
	if err != nil {
		return nil, err
	}
	if _, err = coseCekSizeForEnc(contentAlg); err != nil {
		return nil, err
	}
	iv, err := unprotectedIV(unprotected)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 {
		return nil, errors.New("cwt/hpke: empty ciphertext")
	}
	return &coseContentLayer{iv: iv}, nil
}

// decodeCoseRecipient decodes and validates the single COSE_Recipient of
// a COSE_Encrypt: protected alg (the COSE-HPKE suite), ek in the
// unprotected bucket, psk_id rejected.
func decodeCoseRecipient(content any) (recipient *coseRecipient, alg int64, ek []byte, err error) {
	recipientArray, okR := content.([]any)
	if !okR || len(recipientArray) != 1 {
		// The token strategy is single-recipient: the Encrypter never
		// emits multi-recipient structures.
		return nil, 0, nil, errors.New("cwt/hpke: expected exactly one COSE_Recipient")
	}
	rFields, err := decodeCoseArray(recipientArray[0], 3, "COSE_Recipient")
	if err != nil {
		return nil, 0, nil, err
	}
	rProtected, okRP := rFields[0].([]byte)
	rUnprotected, okRU := asHeaderMap(rFields[1])
	rCiphertext, okRC := rFields[2].([]byte)
	if !okRP || !okRU || !okRC {
		return nil, 0, nil, errors.New("cwt/hpke: malformed COSE_Recipient fields")
	}

	err = rejectPskID(rProtected)
	if err != nil {
		return nil, 0, nil, err
	}
	alg, err = protectedAlg(rProtected)
	if err != nil {
		return nil, 0, nil, err
	}
	ek, err = unprotectedEK(rUnprotected)
	if err != nil {
		return nil, 0, nil, err
	}

	return &coseRecipient{
		Protected:   rProtected,
		Unprotected: rUnprotected,
		Ciphertext:  rCiphertext,
	}, alg, ek, nil
}

// decodeCoseArray decodes a CBOR fragment into a fixed-size array of
// length n, validating the shape.
func decodeCoseArray(content any, n int, what string) ([]any, error) {
	data, err := cborDeterministicMode.Marshal(content)
	if err != nil {
		return nil, fmt.Errorf("cwt/hpke: malformed %s: %w", what, err)
	}
	arr := make([]any, 0, n)
	if err := cborDeterministicDecode.Unmarshal(data, &arr); err != nil {
		return nil, fmt.Errorf("cwt/hpke: malformed %s: %w", what, err)
	}
	if len(arr) != n {
		return nil, fmt.Errorf("cwt/hpke: malformed %s: expected %d fields, got %d", what, n, len(arr))
	}
	return arr, nil
}

// decrypt resolves the suite, routes the recipient key and decrypts the
// token; no plaintext is emitted on any error.
func (v *coseHPKEVerifier) decrypt(raw string) ([]byte, error) {
	decoded, err := v.decode(raw)
	if err != nil {
		return nil, err
	}

	suite, err := lookupCoseSuite(decoded.alg)
	if err != nil {
		return nil, err
	}

	// Retrieve key set
	jwks, err := v.keySetProvider(context.Background())
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve key set: %w", err)
	}

	// Resolve candidate encryption keys: kid routing when present and
	// known, every use=enc key otherwise.
	keys := coseCandidateEncryptionKeys(jwks)
	if kid := decodedKid(decoded); kid != "" {
		if k, found := jwks.LookupKeyID(kid); found {
			keys = []jwk.Key{k}
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("cwt/hpke: no encryption key matched the token")
	}

	// Attempt decryption with each candidate key.
	var plaintext []byte
	var lastErr error
	for _, k := range keys {
		pt, errKey := decryptCoseWithKey(k, suite, decoded)
		if errKey == nil {
			plaintext = pt
			break
		}
		lastErr = errKey
	}
	if plaintext == nil {
		if lastErr == nil {
			lastErr = errors.New("cwt/hpke: no encryption key matched the token")
		}
		return nil, fmt.Errorf("unable to decrypt token: %w", lastErr)
	}
	return plaintext, nil
}

// decryptCoseWithKey decrypts a decoded token with a single candidate key.
func decryptCoseWithKey(k jwk.Key, suite *mech.Suite, d *coseDecoded) ([]byte, error) {
	priv, err := coseKEMPrivateKey(k, suite)
	if err != nil {
		return nil, err
	}

	if suite.KeyEncryption {
		return coseDecryptKeyEncryption(priv, suite, d)
	}
	return coseDecryptIntegrated(priv, suite, d)
}

// coseDecryptIntegrated opens a COSE_Encrypt0: the HPKE aad is the
// Enc_structure("Encrypt0", protected, "") of RFC 9052 section 5.3.
func coseDecryptIntegrated(priv chpke.PrivateKey, suite *mech.Suite, d *coseDecoded) ([]byte, error) {
	aad, err := encStructure("Encrypt0", d.protectedBytes)
	if err != nil {
		return nil, err
	}
	recipient, err := chpke.NewRecipient(d.ek, priv, suite.KDF, suite.AEAD, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize HPKE recipient: %w", err)
	}
	plaintext, err := recipient.Open(aad, d.encrypt0.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("unable to open token: %w", err)
	}
	return plaintext, nil
}

// coseDecryptKeyEncryption opens a COSE_Encrypt: the CEK is recovered from
// the COSE_Recipient with HPKE (info = Recipient_structure, aad empty),
// the content with the layer-0 AEAD under the Enc_structure("Encrypt").
func coseDecryptKeyEncryption(priv chpke.PrivateKey, suite *mech.Suite, d *coseDecoded) ([]byte, error) {
	contentAlg, err := protectedAlg(d.encrypt.Protected)
	if err != nil {
		return nil, err
	}
	r := d.encrypt.Recipients[0]

	// HPKE Open of the CEK: info = Recipient_structure with the
	// next-layer (content) alg and the recipient protected header bytes.
	info, err := recipientStructure(contentAlg, r.Protected, nil)
	if err != nil {
		return nil, err
	}
	recipient, err := chpke.NewRecipient(d.ek, priv, suite.KDF, suite.AEAD, info)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize HPKE recipient: %w", err)
	}
	cek, err := recipient.Open(nil, r.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("unable to recover content encryption key: %w", err)
	}

	// CEK length must match the content-encryption key size (fail-closed).
	cekSize, err := coseCekSizeForEnc(contentAlg)
	if err != nil {
		return nil, err
	}
	if len(cek) != cekSize {
		return nil, fmt.Errorf("content encryption key length mismatch: expected %d bytes, got %d", cekSize, len(cek))
	}

	// Content AEAD: key CEK, nonce IV, aad Enc_structure("Encrypt").
	aad, err := encStructure("Encrypt", d.encrypt.Protected)
	if err != nil {
		return nil, err
	}
	contentAEAD, err := coseGcmForKey(cek, contentAlg, len(d.iv))
	if err != nil {
		return nil, err
	}
	plaintext, err := contentAEAD.Open(nil, d.iv, d.encrypt.Ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("unable to open token content: %w", err)
	}
	return plaintext, nil
}

// -----------------------------------------------------------------------------

// coseHPKEToken adapts a decoded COSE-HPKE token to the token.Token
// contract. Claims-bearing methods require decryption and inner
// verification; anything exposing attacker-controlled values without
// authentication fails closed.
type coseHPKEToken struct {
	verifier *coseHPKEVerifier
	decoded  *coseDecoded
}

// Algorithm returns the COSE-HPKE algorithm identifier as its JWE-registry
// label for cross-strategy readability.
func (t *coseHPKEToken) Algorithm() (string, error) {
	s, err := lookupCoseSuite(t.decoded.alg)
	if err != nil {
		return "", err
	}
	return s.Label, nil
}

// Type reads the inner token typ header after decryption and inner
// verification.
func (t *coseHPKEToken) Type() (string, error) {
	plaintext, err := t.verifier.decrypt(t.decoded.raw)
	if err != nil {
		return "", err
	}
	inner, err := t.verifier.inner.Parse(string(plaintext))
	if err != nil {
		return "", err
	}
	return inner.Type()
}

// KeyID returns the recipient kid header value, when present.
func (t *coseHPKEToken) KeyID() (string, error) {
	return decodedKid(t.decoded), nil
}

// PublicKey is not supported: content-encryption keys are not signature
// keys.
func (t *coseHPKEToken) PublicKey() (any, error) {
	return nil, errors.New("cwt/hpke: public key is not supported by the COSE-HPKE verifier")
}

// PublicKeyThumbPrint is not supported: content-encryption keys are not
// signature keys.
func (t *coseHPKEToken) PublicKeyThumbPrint() (string, error) {
	return "", errors.New("cwt/hpke: public key thumbprint is not supported by the COSE-HPKE verifier")
}

// asHeaderMap converts a decoded CBOR value into a header map with int64
// labels, rejecting non-map values. The CBOR decoder yields
// map[any]any with mixed integer key types (uint64 for positive labels,
// int64 for negative ones): both are normalized to int64.
func asHeaderMap(v any) (map[int64]any, bool) {
	switch m := v.(type) {
	case map[int64]any:
		return m, true
	case map[any]any:
		normalized := make(map[int64]any, len(m))
		for k, val := range m {
			label, ok := asInt64(k)
			if !ok {
				return nil, false
			}
			normalized[label] = val
		}
		return normalized, true
	default:
		return nil, false
	}
}

// Claims decrypts the token and delegates the verified claim extraction
// to the inner verifier.
func (t *coseHPKEToken) Claims(_, claims any) error {
	plaintext, err := t.verifier.decrypt(t.decoded.raw)
	if err != nil {
		return err
	}
	return t.verifier.inner.Claims(context.Background(), string(plaintext), claims)
}

// UnverifiedClaims fails closed: the encrypted payload is
// attacker-controlled until decrypted and the inner token verified.
func (t *coseHPKEToken) UnverifiedClaims(_ any) error {
	return errors.New("cwt/hpke: unverified claims are not available for encrypted tokens")
}

// -----------------------------------------------------------------------------

// coseCandidateEncryptionKeys returns every encryption (use=enc) key of
// the set.
func coseCandidateEncryptionKeys(jwks jwk.Set) []jwk.Key {
	var keys []jwk.Key
	for i := range jwks.Len() {
		k, ok := jwks.Key(i)
		if !ok {
			continue
		}
		if use, hasUse := k.KeyUsage(); hasUse && use != "enc" {
			continue
		}
		keys = append(keys, k)
	}
	return keys
}

// decodedKid reads the kid (bstr) from the protected header, falling back
// to the unprotected one.
func decodedKid(d *coseDecoded) string {
	var protected map[int64]any
	var unprotected map[int64]any
	switch {
	case d.encrypt0 != nil:
		protected = mustDecodeProtected(d.encrypt0.Protected)
		unprotected = d.encrypt0.Unprotected
	case d.encrypt != nil && len(d.encrypt.Recipients) > 0:
		protected = mustDecodeProtected(d.encrypt.Recipients[0].Protected)
		unprotected = d.encrypt.Recipients[0].Unprotected
	default:
		return ""
	}
	if v, ok := protected[headerLabelKid]; ok {
		if b, isBstr := v.([]byte); isBstr {
			return string(b)
		}
	}
	if v, ok := unprotected[headerLabelKid]; ok {
		if b, isBstr := v.([]byte); isBstr {
			return string(b)
		}
	}
	return ""
}

// mustDecodeProtected decodes protected header bytes into a label map.
func mustDecodeProtected(data []byte) map[int64]any {
	var h map[int64]any
	if err := cborDeterministicDecode.Unmarshal(data, &h); err != nil {
		return map[int64]any{}
	}
	return h
}

// protectedAlg extracts the alg header parameter from a protected header.
func protectedAlg(protected []byte) (int64, error) {
	h := mustDecodeProtectedOrErr(protected)
	v, ok := h[headerLabelAlg]
	if !ok {
		return 0, errors.New("cwt/hpke: missing alg header")
	}
	alg, isInt := asInt64(v)
	if !isInt {
		return 0, errors.New("cwt/hpke: alg header must be an integer")
	}
	return alg, nil
}

// mustDecodeProtectedOrErr decodes protected header bytes into a label
// map, propagating decode errors.
func mustDecodeProtectedOrErr(protected []byte) map[int64]any {
	var h map[int64]any
	if err := cborDeterministicDecode.Unmarshal(protected, &h); err != nil {
		return map[int64]any{}
	}
	return h
}

// rejectPskID enforces the mode_base-only posture: the presence of the
// protected psk_id header selects HPKE mode_psk, unsupported here.
func rejectPskID(protected []byte) error {
	var h map[int64]any
	if err := cborDeterministicDecode.Unmarshal(protected, &h); err != nil {
		return fmt.Errorf("cwt/hpke: unable to decode protected header: %w", err)
	}
	if _, ok := h[headerLabelPSKID]; ok {
		return errors.New("cwt/hpke: PSK mode (psk_id) is not supported")
	}
	return nil
}

// unprotectedEK extracts the ek (bstr) header parameter.
func unprotectedEK(unprotected map[int64]any) ([]byte, error) {
	v, ok := unprotected[headerLabelEK]
	if !ok {
		return nil, errors.New("cwt/hpke: missing ek header")
	}
	ek, isBstr := v.([]byte)
	if !isBstr || len(ek) == 0 {
		return nil, errors.New("cwt/hpke: ek header must be a non-empty byte string")
	}
	return ek, nil
}

// unprotectedIV extracts the iv (bstr) header parameter.
func unprotectedIV(unprotected map[int64]any) ([]byte, error) {
	v, ok := unprotected[headerLabelIV]
	if !ok {
		return nil, errors.New("cwt/hpke: missing iv header")
	}
	iv, isBstr := v.([]byte)
	if !isBstr || len(iv) == 0 {
		return nil, errors.New("cwt/hpke: iv header must be a non-empty byte string")
	}
	return iv, nil
}

// asInt64 converts a decoded CBOR integer into an int64.
func asInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case uint64:
		if n > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	case int:
		return int64(n), true
	case uint:
		if n > math.MaxUint64>>1 {
			return 0, false
		}
		return int64(n), true
	default:
		return 0, false
	}
}
