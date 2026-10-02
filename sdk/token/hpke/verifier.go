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
	"crypto/hpke"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	mech "zntr.io/solid/sdk/hpke"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token"
)

// Verifier returns a JWE decrypting verifier for HPKE-encrypted tokens
// (draft-ietf-jose-hpke-encrypt-22, both operating modes). It implements
// token.Verifier: Claims decrypts the JWE, then delegates signature
// verification of the inner serialized token to the provided inner
// verifier (e.g. the JWT verifier of a sign-then-encrypt assembly).
//
// The key set MUST contain the recipient encryption keys (use=enc). The
// token kid header, when present, routes key resolution but is never
// trusted beyond that.
func Verifier(keySetProvider jwk.KeySetProviderFunc, inner token.Verifier) token.Verifier {
	return &hpkeVerifier{
		keySetProvider: keySetProvider,
		inner:          inner,
	}
}

// -----------------------------------------------------------------------------

type hpkeVerifier struct {
	keySetProvider jwk.KeySetProviderFunc
	inner          token.Verifier
}

// parsedJWE holds the decoded compact JWE parts and protected header.
type parsedJWE struct {
	raw        string   // original compact serialization
	segments   []string // the five dot-separated segments
	protected  []byte   // decoded protected header JSON
	alg        string
	kid        string
	enc        string
	ek         []byte // decoded ek header (Key Encryption mode)
	encap      []byte // decoded encrypted key segment
	iv         []byte
	ciphertext []byte
	tag        []byte
}

// Parse decodes the JWE structure and returns a token.Token adapter
// exposing the header-derived values; claims stay unavailable until the
// encrypted content is decrypted and the inner token verified.
func (v *hpkeVerifier) Parse(raw string) (token.Token, error) {
	p, err := parseCompact(raw)
	if err != nil {
		return nil, err
	}
	return &jweToken{
		verifier: v,
		parsed:   p,
	}, nil
}

// Verify decrypts the JWE and verifies the inner token signature.
func (v *hpkeVerifier) Verify(raw string) error {
	_, err := v.decrypt(raw)
	if err != nil {
		return err
	}
	return nil
}

// ContentType returns the outer serialization this verifier parses.
func (v *hpkeVerifier) ContentType() string {
	return contentTypeJWE
}

// Claims decrypts the JWE, then delegates claim extraction and signature
// verification of the inner token to the inner verifier.
func (v *hpkeVerifier) Claims(ctx context.Context, raw string, claims any) error {
	plaintext, err := v.decrypt(raw)
	if err != nil {
		return err
	}
	if v.inner == nil {
		return errors.New("hpke: no inner verifier configured")
	}
	return v.inner.Claims(ctx, string(plaintext), claims)
}

// decrypt resolves the suite, routes the recipient key and decrypts the
// JWE following the fail-closed validation rules; no plaintext is
// emitted on any error.
func (v *hpkeVerifier) decrypt(raw string) ([]byte, error) {
	if v.keySetProvider == nil {
		return nil, errors.New("hpke: nil key set provider")
	}

	// Parse and validate the JWE structure and headers.
	p, err := parseCompact(raw)
	if err != nil {
		return nil, err
	}

	// Resolve suite: parseCompact validated the mode-specific headers.
	s, err := lookupSuite(p.alg)
	if err != nil {
		return nil, err
	}
	if s.KeyEncryption && len(p.ek) == 0 {
		return nil, errors.New("hpke: missing ek header for Key Encryption algorithm")
	}

	// Retrieve key set
	jwks, err := v.keySetProvider(context.Background())
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve key set: %w", err)
	}

	// Resolve candidate encryption keys: kid routing when present and known,
	// every use=enc key otherwise.
	keys := candidateEncryptionKeys(jwks)
	if p.kid != "" {
		if k, found := jwks.LookupKeyID(p.kid); found {
			keys = []jwk.Key{k}
		}
	}

	// Attempt decryption with each candidate key: a tag failure under the
	// wrong key is indistinguishable from tampering, so every candidate is
	// tried before failing.
	var plaintext []byte
	var lastErr error
	for _, k := range keys {
		pt, err := decryptWithKey(k, s, p)
		if err == nil {
			plaintext = pt
			break
		}
		lastErr = err
	}
	if plaintext == nil {
		if lastErr == nil {
			lastErr = errors.New("hpke: no encryption key matched the token")
		}
		return nil, fmt.Errorf("unable to decrypt token: %w", lastErr)
	}
	return plaintext, nil
}

// decryptWithKey decrypts a parsed JWE with a single candidate key.
func decryptWithKey(k jwk.Key, s *mech.Suite, p *parsedJWE) ([]byte, error) {
	priv, err := kemPrivateKey(k, s)
	if err != nil {
		return nil, err
	}

	if s.KeyEncryption {
		return decryptKeyEncryption(priv, s, p)
	}
	return decryptIntegrated(priv, s, p)
}

// decryptIntegrated opens an Integrated Encryption JWE: the HPKE aad is
// the encoded protected header segment, info is empty (Base mode).
func decryptIntegrated(priv hpke.PrivateKey, s *mech.Suite, p *parsedJWE) ([]byte, error) {
	recipient, err := hpke.NewRecipient(p.encap, priv, s.KDF, s.AEAD, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize HPKE recipient: %w", err)
	}
	plaintext, err := recipient.Open([]byte(p.segments[0]), p.ciphertext)
	if err != nil {
		return nil, fmt.Errorf("unable to open token: %w", err)
	}
	return plaintext, nil
}

// decryptKeyEncryption opens a Key Encryption JWE: the CEK is recovered
// with HPKE (info = Recipient_structure, aad empty), the content with the
// enc AEAD under the JWE AAD (the encoded protected header segment).
func decryptKeyEncryption(priv hpke.PrivateKey, s *mech.Suite, p *parsedJWE) ([]byte, error) {
	recipient, err := hpke.NewRecipient(p.ek, priv, s.KDF, s.AEAD, recipientStructure(p.enc))
	if err != nil {
		return nil, fmt.Errorf("unable to initialize HPKE recipient: %w", err)
	}
	cek, err := recipient.Open(nil, p.encap)
	if err != nil {
		return nil, fmt.Errorf("unable to recover content encryption key: %w", err)
	}

	// CEK length must match the enc key size (fail-closed).
	cekSize, err := cekSizeForEnc(p.enc)
	if err != nil {
		return nil, err
	}
	if len(cek) != cekSize {
		return nil, fmt.Errorf("content encryption key length mismatch: expected %d bytes, got %d", cekSize, len(cek))
	}

	contentAEAD, err := gcmForKey(cek, p.enc)
	if err != nil {
		return nil, err
	}
	sealed := make([]byte, 0, len(p.ciphertext)+len(p.tag))
	sealed = append(sealed, p.ciphertext...)
	sealed = append(sealed, p.tag...)
	plaintext, err := contentAEAD.Open(nil, p.iv, sealed, []byte(p.segments[0]))
	if err != nil {
		return nil, fmt.Errorf("unable to open token content: %w", err)
	}
	return plaintext, nil
}

// parseCompact splits and decodes a compact JWE, enforcing the strict
// validation rules: exactly five dot-separated segments, unpadded
// base64url, a valid UTF-8 JSON protected header with no duplicate
// members, a known HPKE alg, and the mode-specific header constraints
// (crit/zip/psk_id rejected, Integrated IV and tag empty).
func parseCompact(raw string) (*parsedJWE, error) {
	segments, err := splitCompact(raw)
	if err != nil {
		return nil, err
	}
	header, err := decodeProtectedHeader(segments)
	if err != nil {
		return nil, err
	}
	encap, iv, ciphertext, tag, err := decodeJWESegments(segments)
	if err != nil {
		return nil, err
	}
	s, err := lookupSuite(header.alg)
	if err != nil {
		return nil, err
	}
	err = checkModeHeaders(s, header, segments, iv, tag)
	if err != nil {
		return nil, err
	}
	var ek []byte
	if header.ek != "" {
		if strings.Contains(header.ek, "=") {
			return nil, errors.New("hpke: ek header contains base64 padding characters")
		}
		ek, err = base64.RawURLEncoding.DecodeString(header.ek)
		if err != nil {
			return nil, fmt.Errorf("hpke: unable to decode ek header: %w", err)
		}
	}
	return &parsedJWE{
		raw:        raw,
		segments:   segments,
		protected:  header.protected,
		alg:        header.alg,
		kid:        header.kid,
		enc:        header.enc,
		ek:         ek,
		encap:      encap,
		iv:         iv,
		ciphertext: ciphertext,
		tag:        tag,
	}, nil
}

// compactHeader is the decoded protected header of a compact JWE.
type compactHeader struct {
	protected []byte
	alg       string
	kid       string
	enc       string
	ek        string
}

// splitCompact splits a compact JWE into its five segments, rejecting
// padded base64url.
func splitCompact(raw string) ([]string, error) {
	segments := strings.Split(raw, ".")
	if len(segments) != 5 {
		return nil, fmt.Errorf("hpke: token is not a 5-segment compact JWE (got %d segments)", len(segments))
	}
	for i, seg := range segments {
		if strings.Contains(seg, "=") {
			return nil, fmt.Errorf("hpke: segment %d contains base64 padding characters", i)
		}
	}
	return segments, nil
}

// decodeProtectedHeader decodes and validates the protected header JSON:
// object shape, no duplicate members, alg present, and the crit/zip/psk_id
// prohibitions of the draft (fail-closed on every unsupported extension).
func decodeProtectedHeader(segments []string) (*compactHeader, error) {
	protected, err := base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		return nil, fmt.Errorf("hpke: unable to decode protected header: %w", err)
	}
	if err := checkNoDuplicateMembers(protected); err != nil {
		return nil, err
	}
	var raw struct {
		Alg   string   `json:"alg"`
		Kid   string   `json:"kid"`
		Enc   string   `json:"enc"`
		EK    string   `json:"ek"`
		Crit  []string `json:"crit"`
		Zip   string   `json:"zip"`
		PskID string   `json:"psk_id"`
	}
	if err := json.Unmarshal(protected, &raw); err != nil {
		return nil, fmt.Errorf("hpke: unable to decode protected header: %w", err)
	}
	if raw.Alg == "" {
		return nil, errors.New("hpke: missing alg header")
	}
	if len(raw.Crit) > 0 {
		return nil, errors.New("hpke: unsupported crit header parameters")
	}
	if raw.Zip != "" {
		return nil, errors.New("hpke: compression (zip) is not supported")
	}
	if raw.PskID != "" {
		return nil, errors.New("hpke: PSK mode (psk_id) is not supported")
	}
	return &compactHeader{
		protected: protected,
		alg:       raw.Alg,
		kid:       raw.Kid,
		enc:       raw.Enc,
		ek:        raw.EK,
	}, nil
}

// decodeJWESegments decodes the encrypted key, IV, ciphertext and tag
// segments.
func decodeJWESegments(segments []string) (encap, iv, ciphertext, tag []byte, err error) {
	encap, err = base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("hpke: unable to decode encrypted key: %w", err)
	}
	iv, err = base64.RawURLEncoding.DecodeString(segments[2])
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("hpke: unable to decode initialization vector: %w", err)
	}
	ciphertext, err = base64.RawURLEncoding.DecodeString(segments[3])
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("hpke: unable to decode ciphertext: %w", err)
	}
	tag, err = base64.RawURLEncoding.DecodeString(segments[4])
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("hpke: unable to decode authentication tag: %w", err)
	}
	return encap, iv, ciphertext, tag, nil
}

// checkModeHeaders enforces the mode-specific header constraints of the
// draft on the decoded parts (Integrated: no enc/ek, empty IV and tag;
// Key Encryption: enc/ek present, enc supported, IV and tag non-empty).
func checkModeHeaders(s *mech.Suite, h *compactHeader, segments []string, iv, tag []byte) error {
	if !s.KeyEncryption {
		if len(iv) > 0 || segments[2] != "" {
			return errors.New("hpke: initialization vector MUST be empty for Integrated Encryption")
		}
		if len(tag) > 0 || segments[4] != "" {
			return errors.New("hpke: authentication tag MUST be empty for Integrated Encryption")
		}
		if h.enc != "" {
			return errors.New("hpke: enc header MUST NOT be present for Integrated Encryption")
		}
		if h.ek != "" {
			return errors.New("hpke: ek header MUST NOT be present for Integrated Encryption")
		}
		return nil
	}
	if h.enc == "" {
		return errors.New("hpke: missing enc header for Key Encryption algorithm")
	}
	if _, err := cekSizeForEnc(h.enc); err != nil {
		return err
	}
	if len(iv) == 0 {
		return errors.New("hpke: initialization vector MUST NOT be empty for Key Encryption")
	}
	if len(tag) == 0 {
		return errors.New("hpke: authentication tag MUST NOT be empty for Key Encryption")
	}
	return nil
}

// checkNoDuplicateMembers rejects protected headers carrying duplicated
// JSON member names (RFC 7516 section 4.1.2 / RFC 8725 section 3.3).
func checkNoDuplicateMembers(headerJSON []byte) error {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(headerJSON, &probe); err != nil {
		return fmt.Errorf("hpke: protected header is not a JSON object: %w", err)
	}
	// Re-marshal the member names and compare counts with a duplicate-aware
	// decode: json.Decoder with UseNumber does not flag duplicates either,
	// so walk the raw tokens.
	dec := json.NewDecoder(strings.NewReader(string(headerJSON)))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return errors.New("hpke: protected header is not a JSON object")
	}
	seen := map[string]struct{}{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("hpke: unable to decode protected header: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return errors.New("hpke: invalid protected header member name")
		}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("hpke: duplicated protected header member %q", key)
		}
		seen[key] = struct{}{}
		// Skip the member value.
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return fmt.Errorf("hpke: unable to decode protected header: %w", err)
		}
	}
	return nil
}

// candidateEncryptionKeys returns every encryption (use=enc) key of the
// set.
func candidateEncryptionKeys(jwks jwk.Set) []jwk.Key {
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

// -----------------------------------------------------------------------------

// jweToken adapts a parsed JWE to the token.Token contract. Claims-bearing
// methods require decryption and inner verification; anything exposing
// attacker-controlled values without authentication fails closed.
type jweToken struct {
	verifier *hpkeVerifier
	parsed   *parsedJWE
}

// Algorithm returns the JWE alg header value.
func (t *jweToken) Algorithm() (string, error) {
	return t.parsed.alg, nil
}

// Type reads the inner token typ header after decryption and inner
// verification.
func (t *jweToken) Type() (string, error) {
	plaintext, err := t.verifier.decrypt(t.parsed.raw)
	if err != nil {
		return "", err
	}
	inner, err := t.verifier.inner.Parse(string(plaintext))
	if err != nil {
		return "", err
	}
	return inner.Type()
}

// KeyID returns the JWE kid header value.
func (t *jweToken) KeyID() (string, error) {
	return t.parsed.kid, nil
}

// PublicKey is not supported: content-encryption keys are not signature
// keys.
func (t *jweToken) PublicKey() (any, error) {
	return nil, errors.New("hpke: public key is not supported by the HPKE verifier")
}

// PublicKeyThumbPrint is not supported: content-encryption keys are not
// signature keys.
func (t *jweToken) PublicKeyThumbPrint() (string, error) {
	return "", errors.New("hpke: public key thumbprint is not supported by the HPKE verifier")
}

// Claims decrypts the JWE and delegates the verified claim extraction to
// the inner verifier.
func (t *jweToken) Claims(_, claims any) error {
	plaintext, err := t.verifier.decrypt(t.parsed.raw)
	if err != nil {
		return err
	}
	return t.verifier.inner.Claims(context.Background(), string(plaintext), claims)
}

// UnverifiedClaims fails closed: the encrypted payload is
// attacker-controlled until decrypted and the inner token verified.
func (t *jweToken) UnverifiedClaims(_ any) error {
	return errors.New("hpke: unverified claims are not available for encrypted tokens")
}
