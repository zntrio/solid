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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	cbor "github.com/fxamacker/cbor/v2"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"

	"zntr.io/solid/sdk/hpke"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token"
)

// noopCoseVerifier accepts any inner token: draft vector plaintexts are
// arbitrary octet sequences, not COSE_Sign1 structures.
type noopCoseVerifier struct{}

func (noopCoseVerifier) Parse(raw string) (token.Token, error) { return nil, assert.AnError }
func (noopCoseVerifier) Verify(raw string) error               { return nil }
func (noopCoseVerifier) Claims(_ context.Context, _ string, _ any) error {
	return nil
}
func (noopCoseVerifier) ContentType() string { return "NOOP" }

// coseTestKeys generates an ES256 COSE signing key pair and an HPKE
// recipient key pair for the given suite curve, exported as JWKs.
type coseTestKeys struct {
	signingPrivate jwk.Key
	signingPublic  jwk.Set
	encPrivate     jwk.Key
	encSet         jwk.Set
}

func newCoseTestKeys(t *testing.T, alg int64) *coseTestKeys {
	t.Helper()
	s, err := lookupCoseSuite(alg)
	require.NoError(t, err, "suite must resolve")
	// lookupCoseSuite returns the full suite (primitives + curve).
	suite := s

	// ES256 signing key (COSE_Sign1 inner signature).
	signEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signingPrivate, err := jwxjwk.Import(signEC)
	require.NoError(t, err)
	require.NoError(t, signingPrivate.Set(jwk.KeyIDKey, "test-signing-key"))
	signingPub, err := signingPrivate.PublicKey()
	require.NoError(t, err)
	signingSet := jwk.NewSet()
	require.NoError(t, signingSet.AddKey(signingPub))

	// HPKE recipient key on the suite curve: generate the ecdh key
	// directly (jwx imports ecdh keys, not crypto/hpke ones).
	ecdhPriv, err := suite.Curve.GenerateKey(rand.Reader)
	require.NoError(t, err, "unable to generate encryption key")
	encPrivate, err := jwxjwk.Import(ecdhPriv)
	require.NoError(t, err)
	require.NoError(t, encPrivate.Set(jwk.KeyIDKey, "test-encryption-key"))
	require.NoError(t, encPrivate.Set(jwk.KeyUsageKey, "enc"))
	encSet := jwk.NewSet()
	require.NoError(t, encSet.AddKey(encPrivate))

	return &coseTestKeys{
		signingPrivate: signingPrivate,
		signingPublic:  signingSet,
		encPrivate:     encPrivate,
		encSet:         encSet,
	}
}

// signThenEncryptCose assembles the sign-then-encrypt stack: the inner
// COSE_Sign1 CWT is produced by the cwt signer, then COSE-HPKE encrypted.
func signThenEncryptCose(t *testing.T, keys *coseTestKeys, alg, contentAlg int64, claims any) string {
	t.Helper()

	signer := AccessTokenSigner(cose.AlgorithmES256, func(context.Context) (jwk.Key, error) {
		return keys.signingPrivate, nil
	})
	signed, err := signer.Serialize(context.Background(), claims)
	require.NoError(t, err, "unable to sign inner CWT")

	var encrypter token.Encrypter
	if s, errSuite := lookupCoseSuite(alg); errSuite == nil && s.KeyEncryption {
		encrypter = CoseHPKEKeyEncryptionEncrypter(alg, contentAlg, func(context.Context) (jwk.Key, error) {
			return keys.encPrivate, nil
		})
	} else {
		encrypter = CoseHPKEEncrypter(alg, func(context.Context) (jwk.Key, error) {
			return keys.encPrivate, nil
		})
	}
	encrypted, err := encrypter.Encrypt(context.Background(), "CWT", signed, nil)
	require.NoError(t, err, "unable to encrypt signed CWT")
	return encrypted
}

// innerCoseVerifier is the COSE_Sign1 verifier for the inner signature.
func innerCoseVerifier(keys *coseTestKeys) token.Verifier {
	return DefaultVerifier(func(context.Context) (jwk.Set, error) {
		return keys.signingPublic, nil
	}, []cose.Algorithm{cose.AlgorithmES256})
}

// es256Cose is the COSE ES256 algorithm identifier (RFC 9053: -7).

// TestCoseHPKEDraftVectorIntegrated decrypts the draft-ietf-cose-hpke-27
// section 5.1 Figure 2 COSE_Encrypt0 example with its Figure 4 COSE key:
// a successful open proves the Enc_structure aad binding and the ek
// routing match the draft.
func TestCoseHPKEDraftVectorIntegrated(t *testing.T) {
	const vectorHex = "d08344a1011823a20443626f622358410457229bdd99407b384a9e59fa15" +
		"53224d58b106e9ebebdaa06d2126bd96757674847669966ecb0dcdf21af5" +
		"623f19f0b799b0cddf3ee930b739dd474f6282de0158253f3c1595e9d252" +
		"e816215a9ce73f47ba4b57acb06ecc39ca5a03a14108bbe7807af5688d61"

	// Figure 4 COSE key (EC2 P-256, HPKE-0), expressed as a JWK.
	const vectorJWK = `{"kty":"EC","crv":"P-256","kid":"bob",` +
		`"x":"AqjjMV-WvHNV2_hXQMbY5T-wcM2LpcQZvkmpHXie9Vw",` +
		`"y":"lrZiGr9cpTLgQtxcNGwe8MkYa4PLEi5QpG8UWN4CPTU",` +
		`"d":"7KOTABR8kaKmXRfgDqJ4tXoUF4JFv1aG2aQEzKGBa44"}`

	key, err := jwxjwk.ParseKey([]byte(vectorJWK))
	require.NoError(t, err, "vector JWK must parse")
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(key))

	verifier := CoseHPKEVerifier(func(context.Context) (jwk.Set, error) {
		return set, nil
	}, noopCoseVerifier{})

	// The vector is raw CBOR hex; wrap it in the base64url wire form.
	raw, err := hex.DecodeString(vectorHex)
	require.NoError(t, err)
	wire := encodeBase64(raw)

	require.NoError(t, verifier.Verify(wire), "draft vector must decrypt")

	parsed, err := verifier.Parse(wire)
	require.NoError(t, err)
	alg, err := parsed.Algorithm()
	require.NoError(t, err)
	assert.Equal(t, hpke.HPKE0, alg, "vector alg must resolve to HPKE-0")
	kid, err := parsed.KeyID()
	require.NoError(t, err)
	assert.Equal(t, "bob", kid, "vector kid must be bob")
}

// TestCoseHPKEDraftVectorKeyEncryption decrypts the draft section 5.2
// COSE_Encrypt example (HPKE-0-KE, A128GCM content) with its COSE key:
// a successful open proves the Recipient_structure info binding and the
// two-layer decryption match the draft.
func TestCoseHPKEDraftVectorKeyEncryption(t *testing.T) {
	const vectorHex = "d8608443a10101a1055089115f10ecc1c7fd834442cb87929bc15825534d" +
		"b92f5366e3cadd096774a9576bb8d8867e75ea38c329ecfc7b8793c5a4ae" +
		"9603e5b0b6818349a201182e0443626f62a12358410417cd85837981ddb1" +
		"4963061ab5fb7308988eb922f87cf6cf6ef83556f7657922c9815947e41b" +
		"9bc932e48c6f1c4677d9a5506a30d694587628b5193a4cde2f3f58204b50" +
		"8a340e463c317f4e62fb8d08c887cac4788087ad022562d05855a50ca4a0"

	const vectorJWK = `{"kty":"EC","crv":"P-256","kid":"bob",` +
		`"x":"2DKRZ3hZjqYgOvl0yXtFlwrAJm_Go7fyE7qfi1kbkpc",` +
		`"y":"jZQQWZqOg9AOtG1ns01NrI-9S4sfCIZFmWWc7p7wkYQ",` +
		`"d":"sRYsVo78upHI5OgvZuNrRaoQvFUijPZezTuynPsJ-Yk"}`

	key, err := jwxjwk.ParseKey([]byte(vectorJWK))
	require.NoError(t, err, "vector JWK must parse")
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(key))

	verifier := CoseHPKEVerifier(func(context.Context) (jwk.Set, error) {
		return set, nil
	}, noopCoseVerifier{})

	raw, err := hex.DecodeString(vectorHex)
	require.NoError(t, err)
	wire := encodeBase64(raw)

	require.NoError(t, verifier.Verify(wire), "draft vector must decrypt")

	parsed, err := verifier.Parse(wire)
	require.NoError(t, err)
	alg, err := parsed.Algorithm()
	require.NoError(t, err)
	assert.Equal(t, hpke.HPKE0KE, alg, "vector alg must resolve to HPKE-0-KE")
}

// TestCoseHPKERoundTripAllSuites signs an inner CWT (COSE_Sign1, ES256),
// encrypts it with every supported COSE-HPKE suite, and recovers the
// verified claims — proving the full sign-then-encrypt assembly for both
// operating modes and both content AEADs.
func TestCoseHPKERoundTripAllSuites(t *testing.T) {
	claims := map[string]any{
		"iss":       "https://issuer.example.org",
		"sub":       "subject-reference",
		"client_id": "confidential-client",
		"scope":     "openid profile",
	}

	for _, tc := range []struct {
		alg        int64
		contentAlg int64
	}{
		{AlgHPKE0, 0},
		{AlgHPKE1, 0},
		{AlgHPKE2, 0},
		{AlgHPKE3, 0},
		{AlgHPKE4, 0},
		{AlgHPKE7, 0},
		{AlgHPKE0KE, CoseAlgA128GCM},
		{AlgHPKE0KE, CoseAlgA256GCM},
		{AlgHPKE1KE, CoseAlgA256GCM},
		{AlgHPKE2KE, CoseAlgA256GCM},
		{AlgHPKE3KE, CoseAlgA128GCM},
		{AlgHPKE7KE, CoseAlgA256GCM},
	} {
		name := joseLabelOfCoseAlg(tc.alg)
		if tc.contentAlg != 0 {
			name += "/" + map[int64]string{CoseAlgA128GCM: "A128GCM", CoseAlgA256GCM: "A256GCM"}[tc.contentAlg]
		}
		t.Run(name, func(t *testing.T) {
			keys := newCoseTestKeys(t, tc.alg)

			encrypted := signThenEncryptCose(t, keys, tc.alg, tc.contentAlg, claims)

			// Wire form: base64url of a tagged CBOR object.
			raw, err := decodeBase64(encrypted)
			require.NoError(t, err)
			assert.Equal(t, byte(0xd8), raw[0]&0xe0|0x18, "tagged CBOR expected")

			verifier := CoseHPKEVerifier(func(context.Context) (jwk.Set, error) {
				return keys.encSet, nil
			}, innerCoseVerifier(keys))

			var recovered map[string]any
			require.NoError(t, verifier.Claims(context.Background(), encrypted, &recovered), "round-trip must decrypt and verify")
			assert.Equal(t, claims["client_id"], recovered["client_id"], "claim mismatch")
		})
	}
}

// TestCoseHPKEEncrypterRejectsUnknownAlgs verifies the registry error
// paths, including the X448 cases.
func TestCoseHPKEEncrypterRejectsUnknownAlgs(t *testing.T) {
	keys := newCoseTestKeys(t, AlgHPKE7)

	cases := []struct {
		alg  int64
		want string
	}{
		{43, "X448"},
		{44, "X448"},
		{51, "X448"},
		{52, "X448"},
		{50, "unknown"},
		{-37, "unknown"},
	}
	for _, tc := range cases {
		encrypter := CoseHPKEEncrypter(tc.alg, func(context.Context) (jwk.Key, error) {
			return keys.encPrivate, nil
		})
		_, err := encrypter.Encrypt(context.Background(), "CWT", "payload", nil)
		require.Error(t, err, "alg %d must be rejected", tc.alg)
		assert.Contains(t, err.Error(), tc.want)
	}

	// Mode mismatch.
	_, err := CoseHPKEEncrypter(AlgHPKE7KE, nil).Encrypt(context.Background(), "CWT", "p", nil)
	require.Error(t, err, "Integrated encrypter must reject a Key Encryption suite")
	_, err = CoseHPKEKeyEncryptionEncrypter(AlgHPKE7, CoseAlgA256GCM, nil).Encrypt(context.Background(), "CWT", "p", nil)
	require.Error(t, err, "Key Encryption encrypter must reject an Integrated suite")
	_, err = CoseHPKEKeyEncryptionEncrypter(AlgHPKE7KE, 10, nil).Encrypt(context.Background(), "CWT", "p", nil)
	require.Error(t, err, "Key Encryption encrypter must reject an unsupported content alg")
	_, err = CoseHPKEEncrypter(AlgHPKE7, nil).Encrypt(context.Background(), "CWT", "p", nil)
	require.Error(t, err, "nil key provider must be rejected")
}

// TestCoseHPKETamperedCiphertextRejected flips one byte of the ciphertext:
// the AEAD tag check must fail.
func TestCoseHPKETamperedCiphertextRejected(t *testing.T) {
	for _, tc := range []struct {
		alg        int64
		contentAlg int64
	}{
		{AlgHPKE3, 0},
		{AlgHPKE3KE, CoseAlgA256GCM},
	} {
		t.Run(joseLabelOfCoseAlg(tc.alg), func(t *testing.T) {
			keys := newCoseTestKeys(t, tc.alg)
			claims := map[string]any{"iss": "https://issuer.example.org"}
			encrypted := signThenEncryptCose(t, keys, tc.alg, tc.contentAlg, claims)

			raw, err := decodeBase64(encrypted)
			require.NoError(t, err)
			raw[len(raw)-1] ^= 1
			tampered := encodeBase64(raw)

			verifier := CoseHPKEVerifier(func(context.Context) (jwk.Set, error) {
				return keys.encSet, nil
			}, innerCoseVerifier(keys))
			require.Error(t, verifier.Verify(tampered), "tampered ciphertext must be rejected")
		})
	}
}

// TestCoseHPKEAlgSwapRejected rewrites the alg header of an HPKE-0 token to
// HPKE-7 while keeping the ciphertext: the protected header is bound into
// the Enc_structure aad, the swap must fail.
func TestCoseHPKEAlgSwapRejected(t *testing.T) {
	keys := newCoseTestKeys(t, AlgHPKE0)
	claims := map[string]any{"iss": "https://issuer.example.org"}
	encrypted := signThenEncryptCose(t, keys, AlgHPKE0, 0, claims)

	raw, err := decodeBase64(encrypted)
	require.NoError(t, err)

	// The protected header is the first field: bstr of the encoded map.
	// Rebuild the COSE_Encrypt0 with an alg-swapped protected header: the
	// swap changes the Enc_structure aad, so the HPKE Open must fail.
	swapped, err := cborDeterministicMode.Marshal(map[int64]any{headerLabelAlg: int64(AlgHPKE7)})
	require.NoError(t, err)
	encrypt0 := []any{swapped, map[int64]any{headerLabelEK: mustExtractEK(t, raw)}, mustExtractCiphertext(t, raw)}
	tagged, err := cborDeterministicMode.Marshal(cbor.Tag{Number: cborTagEncrypt0, Content: encrypt0})
	require.NoError(t, err)
	tampered := encodeBase64(tagged)

	verifier := CoseHPKEVerifier(func(context.Context) (jwk.Set, error) {
		return keys.encSet, nil
	}, innerCoseVerifier(keys))
	require.Error(t, verifier.Verify(tampered), "alg-swapped token must be rejected")
}

// TestCoseHPKEPskIDRejected crafts a mode_psk token (protected psk_id
// header): the verifier must reject it (Base mode only).
func TestCoseHPKEPskIDRejected(t *testing.T) {
	keys := newCoseTestKeys(t, AlgHPKE0)
	claims := map[string]any{"iss": "https://issuer.example.org"}
	encrypted := signThenEncryptCose(t, keys, AlgHPKE0, 0, claims)

	raw, err := decodeBase64(encrypted)
	require.NoError(t, err)

	protected, err := cborDeterministicMode.Marshal(map[int64]any{
		headerLabelAlg:   int64(AlgHPKE0),
		headerLabelPSKID: []byte("psk"),
	})
	require.NoError(t, err)
	encrypt0 := []any{protected, map[int64]any{headerLabelEK: mustExtractEK(t, raw)}, mustExtractCiphertext(t, raw)}
	tagged, err := cborDeterministicMode.Marshal(cbor.Tag{Number: cborTagEncrypt0, Content: encrypt0})
	require.NoError(t, err)
	tampered := encodeBase64(tagged)

	verifier := CoseHPKEVerifier(func(context.Context) (jwk.Set, error) {
		return keys.encSet, nil
	}, innerCoseVerifier(keys))
	require.Error(t, verifier.Verify(tampered), "psk_id token must be rejected")
}

// TestCoseHPKEWrongKeyRejected decrypts with a key set that does not hold
// the recipient key.
func TestCoseHPKEWrongKeyRejected(t *testing.T) {
	keys := newCoseTestKeys(t, AlgHPKE3)
	other := newCoseTestKeys(t, AlgHPKE3)
	claims := map[string]any{"iss": "https://issuer.example.org"}

	encrypted := signThenEncryptCose(t, keys, AlgHPKE3, 0, claims)

	verifier := CoseHPKEVerifier(func(context.Context) (jwk.Set, error) {
		return other.encSet, nil
	}, innerCoseVerifier(other))
	require.Error(t, verifier.Verify(encrypted), "decryption under a foreign key must fail")
}

// TestCoseHPKEMalformedTokensRejected crafts malformed structures and
// asserts the verifier fails closed.
func TestCoseHPKEMalformedTokensRejected(t *testing.T) {
	keys := newCoseTestKeys(t, AlgHPKE0)
	claims := map[string]any{"iss": "https://issuer.example.org"}
	encrypted := signThenEncryptCose(t, keys, AlgHPKE0, 0, claims)
	raw, err := decodeBase64(encrypted)
	require.NoError(t, err)
	ek := mustExtractEK(t, raw)
	ct := mustExtractCiphertext(t, raw)

	buildEncrypt0 := func(protected map[int64]any, unprotected map[int64]any, ciphertext []byte) string {
		p, errP := cborDeterministicMode.Marshal(protected)
		require.NoError(t, errP)
		tagged, errT := cborDeterministicMode.Marshal(cbor.Tag{Number: cborTagEncrypt0, Content: []any{p, unprotected, ciphertext}})
		require.NoError(t, errT)
		return encodeBase64(tagged)
	}

	malformed := map[string]string{
		"missing ek":       buildEncrypt0(map[int64]any{headerLabelAlg: int64(AlgHPKE0)}, map[int64]any{}, ct),
		"missing alg":      buildEncrypt0(map[int64]any{headerLabelKid: []byte("k")}, map[int64]any{headerLabelEK: ek}, ct),
		"empty ciphertext": buildEncrypt0(map[int64]any{headerLabelAlg: int64(AlgHPKE0)}, map[int64]any{headerLabelEK: ek}, nil),
		"wrong tag 18": func() string {
			tagged, errT := cborDeterministicMode.Marshal(cbor.Tag{Number: 18, Content: []any{[]byte{}, map[int64]any{}, ct}})
			require.NoError(t, errT)
			return encodeBase64(tagged)
		}(),
		"not CBOR": encodeBase64([]byte{0x00, 0x01, 0x02}),
	}

	verifier := CoseHPKEVerifier(func(context.Context) (jwk.Set, error) {
		return keys.encSet, nil
	}, innerCoseVerifier(keys))
	for name, rawMalformed := range malformed {
		t.Run(name, func(t *testing.T) {
			require.Error(t, verifier.Verify(rawMalformed), "malformed token must be rejected")
		})
	}
}

// TestCoseHPKETokenAdapterSurface exercises the token.Token adapter: the
// fail-closed methods and the header-derived accessors.
func TestCoseHPKETokenAdapterSurface(t *testing.T) {
	keys := newCoseTestKeys(t, AlgHPKE7)
	claims := map[string]any{"iss": "https://issuer.example.org"}
	encrypted := signThenEncryptCose(t, keys, AlgHPKE7, 0, claims)

	verifier := CoseHPKEVerifier(func(context.Context) (jwk.Set, error) {
		return keys.encSet, nil
	}, innerCoseVerifier(keys))

	parsed, err := verifier.Parse(encrypted)
	require.NoError(t, err)

	_, err = parsed.PublicKey()
	require.Error(t, err, "PublicKey must be unsupported")
	_, err = parsed.PublicKeyThumbPrint()
	require.Error(t, err, "PublicKeyThumbPrint must be unsupported")
	require.Error(t, parsed.UnverifiedClaims(&map[string]any{}), "UnverifiedClaims must fail closed")

	kid, err := parsed.KeyID()
	require.NoError(t, err)
	assert.Equal(t, "test-encryption-key", kid)

	typ, err := parsed.Type()
	require.NoError(t, err)
	assert.True(t, strings.Contains(typ, "cwt"), "inner typ must be CWT-shaped, got %q", typ)
}

// TestSupportedCoseHPKEAlgorithms verifies the registry surface.
func TestSupportedCoseHPKEAlgorithms(t *testing.T) {
	algs := SupportedCoseHPKEAlgorithms()
	require.Len(t, algs, 11)
	for i := 1; i < len(algs); i++ {
		assert.Less(t, algs[i-1], algs[i], "algorithms must be sorted")
	}
}

// mustExtractEK decodes a COSE_Encrypt0 wire form and returns its ek.
func mustExtractEK(t *testing.T, raw []byte) []byte {
	t.Helper()
	var tag cbor.Tag
	require.NoError(t, cborDeterministicDecode.Unmarshal(raw, &tag))
	require.EqualValues(t, cborTagEncrypt0, tag.Number)
	fields, err := decodeCoseArray(tag.Content, 3, "COSE_Encrypt0")
	require.NoError(t, err)
	unprotected, ok := asHeaderMap(fields[1])
	require.True(t, ok)
	ek, err := unprotectedEK(unprotected)
	require.NoError(t, err)
	return ek
}

// mustExtractCiphertext decodes a COSE_Encrypt0 wire form and returns its
// ciphertext.
func mustExtractCiphertext(t *testing.T, raw []byte) []byte {
	t.Helper()
	var tag cbor.Tag
	require.NoError(t, cborDeterministicDecode.Unmarshal(raw, &tag))
	require.EqualValues(t, cborTagEncrypt0, tag.Number)
	fields, err := decodeCoseArray(tag.Content, 3, "COSE_Encrypt0")
	require.NoError(t, err)
	ct, ok := fields[2].([]byte)
	require.True(t, ok)
	return ct
}

// joseLabelOfCoseAlg maps a COSE-HPKE identifier to the JWE alg string, or
// a synthetic label for unregistered values (used for test names).
func joseLabelOfCoseAlg(alg int64) string {
	if s, err := hpke.LookupCOSE(alg); err == nil {
		return s.Label
	}
	return fmt.Sprintf("COSE alg %d", alg)
}
