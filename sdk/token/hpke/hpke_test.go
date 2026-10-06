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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token"
	"zntr.io/solid/sdk/token/jwt"
)

//go:embed testdata/jose-vectors.json
var vectorData []byte

// draftVector is one entry of the draft's companion test vector file
// (draft-ietf-jose-hpke-encrypt, examples/jose-vectors.json).
type draftVector struct {
	Alg       string          `json:"alg"`
	JWK       json.RawMessage `json:"jwk"`
	Compact   string          `json:"compact"`
	Flattened struct {
		Protected    string `json:"protected"`
		AAD          string `json:"aad"`
		EncryptedKey string `json:"encrypted_key"`
		Ciphertext   string `json:"ciphertext"`
	} `json:"flattened"`
}

// supportedVectorAlgs is the subset of draft-22 suites whose KEM is
// available in the Go standard library; the vendored file additionally
// carries X448 (HPKE-5/5-KE/6/6-KE) and non-draft-22 (HPKE-4-KE) entries
// which are filtered out.
var supportedVectorAlgs = SupportedAlgorithms()

func loadVectors(t *testing.T) []draftVector {
	t.Helper()
	var vectors []draftVector
	if err := json.Unmarshal(vectorData, &vectors); err != nil {
		t.Fatalf("unable to decode test vectors: %v", err)
	}
	return vectors
}

// keySetFromVector builds a jwk.Set holding the vector's recipient key.
// The alg member carries the draft's HPKE suite identifier, which is not a
// registered JOSE key algorithm in jwx: strip it before parsing (the
// suite is selected by the token alg header, the member is informational).
func keySetFromVector(t *testing.T, v draftVector) jwk.Set {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(v.JWK, &raw); err != nil {
		t.Fatalf("unable to decode vector JWK: %v", err)
	}
	delete(raw, "alg")
	stripped, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("unable to re-encode vector JWK: %v", err)
	}
	k, err := jwxjwk.ParseKey(stripped)
	if err != nil {
		t.Fatalf("unable to parse vector JWK: %v", err)
	}
	set := jwk.NewSet()
	if err := set.AddKey(k); err != nil {
		t.Fatalf("unable to add vector key: %v", err)
	}
	return set
}

// noopVerifier accepts any inner token: vector plaintexts are arbitrary
// octet sequences, not JWS structures.
type noopVerifier struct{}

func (noopVerifier) Parse(raw string) (token.Token, error) { return nil, fmt.Errorf("noop") }
func (noopVerifier) Verify(raw string) error               { return nil }
func (noopVerifier) Claims(_ context.Context, _ string, _ any) error {
	return nil
}
func (noopVerifier) ContentType() string { return "NOOP" }

// TestDraftVectors decrypts the official draft-22 companion vectors for
// every supported suite: a successful open proves KEM/KDF/AEAD selection,
// the Recipient_structure info binding (Key Encryption) and the protected
// header aad binding (Integrated) all match the draft.
func TestDraftVectors(t *testing.T) {
	vectors := loadVectors(t)
	if len(vectors) == 0 {
		t.Fatal("no vectors loaded")
	}

	decrypted := 0
	for _, v := range vectors {
		if !algSupported(v.Alg) {
			continue
		}
		t.Run(v.Alg, func(t *testing.T) {
			verifier := Verifier(func(context.Context) (jwk.Set, error) {
				return keySetFromVector(t, v), nil
			}, noopVerifier{})

			if err := verifier.Verify(v.Compact); err != nil {
				t.Fatalf("unable to decrypt draft vector: %v", err)
			}

			// Header-derived values match the vector alg.
			parsed, err := verifier.Parse(v.Compact)
			if err != nil {
				t.Fatalf("unable to parse draft vector: %v", err)
			}
			alg, err := parsed.Algorithm()
			if err != nil {
				t.Fatalf("unable to read alg: %v", err)
			}
			if alg != v.Alg {
				t.Fatalf("alg mismatch: expected %q, got %q", v.Alg, alg)
			}
		})
		decrypted++
	}
	if decrypted != len(supportedVectorAlgs) {
		t.Fatalf("expected %d supported-suite vectors, decrypted %d", len(supportedVectorAlgs), decrypted)
	}
}

// algSupported reports whether alg is a supported suite identifier.
func algSupported(alg string) bool {
	_, err := lookupSuite(alg)
	return err == nil
}

// -----------------------------------------------------------------------------

// testKeys generates an ES256 signing key pair and an HPKE recipient key
// pair for the given curve, exported as JWKs.
type testKeys struct {
	signingPrivate jwk.Key
	signingPublic  jwk.Set
	encPrivate     jwk.Key
	encSet         jwk.Set
}

func newTestKeys(t *testing.T, alg string) *testKeys {
	t.Helper()
	s, err := lookupSuite(alg)
	if err != nil {
		t.Fatalf("unsupported alg %q: %v", alg, err)
	}

	// ES256 signing key
	signEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("unable to generate signing key: %v", err)
	}
	signingPrivate, err := jwxjwk.Import(signEC)
	if err != nil {
		t.Fatalf("unable to import signing key: %v", err)
	}
	if err := signingPrivate.Set(jwk.KeyIDKey, "test-signing-key"); err != nil {
		t.Fatalf("unable to set signing kid: %v", err)
	}
	signingPub, err := signingPrivate.PublicKey()
	if err != nil {
		t.Fatalf("unable to derive signing public key: %v", err)
	}
	signingSet := jwk.NewSet()
	if err := signingSet.AddKey(signingPub); err != nil {
		t.Fatalf("unable to add signing public key: %v", err)
	}

	// HPKE recipient key on the suite curve
	ecdhPriv, err := s.Curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("unable to generate encryption key: %v", err)
	}
	encPrivate, err := jwxjwk.Import(ecdhPriv)
	if err != nil {
		t.Fatalf("unable to import encryption key: %v", err)
	}
	if err := encPrivate.Set(jwk.KeyIDKey, "test-encryption-key"); err != nil {
		t.Fatalf("unable to set encryption kid: %v", err)
	}
	if err := encPrivate.Set(jwk.KeyUsageKey, "enc"); err != nil {
		t.Fatalf("unable to set encryption use: %v", err)
	}
	encPub, err := encPrivate.PublicKey()
	if err != nil {
		t.Fatalf("unable to derive encryption public key: %v", err)
	}
	if err := encPub.Set(jwk.KeyUsageKey, "enc"); err != nil {
		t.Fatalf("unable to set public encryption use: %v", err)
	}
	// The decrypt-side key set carries the private key: the verifier is
	// used by the party holding the decapsulation key (e.g. the AS
	// decrypting its own tokens).
	encSet := jwk.NewSet()
	if err := encSet.AddKey(encPrivate); err != nil {
		t.Fatalf("unable to add encryption private key: %v", err)
	}

	return &testKeys{
		signingPrivate: signingPrivate,
		signingPublic:  signingSet,
		encPrivate:     encPrivate,
		encSet:         encSet,
	}
}

// encryptWith assembles the sign-then-encrypt stack exactly like the
// token.Encryption decorator does for the example server.
func encryptWith(t *testing.T, keys *testKeys, alg, enc string, claims any) string {
	t.Helper()

	signer := jwt.AccessTokenSigner("ES256", func(context.Context) (jwk.Key, error) {
		return keys.signingPrivate, nil
	})

	var encrypter token.Encrypter
	switch {
	case alg == "":
		t.Fatal("empty alg")
	case strings.HasSuffix(alg, "-KE"):
		encrypter = KeyEncryptionEncrypter(alg, enc, func(context.Context) (jwk.Key, error) {
			return keys.encPrivate, nil
		})
	default:
		encrypter = Encrypter(alg, func(context.Context) (jwk.Key, error) {
			return keys.encPrivate, nil
		})
	}

	serialized, err := token.Encryption(signer, encrypter).Sign(context.Background(), claims)
	if err != nil {
		t.Fatalf("unable to sign-then-encrypt: %v", err)
	}
	return serialized
}

// innerVerifier is the JWT verifier for the inner signature.
func innerVerifier(keys *testKeys) token.Verifier {
	return jwt.DefaultVerifier(func(context.Context) (jwk.Set, error) {
		return keys.signingPublic, nil
	}, []string{"ES256"})
}

// TestRoundTripAllSuites signs an inner JWT with ES256, encrypts it with
// every supported suite, and recovers the verified claims — proving the
// full sign-then-encrypt assembly for both operating modes.
func TestRoundTripAllSuites(t *testing.T) {
	claims := map[string]any{
		"iss":       "https://issuer.example.org",
		"sub":       "subject-reference",
		"client_id": "confidential-client",
		"scope":     "openid profile",
	}

	for _, alg := range supportedVectorAlgs {
		isKE := strings.HasSuffix(alg, "-KE")
		for _, enc := range []string{"", EncA128GCM, EncA256GCM} {
			// Key Encryption suites require a content-encryption algorithm;
			// Integrated suites ignore the enc parameter.
			if isKE && enc == "" {
				continue
			}
			name := alg
			if isKE {
				name = alg + "/" + enc
			}
			t.Run(name, func(t *testing.T) {
				keys := newTestKeys(t, alg)

				encrypted := encryptWith(t, keys, alg, enc, claims)
				if got := len(strings.Split(encrypted, ".")); got != 5 {
					t.Fatalf("expected 5 compact segments, got %d", got)
				}

				verifier := Verifier(func(context.Context) (jwk.Set, error) {
					return keys.encSet, nil
				}, innerVerifier(keys))

				var recovered map[string]any
				if err := verifier.Claims(context.Background(), encrypted, &recovered); err != nil {
					t.Fatalf("unable to decrypt and verify: %v", err)
				}
				if recovered["client_id"] != claims["client_id"] {
					t.Fatalf("claim mismatch: expected client_id %q, got %v", claims["client_id"], recovered["client_id"])
				}
			})
		}
	}
}

// TestEncrypterRejectsUnknownAlgs verifies the suite registry error paths,
// including the X448 and non-draft-22 cases.
func TestEncrypterRejectsUnknownAlgs(t *testing.T) {
	keys := newTestKeys(t, HPKE7)

	cases := []struct {
		alg  string
		want string
	}{
		{"HPKE-5", "X448"},
		{"HPKE-6", "X448"},
		{"HPKE-5-KE", "X448"},
		{"HPKE-6-KE", "X448"},
		{"HPKE-4-KE", "not registered"},
		{"RSA-OAEP", "unknown"},
		{"", "unknown"},
	}
	for _, tc := range cases {
		encrypter := Encrypter(tc.alg, func(context.Context) (jwk.Key, error) {
			return keys.encPrivate, nil
		})
		_, err := encrypter.Encrypt(context.Background(), "JWT", "payload", nil)
		if err == nil {
			t.Fatalf("alg %q: expected error", tc.alg)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("alg %q: expected error mentioning %q, got %q", tc.alg, tc.want, err.Error())
		}
	}

	// Mode mismatch: Integrated constructor with a -KE suite and back.
	if _, err := Encrypter(HPKE7KE, nil).Encrypt(context.Background(), "JWT", "p", nil); err == nil {
		t.Fatal("expected Integrated encrypter to reject a Key Encryption suite")
	}
	if _, err := KeyEncryptionEncrypter(HPKE7, EncA256GCM, nil).Encrypt(context.Background(), "JWT", "p", nil); err == nil {
		t.Fatal("expected Key Encryption encrypter to reject an Integrated suite")
	}
	if _, err := KeyEncryptionEncrypter(HPKE7KE, "A192GCM", nil).Encrypt(context.Background(), "JWT", "p", nil); err == nil {
		t.Fatal("expected Key Encryption encrypter to reject an unsupported enc")
	}
	// Nil key provider.
	if _, err := Encrypter(HPKE7, nil).Encrypt(context.Background(), "JWT", "p", nil); err == nil {
		t.Fatal("expected error with nil key provider")
	}
}

// TestTamperedCiphertextRejected flips one base64url character in the
// ciphertext segment: the AEAD tag check must fail.
func TestTamperedCiphertextRejected(t *testing.T) {
	for _, tc := range []struct {
		alg string
		enc string
	}{
		{HPKE7, ""},
		{HPKE3, ""},
		{HPKE7KE, EncA256GCM},
		{HPKE3KE, EncA256GCM},
	} {
		alg, enc := tc.alg, tc.enc
		t.Run(alg, func(t *testing.T) {
			keys := newTestKeys(t, alg)
			claims := map[string]any{"iss": "https://issuer.example.org"}

			encrypted := encryptWith(t, keys, alg, enc, claims)

			parts := strings.Split(encrypted, ".")
			ct := []byte(parts[3])
			ct[len(ct)-1] ^= 1
			parts[3] = string(ct)
			tampered := strings.Join(parts, ".")

			verifier := Verifier(func(context.Context) (jwk.Set, error) {
				return keys.encSet, nil
			}, innerVerifier(keys))
			if err := verifier.Verify(tampered); err == nil {
				t.Fatal("expected tampered ciphertext to be rejected")
			}
		})
	}
}

// TestAlgSwapRejected rewrites the alg header (HPKE-0 to HPKE-7) while
// keeping the ciphertext: the header is AEAD-bound, so the swap must fail
// (algorithm substitution, RFC 8725 section 3.4).
func TestAlgSwapRejected(t *testing.T) {
	// Both suites share the P-256 KEM; only the AEAD differs (A128GCM vs
	// A256GCM), which is precisely the confusion an attacker would attempt.
	keys := newTestKeys(t, HPKE0)
	claims := map[string]any{"iss": "https://issuer.example.org"}

	encrypted := encryptWith(t, keys, HPKE0, "", claims)

	parts := strings.Split(encrypted, ".")
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("unable to decode header: %v", err)
	}
	swapped := strings.Replace(string(headerJSON), `"alg":"HPKE-0"`, `"alg":"HPKE-7"`, 1)
	if swapped == string(headerJSON) {
		t.Fatal("alg substitution did not apply")
	}
	parts[0] = base64.RawURLEncoding.EncodeToString([]byte(swapped))
	tampered := strings.Join(parts, ".")

	verifier := Verifier(func(context.Context) (jwk.Set, error) {
		return keys.encSet, nil
	}, innerVerifier(keys))
	if err := verifier.Verify(tampered); err == nil {
		t.Fatal("expected alg-swapped token to be rejected")
	}
}

// TestHeaderValidationFailClosed crafts malformed JWEs via raw string
// surgery and asserts the verifier fails closed on every draft rule.
func TestHeaderValidationFailClosed(t *testing.T) {
	keys := newTestKeys(t, HPKE7)
	claims := map[string]any{"iss": "https://issuer.example.org"}

	encryptIntegrated := func(alg string) string {
		return encryptWith(t, keys, alg, "", claims)
	}
	encryptKeyEnc := func(enc string) string {
		return encryptWith(t, keys, HPKE7KE, enc, claims)
	}

	// Rewrite the protected header of a compact JWE, keeping the other
	// segments unchanged.
	withHeader := func(tokenStr string, header any) string {
		parts := strings.Split(tokenStr, ".")
		headerJSON, err := json.Marshal(header)
		if err != nil {
			t.Fatalf("unable to encode header: %v", err)
		}
		parts[0] = base64.RawURLEncoding.EncodeToString(headerJSON)
		return strings.Join(parts, ".")
	}
	baseHeader := func(tokenStr string) map[string]any {
		parts := strings.Split(tokenStr, ".")
		var h map[string]any
		headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			t.Fatalf("unable to decode header: %v", err)
		}
		if err := json.Unmarshal(headerJSON, &h); err != nil {
			t.Fatalf("unable to parse header: %v", err)
		}
		return h
	}

	integrated := encryptIntegrated(HPKE7)
	keyEnc := encryptKeyEnc(EncA256GCM)

	cases := []struct {
		name string
		raw  string
	}{
		{"4-part input", strings.Join(strings.Split(integrated, ".")[:4], ".")},
		{"6-part input", integrated + ".x"},
		{"padded base64url segment", strings.Replace(integrated, ".", "=.", 1)},
		{"enc header on Integrated", withHeader(integrated, func() map[string]any {
			h := baseHeader(integrated)
			h["enc"] = EncA256GCM
			return h
		}())},
		{"ek header on Integrated", withHeader(integrated, func() map[string]any {
			h := baseHeader(integrated)
			h["ek"] = "AAAA"
			return h
		}())},
		{"iv segment on Integrated", func() string {
			parts := strings.Split(integrated, ".")
			parts[2] = "AAAAAAAAAAAAAAAA"
			return strings.Join(parts, ".")
		}()},
		{"tag segment on Integrated", func() string {
			parts := strings.Split(integrated, ".")
			parts[4] = "AAAAAAAAAAAAAAAAAAAAAA"
			return strings.Join(parts, ".")
		}()},
		{"missing ek on KeyEnc", withHeader(keyEnc, func() map[string]any {
			h := baseHeader(keyEnc)
			delete(h, "ek")
			return h
		}())},
		{"missing enc on KeyEnc", withHeader(keyEnc, func() map[string]any {
			h := baseHeader(keyEnc)
			delete(h, "enc")
			return h
		}())},
		{"unsupported enc on KeyEnc", withHeader(keyEnc, func() map[string]any {
			h := baseHeader(keyEnc)
			h["enc"] = "A192GCM"
			return h
		}())},
		{"crit header", withHeader(integrated, func() map[string]any {
			h := baseHeader(integrated)
			h["crit"] = []string{"exp"}
			return h
		}())},
		{"zip header", withHeader(integrated, func() map[string]any {
			h := baseHeader(integrated)
			h["zip"] = "DEF"
			return h
		}())},
		{"psk_id header", withHeader(integrated, func() map[string]any {
			h := baseHeader(integrated)
			h["psk_id"] = "shared-secret"
			return h
		}())},
		{"X448 alg", withHeader(integrated, func() map[string]any {
			h := baseHeader(integrated)
			h["alg"] = "HPKE-5"
			return h
		}())},
		{"missing alg", withHeader(integrated, func() map[string]any {
			h := baseHeader(integrated)
			delete(h, "alg")
			return h
		}())},
		{"duplicated header members", func() string {
			// Two alg members: the decoder keeps the last, the duplicate
			// check must reject the token.
			parts := strings.Split(integrated, ".")
			return strings.Join([]string{
				base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HPKE-7","alg":"HPKE-7"}`)),
				parts[1], parts[2], parts[3], parts[4],
			}, ".")
		}()},
		{"non-object header", func() string {
			parts := strings.Split(integrated, ".")
			return strings.Join([]string{
				base64.RawURLEncoding.EncodeToString([]byte(`["alg"]`)),
				parts[1], parts[2], parts[3], parts[4],
			}, ".")
		}()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verifier := Verifier(func(context.Context) (jwk.Set, error) {
				return keys.encSet, nil
			}, innerVerifier(keys))
			if err := verifier.Verify(tc.raw); err == nil {
				t.Fatal("expected malformed token to be rejected")
			}
			// Claims path fails identically: no partial plaintext.
			if err := verifier.Claims(context.Background(), tc.raw, &map[string]any{}); err == nil {
				t.Fatal("expected malformed token to be rejected on Claims")
			}
		})
	}
}

// TestWrongKeyRejected decrypts with a key set that does not contain the
// recipient key.
func TestWrongKeyRejected(t *testing.T) {
	keys := newTestKeys(t, HPKE3)
	other := newTestKeys(t, HPKE3)
	claims := map[string]any{"iss": "https://issuer.example.org"}

	encrypted := encryptWith(t, keys, HPKE3, "", claims)

	verifier := Verifier(func(context.Context) (jwk.Set, error) {
		return other.encSet, nil
	}, innerVerifier(other))
	if err := verifier.Verify(encrypted); err == nil {
		t.Fatal("expected decryption under the wrong key to fail")
	}
}

// TestCurveMismatchRejected verifies the draft section 10.1 key separation
// rule: a P-256 recipient key cannot serve an X25519 suite and vice versa.
func TestCurveMismatchRejected(t *testing.T) {
	keys := newTestKeys(t, HPKE3) // X25519 key

	encrypter := Encrypter(HPKE7, func(context.Context) (jwk.Key, error) {
		return keys.encPrivate, nil
	})
	if _, err := encrypter.Encrypt(context.Background(), "JWT", "payload", nil); err == nil {
		t.Fatal("expected curve mismatch to be rejected")
	}
}

// TestWrongKeyUsageRejected verifies the use=enc requirement on the
// recipient key.
func TestWrongKeyUsageRejected(t *testing.T) {
	keys := newTestKeys(t, HPKE7)
	if err := keys.encPrivate.Set(jwk.KeyUsageKey, "sig"); err != nil {
		t.Fatalf("unable to set key usage: %v", err)
	}

	encrypter := Encrypter(HPKE7, func(context.Context) (jwk.Key, error) {
		return keys.encPrivate, nil
	})
	if _, err := encrypter.Encrypt(context.Background(), "JWT", "payload", nil); err == nil {
		t.Fatal("expected sig-use key to be rejected")
	}
}

// TestTokenAdapterSurface exercises the token.Token adapter: PublicKey,
// PublicKeyThumbPrint and UnverifiedClaims fail closed, Type and KeyID are
// answered from the decrypted/verified token.
func TestTokenAdapterSurface(t *testing.T) {
	keys := newTestKeys(t, HPKE7)
	claims := map[string]any{"iss": "https://issuer.example.org"}

	encrypted := encryptWith(t, keys, HPKE7, "", claims)
	verifier := Verifier(func(context.Context) (jwk.Set, error) {
		return keys.encSet, nil
	}, innerVerifier(keys))

	parsed, err := verifier.Parse(encrypted)
	if err != nil {
		t.Fatalf("unable to parse: %v", err)
	}

	if _, err := parsed.PublicKey(); err == nil {
		t.Fatal("expected PublicKey to be unsupported")
	}
	if _, err := parsed.PublicKeyThumbPrint(); err == nil {
		t.Fatal("expected PublicKeyThumbPrint to be unsupported")
	}
	if err := parsed.UnverifiedClaims(&map[string]any{}); err == nil {
		t.Fatal("expected UnverifiedClaims to fail closed")
	}

	kid, err := parsed.KeyID()
	if err != nil {
		t.Fatalf("unable to read kid: %v", err)
	}
	if kid != "test-encryption-key" {
		t.Fatalf("kid mismatch: got %q", kid)
	}

	typ, err := parsed.Type()
	if err != nil {
		t.Fatalf("unable to read inner typ: %v", err)
	}
	if !strings.Contains(typ, "jwt") {
		t.Fatalf("unexpected inner typ %q", typ)
	}
}

// TestContentType verifies the outer serialization identifier.
func TestContentType(t *testing.T) {
	if got := Verifier(nil, nil).ContentType(); got != "JWE" {
		t.Fatalf("expected JWE, got %q", got)
	}
}

// TestSupportedAlgorithms verifies the registry surface.
func TestSupportedAlgorithms(t *testing.T) {
	algs := SupportedAlgorithms()
	if len(algs) != 11 {
		t.Fatalf("expected 11 supported algorithms, got %d", len(algs))
	}
	for i := 1; i < len(algs); i++ {
		if algs[i-1] >= algs[i] {
			t.Fatalf("SupportedAlgorithms not sorted: %v", algs)
		}
	}
}
