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

package jwk

import (
	"crypto"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/json"
	"testing"

	golangjwt "github.com/golang-jwt/jwt/v5"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
)

func TestMLDSAKeyJWKRoundTrip(t *testing.T) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewMLDSAKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Set(jwxjwk.KeyIDKey, "akp-1"); err != nil {
		t.Fatal(err)
	}

	// Marshal never leaks private material.
	encoded, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	var probe map[string]any
	json.Unmarshal(encoded, &probe)
	if _, has := probe["d"]; has {
		t.Fatal("marshal leaks private d member")
	}
	if probe["kty"] != "AKP" || probe["alg"] != "ML-DSA-65" {
		t.Fatalf("unexpected marshal form: %s", encoded)
	}

	// Round-trip through ParseMLDSAJWK (public).
	pubSet, err := Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	pubKey, ok := pubSet.Key(0)
	if !ok {
		t.Fatal("no key in set")
	}
	mk, ok := pubKey.(*MLDSAKey)
	if !ok {
		t.Fatalf("key type = %T", pubKey)
	}
	if mk.PrivateKey() != nil {
		t.Fatal("public round-trip must not carry a private key")
	}

	// Thumbprint stability across marshal/parse.
	tp1, _ := key.Thumbprint(crypto.SHA256)
	tp2, _ := mk.Thumbprint(crypto.SHA256)
	if base64.RawURLEncoding.EncodeToString(tp1) != base64.RawURLEncoding.EncodeToString(tp2) {
		t.Fatal("thumbprint diverged across round-trip")
	}
}

func TestParseMLDSAJWKPrivateSeed(t *testing.T) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	seeded, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
	if err != nil {
		t.Fatal(err)
	}

	doc := map[string]any{
		"kty": "AKP",
		"alg": "ML-DSA-65",
		"kid": "seeded",
		"use": "sig",
		"pub": base64.RawURLEncoding.EncodeToString(seeded.PublicKey().Bytes()),
		"d":   base64.RawURLEncoding.EncodeToString(seed),
	}
	raw, _ := json.Marshal(doc)

	k, err := ParseMLDSAJWK(raw)
	if err != nil {
		t.Fatalf("private AKP parse failed: %v", err)
	}
	if k.PrivateKey() == nil {
		t.Fatal("private seed did not produce a private key")
	}

	// The derived public key must match the pub member.
	if !k.PrivateKey().PublicKey().Equal(seeded.PublicKey()) {
		t.Fatal("seeded key does not match")
	}
	_ = priv
}

func TestParseMLDSAJWKSeedMismatch(t *testing.T) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	other, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	otherSeed := make([]byte, 32)
	for i := range otherSeed {
		otherSeed[i] = byte(255 - i)
	}
	seeded, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), otherSeed)
	if err != nil {
		t.Fatal(err)
	}

	doc := map[string]any{
		"kty": "AKP",
		"alg": "ML-DSA-65",
		"pub": base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()),
		"d":   base64.RawURLEncoding.EncodeToString(otherSeed[:32]),
	}
	raw, _ := json.Marshal(doc)

	if _, err := ParseMLDSAJWK(raw); err == nil {
		t.Fatal("seed/pub mismatch must be rejected")
	}
	_ = other
	_ = seeded
}

func TestParseMixedAKPJWKS(t *testing.T) {
	akp, err := NewMLDSAKeyFromPublic(func() *mldsa.PublicKey {
		priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
		if err != nil {
			t.Fatal(err)
		}
		return priv.PublicKey()
	}())
	if err != nil {
		t.Fatal(err)
	}
	if err := akp.Set(jwxjwk.KeyIDKey, "akp-mix"); err != nil {
		t.Fatal(err)
	}

	ec := `{"kty":"EC","kid":"ec-mix","use":"sig","crv":"P-256","x":"h6jud8ozOJ93MvHZCxvGZnOVHLeTX-3K9LkAvKy1RSs","y":"yY0UQDLFPM8OAgkOYfotwzXCGXtBYinBk1EURJQ7ONk","alg":"ES256"}`

	set, err := Parse([]byte(`{"keys":[` + string(func() []byte {
		b, _ := json.Marshal(akp)
		return b
	}()) + `,` + ec + `]}`))
	if err != nil {
		t.Fatalf("mixed set parse failed: %v", err)
	}
	if set.Len() != 2 {
		t.Fatalf("set len = %d, want 2", set.Len())
	}

	// KeyUsage passthrough on AKP entries.
	k, _ := set.Key(0)
	if _, ok := k.(*MLDSAKey); !ok {
		t.Fatalf("first entry type = %T", k)
	}
}

func TestValidateSignatureWithMLDSAKey(t *testing.T) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewMLDSAKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	// Sign with golang-jwt directly.
	tok := golangjwt.NewWithClaims(SigningMethodMLDSA65, golangjwt.MapClaims{"sub": "alice"})
	raw, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}

	// Verify through ValidateSignature with a public-only AKP keyset.
	pub, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	set := jwxjwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		t.Fatal(err)
	}

	if err := ValidateSignature(set, raw, []string{"ML-DSA-65"}); err != nil {
		t.Fatalf("AKP ValidateSignature failed: %v", err)
	}

	// Wrong allowlist must reject.
	if err := ValidateSignature(set, raw, []string{"ES256"}); err == nil {
		t.Fatal("expected rejection with ES-only allowlist")
	}

	// AKP key marked as enc must be skipped.
	encKey, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := encKey.Set(jwxjwk.KeyUsageKey, "enc"); err != nil {
		t.Fatal(err)
	}
	encSet := jwxjwk.NewSet()
	encSet.AddKey(encKey)
	if err := ValidateSignature(encSet, raw, []string{"ML-DSA-65"}); err == nil {
		t.Fatal("enc-marked AKP key must be skipped")
	}
}
