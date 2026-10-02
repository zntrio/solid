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

package sdcwt

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"math"
	"testing"

	cbor "github.com/fxamacker/cbor/v2"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/veraison/go-cose"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/sdtoken"
)

// newKeyMaterial generates an issuer key pair and returns the private
// key provider plus the public key set provider.
func newKeyMaterial(t *testing.T) (jwk.KeyProviderFunc, jwk.KeySetProviderFunc) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("unable to generate key: %v", err)
	}

	privKey, err := jwxjwk.Import(priv)
	if err != nil {
		t.Fatalf("unable to import private key: %v", err)
	}
	if err := privKey.Set(jwxjwk.KeyIDKey, "test-key"); err != nil {
		t.Fatalf("unable to set kid: %v", err)
	}

	pub, err := jwxjwk.Import(&priv.PublicKey)
	if err != nil {
		t.Fatalf("unable to import public key: %v", err)
	}
	if err := pub.Set(jwxjwk.KeyIDKey, "test-key"); err != nil {
		t.Fatalf("unable to set public kid: %v", err)
	}
	if err := pub.Set(jwxjwk.AlgorithmKey, "ES256"); err != nil {
		t.Fatalf("unable to set public alg: %v", err)
	}

	set := jwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		t.Fatalf("unable to add public key: %v", err)
	}

	return func(context.Context) (jwk.Key, error) { return privKey, nil },
		func(context.Context) (jwk.Set, error) { return set, nil }
}

func TestSDCWT_Figure7_Vector(t *testing.T) {
	// draft section 3.2 Figure 7: disclosure for
	// inspector_license_number with salt bae611067bb823486797da1ebbb52f83,
	// value "ABCD-123456", key 501.
	salt, err := hex.DecodeString("bae611067bb823486797da1ebbb52f83")
	if err != nil {
		t.Fatal(err)
	}

	wire, rawDigest, err := encodeDisclosure(salt, uint64(501), "ABCD-123456")
	if err != nil {
		t.Fatalf("unable to encode disclosure: %v", err)
	}

	// Expected CBOR array (draft Figure 7): 83 50 <16-byte salt> 6b
	// "ABCD-123456" 1901f5 (salt, value, claim order).
	wantWire, err := hex.DecodeString("8350bae611067bb823486797da1ebbb52f836b414243442d3132333435361901f5")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, wantWire) {
		t.Errorf("disclosure wire = %x, want %x", wire, wantWire)
	}
	// Expected digest (Figure 8): d9df03da474fcb3c65771748e2e0608c
	// f437504ecc24f450aaeacd40dd552b3f (raw SHA-256 of the CBOR bytes).
	wantDigest, err := hex.DecodeString("d9df03da474fcb3c65771748e2e0608cf437504ecc24f450aaeacd40dd552b3f")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rawDigest, wantDigest) {
		t.Errorf("digest = %x, want %x", rawDigest, wantDigest)
	}
}

func TestSDCWT_DecoyVector(t *testing.T) {
	// draft section 10: a decoy digest is SHA-256 over the 1-element
	// CBOR array [bstr(salt)].
	salt, err := hex.DecodeString("c1069bc056e234d64f58baff8a7b776b")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := decoyDigest(salt)
	if err != nil {
		t.Fatal(err)
	}
	if len(digest) == 0 {
		t.Error("decoy digest must not be empty")
	}

	// The decoy digest must match a directly-computed SHA-256 of the
	// 1-element array encoding.
	wire, err := cbor.Marshal([]any{salt})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(digest, sdtoken.Digest(wire)) {
		t.Errorf("decoy digest %x does not match direct computation %x", digest, sdtoken.Digest(wire))
	}
}

func TestSDCWT_DecodeDisclosure(t *testing.T) {
	// Round-trip the Figure 7 disclosure.
	salt, _ := hex.DecodeString("bae611067bb823486797da1ebbb52f83")
	wire, _, err := encodeDisclosure(salt, uint64(501), "ABCD-123456")
	if err != nil {
		t.Fatal(err)
	}
	dd, err := decodeDisclosure(wire)
	if err != nil {
		t.Fatalf("unable to decode: %v", err)
	}
	if dd.IsDecoy {
		t.Error("must not be a decoy")
	}
	if k, ok := dd.ClaimKey.(uint64); !ok || k != 501 {
		t.Errorf("claim key = %v, want 501", dd.ClaimKey)
	}
	if dd.Value != "ABCD-123456" {
		t.Errorf("value = %v", dd.Value)
	}
	if !bytes.Equal(dd.Salt, salt) {
		t.Errorf("salt = %x", dd.Salt)
	}

	// Element form (2-element).
	elemWire, _, err := encodeDisclosure(salt, nil, "DE")
	if err != nil {
		t.Fatal(err)
	}
	dd2, err := decodeDisclosure(elemWire)
	if err != nil {
		t.Fatal(err)
	}
	if dd2.ClaimKey != nil {
		t.Errorf("element form must have nil claim key, got %v", dd2.ClaimKey)
	}

	// Decoy form (1-element).
	decoyWire, err := cbor.Marshal([]any{salt})
	if err != nil {
		t.Fatal(err)
	}
	dd3, err := decodeDisclosure(decoyWire)
	if err != nil {
		t.Fatal(err)
	}
	if !dd3.IsDecoy {
		t.Error("1-element disclosure must be a decoy")
	}

	// Bad salt length.
	badSalt := make([]byte, 15)
	badWire, err := cbor.Marshal([]any{badSalt, "v"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeDisclosure(badWire); err == nil {
		t.Error("15-byte salt must be rejected")
	}
}

func TestSDCWT_CheckDefiniteLength(t *testing.T) {
	// Hand-built indefinite-length map: 0x9f 0x01 0x02 0xff.
	if err := checkDefiniteLength([]byte{0x9f, 0x01, 0x02, 0xff}); err == nil {
		t.Error("indefinite map must be rejected")
	}
	// Indefinite-length array: 0x9f 0x01 0xff.
	if err := checkDefiniteLength([]byte{0x9f, 0x01, 0xff}); err == nil {
		t.Error("indefinite array must be rejected")
	}
	// Indefinite-length text string: 0x7f 0x61 0x61 0xff.
	if err := checkDefiniteLength([]byte{0x7f, 0x61, 0x61, 0xff}); err == nil {
		t.Error("indefinite text string must be rejected")
	}
	// Definite map: 0xa1 0x01 0x02.
	if err := checkDefiniteLength([]byte{0xa1, 0x01, 0x02}); err != nil {
		t.Errorf("definite map must pass: %v", err)
	}
	// A full valid COSE_Sign1 (tag 18) round-trips through the check.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmES256, priv)
	if err != nil {
		t.Fatal(err)
	}
	msg := cose.Sign1Message{
		Headers: cose.Headers{Protected: cose.ProtectedHeader{cose.HeaderLabelAlgorithm: cose.AlgorithmES256}},
		Payload: []byte{0xa1, 0x01, 0x02},
	}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatal(err)
	}
	raw, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	if err := checkDefiniteLength(raw); err != nil {
		t.Errorf("valid COSE_Sign1 must pass: %v", err)
	}
}

func TestSDCWT_CheckMapKeys(t *testing.T) {
	// Valid claims map.
	valid := map[any]any{
		uint64(1): "iss",
		"street":  "123 Main St",
		int64(-1): "negative",
	}
	if err := checkMapKeys(valid, 0); err != nil {
		t.Errorf("valid claims rejected: %v", err)
	}

	// Oversized text key.
	oversized := map[any]any{
		string(make([]byte, 256)): "v",
	}
	if err := checkMapKeys(oversized, 0); err == nil {
		t.Error("256-byte text key must be rejected")
	}

	// bstr key: build via CBOR decode (map[any]any with a []byte key
	// is not constructible directly — Go maps require comparable keys).
	bstrRaw, err := cbor.Marshal(map[any]any{"placeholder": "v"})
	if err != nil {
		t.Fatal(err)
	}
	// 0xa1 0x41 0x6b <text> ... — hand-encode: map(1) { bstr(1) "k": "v" }.
	bstrMap := []byte{0xa1, 0x41, 0x6b, 0x61, 0x76} // { h'6b': "v" }
	bstrClaims, err := enforceDuplicateMapKeys(bstrMap)
	if err != nil {
		t.Fatalf("unable to decode bstr-key map: %v", err)
	}
	if err := checkMapKeys(bstrClaims, 0); err == nil {
		t.Error("bstr map key must be rejected")
	}
	_ = bstrRaw

	// float key.
	floatKey := map[any]any{
		1.5: "v",
	}
	if err := checkMapKeys(floatKey, 0); err == nil {
		t.Error("float map key must be rejected")
	}

	// Nested tag in map key.
	tagKey := map[any]any{
		cbor.Tag{Number: 1, Content: uint64(1)}: "v",
	}
	if err := checkMapKeys(tagKey, 0); err == nil {
		t.Error("tagged map key must be rejected")
	}

	// Depth 17: one deeper than the 16-level bound.
	deep := map[any]any{}
	current := deep
	for range 17 {
		next := map[any]any{}
		current["n"] = next
		current = next
	}
	if err := checkMapKeys(deep, 0); err == nil {
		t.Error("depth-17 nesting must be rejected")
	}

	// NaN / Inf / >2^53 float values.
	for _, bad := range []map[any]any{
		{uint64(4): nan()},
		{uint64(4): inf(1)},
		{uint64(4): float64(1 << 54)},
	} {
		if err := checkMapKeys(bad, 0); err == nil {
			t.Errorf("invalid numeric date %v must be rejected", bad)
		}
	}
}

func TestSDCWT_DuplicateMapKeys(t *testing.T) {
	// Duplicate integer keys (preferred-encoding equivalence: 0x01 and
	// 0x1801 encode the same uint 1).
	dup := []byte{0xa2, 0x01, 0x01, 0x18, 0x01, 0x02}
	if _, err := enforceDuplicateMapKeys(dup); err == nil {
		t.Error("duplicate map keys must be rejected")
	}

	// Distinct keys pass.
	ok := []byte{0xa2, 0x01, 0x01, 0x02, 0x02}
	if _, err := enforceDuplicateMapKeys(ok); err != nil {
		t.Errorf("distinct keys must pass: %v", err)
	}
}

func TestSDCWT_ConfirmationRoundTrip(t *testing.T) {
	// EC P-256.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cnf, err := Confirmation(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	got, alg, err := confirmationKey(map[any]any{uint64(ClaimKeyCnf): cnf})
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := got.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("wrong key type %T", got)
	}
	if alg != cose.AlgorithmES256 {
		t.Errorf("alg = %v", alg)
	}
	if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
		t.Error("coordinate mismatch")
	}

	// P-384 / P-521.
	for _, curve := range []elliptic.Curve{elliptic.P384(), elliptic.P521()} {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cnf, err := Confirmation(&priv.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := confirmationKey(map[any]any{uint64(ClaimKeyCnf): cnf}); err != nil {
			t.Errorf("curve %v round-trip failed: %v", curve.Params().Name, err)
		}
	}

	// Ed25519.
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cnf, err = Confirmation(edPub)
	if err != nil {
		t.Fatal(err)
	}
	gotEd, algEd, err := confirmationKey(map[any]any{uint64(ClaimKeyCnf): cnf})
	if err != nil {
		t.Fatal(err)
	}
	ed, ok := gotEd.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("wrong key type %T", gotEd)
	}
	if !bytes.Equal(ed, edPub) {
		t.Error("ed25519 key mismatch")
	}
	if algEd != cose.AlgorithmEd25519 {
		t.Errorf("alg = %v", algEd)
	}
	_ = edPriv
}

func TestSDCWT_IssuePresentVerifyRoundTrip(t *testing.T) {
	issuerKP, issuerSetP := newKeyMaterial(t)

	iss := NewIssuer(cose.AlgorithmES256, issuerKP)

	// Holder key material: one key pair backs both the KBT signing key
	// and the cnf claim.
	holderPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderKey, err := jwxjwk.Import(holderPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := holderKey.Set(jwxjwk.KeyIDKey, "holder-key"); err != nil {
		t.Fatal(err)
	}
	holderKP := func(context.Context) (jwk.Key, error) { return holderKey, nil }
	cnf, err := Confirmation(&holderPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// draft section 14.2 shape: inspection_location with redacted
	// region/postal_code.
	claims := map[any]any{
		uint64(1): "https://issuer.example.com", // iss
		uint64(6): 1750000000,                   // iat
		uint64(2): "holder-123",                 // sub
		"inspection_location": sdtoken.Disclosable{Value: map[any]any{
			"region":      sdtoken.Disclosable{Value: "Northern"},
			"postal_code": sdtoken.Disclosable{Value: "99163"},
		}},
		"inspector_license_number": sdtoken.Disclosable{Value: "ABCD-123456"},
		"certificates": []any{
			sdtoken.DisclosableElement{Value: "cert-1"},
			sdtoken.DisclosableElement{Value: "cert-2"},
		},
		uint64(ClaimKeyCnf): cnf,
	}

	issued, disclosures, err := iss.Issue(context.Background(), claims)
	if err != nil {
		t.Fatalf("unable to issue: %v", err)
	}
	// 5 claim disclosures + decoys (per redacted_claim_keys array at
	// two levels) — the exact count depends on the decoy placement;
	// just require more than the plain disclosures.
	if len(disclosures) < 5 {
		t.Fatalf("expected at least 5 disclosures, got %d", len(disclosures))
	}

	// Holder: present the full chain (children + parents) minus
	// postal_code; include decoys (required for holder semantics).
	hold := NewHolder(issuerSetP, cose.AlgorithmES256, holderKP)

	// Discover disclosures by decoding.
	var selected [][]byte
	var postalWire []byte
	for _, d := range disclosures {
		dd, err := decodeDisclosure(d)
		if err != nil {
			t.Fatalf("unable to decode disclosure: %v", err)
		}
		if k, isStr := dd.ClaimKey.(string); isStr && k == "postal_code" {
			postalWire = d
			continue
		}
		selected = append(selected, d)
	}
	if postalWire == nil {
		t.Fatal("postal_code disclosure not found")
	}

	presentation, err := hold.Present(issued, selected)
	if err != nil {
		t.Fatalf("unable to present: %v", err)
	}

	// Key bind with cnonce and iat.
	cnonce := []byte("challenge-nonce-1")
	cnonces := map[string]bool{}
	kbt, err := hold.KeyBind(presentation, "verifier.example.com", cnonce, WithIssuedAt(1750000500))
	if err != nil {
		t.Fatalf("unable to key bind: %v", err)
	}

	// Verify.
	v := NewVerifier(issuerSetP,
		WithAudience("verifier.example.com"),
		WithCnonceValidator(func(b []byte) error {
			if cnonces[string(b)] {
				return errCnonceReplay
			}
			cnonces[string(b)] = true
			return nil
		}),
	)
	validated, err := v.Verify(context.Background(), kbt)
	if err != nil {
		t.Fatalf("unable to verify: %v", err)
	}

	// Disclosed claims appear; postal_code does not.
	loc, ok := validated["inspection_location"].(map[any]any)
	if !ok {
		t.Fatalf("inspection_location not disclosed: %v", validated)
	}
	if loc["region"] != "Northern" {
		t.Errorf("region not disclosed: %v", loc)
	}
	if _, has := loc["postal_code"]; has {
		t.Error("postal_code must remain undisclosed")
	}
	if validated["inspector_license_number"] != "ABCD-123456" {
		t.Errorf("inspector_license_number not disclosed: %v", validated)
	}

	// Cnonce replay must fail.
	presentation2, err := hold.Present(issued, selected)
	if err != nil {
		t.Fatal(err)
	}
	kbt2, err := hold.KeyBind(presentation2, "verifier.example.com", cnonce, WithIssuedAt(1750000501))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), kbt2); err == nil {
		t.Error("cnonce replay must be rejected")
	}

	// Shuffled disclosure order still validates (order independence):
	// rebuild the presentation with reversed selected disclosures.
	var reversed [][]byte
	for i := len(selected) - 1; i >= 0; i-- {
		reversed = append(reversed, selected[i])
	}
	presentation3, err := hold.Present(issued, reversed)
	if err != nil {
		t.Fatal(err)
	}
	kbt3, err := hold.KeyBind(presentation3, "verifier.example.com", []byte("fresh-nonce"), WithIssuedAt(1750000502))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), kbt3); err != nil {
		t.Errorf("shuffled disclosures must still validate: %v", err)
	}
}

func TestSDCWT_KBTWithCti(t *testing.T) {
	issuerKP, issuerSetP := newKeyMaterial(t)

	iss := NewIssuer(cose.AlgorithmES256, issuerKP)
	holderPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderKey, err := jwxjwk.Import(holderPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := holderKey.Set(jwxjwk.KeyIDKey, "holder-key"); err != nil {
		t.Fatal(err)
	}
	holderKP := func(context.Context) (jwk.Key, error) { return holderKey, nil }
	cnf, err := Confirmation(&holderPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	claims := map[any]any{
		"given_name":        sdtoken.Disclosable{Value: "John"},
		uint64(ClaimKeyCnf): cnf,
	}
	issued, disclosures, err := iss.Issue(context.Background(), claims)
	if err != nil {
		t.Fatal(err)
	}

	hold := NewHolder(issuerSetP, cose.AlgorithmES256, holderKP)
	presentation, err := hold.Present(issued, disclosures)
	if err != nil {
		t.Fatal(err)
	}

	// KBT with cti instead of iat (draft section 8.1: one of
	// iat/cti REQUIRED).
	cti := []byte("token-id-1")
	kbt, err := hold.KeyBind(presentation, "verifier.example.com", []byte("nonce-cti"), WithCti(cti))
	if err != nil {
		t.Fatal(err)
	}

	v := NewVerifier(issuerSetP,
		WithAudience("verifier.example.com"),
		WithCnonceValidator(func([]byte) error { return nil }),
	)
	if _, err := v.Verify(context.Background(), kbt); err != nil {
		t.Fatalf("kbt with cti must verify: %v", err)
	}
}

func nan() float64 {
	var z float64
	return z / z
}

func inf(sign int) float64 {
	return math.Inf(sign)
}

var errCnonceReplay = errCnonce("cnonce replayed")

type errCnonce string

func (e errCnonce) Error() string { return string(e) }
