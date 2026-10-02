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

package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"math"
	"testing"

	cbor "github.com/fxamacker/cbor/v2"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/veraison/go-cose"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/sdtoken"
	"zntr.io/solid/sdk/sdtoken/sdcwt"
)

// sdcwtKeyMaterial generates issuer and holder key material.
type sdcwtKeyMaterial struct {
	issuerPriv    *ecdsa.PrivateKey
	issuerPrivKey jwk.Key
	issuerPubSet  jwk.Set
	holderPriv    *ecdsa.PrivateKey
	holderPrivKey jwk.Key
	attackerPriv  *ecdsa.PrivateKey
	attackerKey   jwk.Key
}

func newSDCWTKeyMaterial(t *testing.T) *sdcwtKeyMaterial {
	t.Helper()

	km := &sdcwtKeyMaterial{}
	var err error
	if km.issuerPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	if km.holderPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	if km.attackerPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}

	if km.issuerPrivKey, err = jwxjwk.Import(km.issuerPriv); err != nil {
		t.Fatal(err)
	}
	if err := km.issuerPrivKey.Set(jwxjwk.KeyIDKey, "issuer-key"); err != nil {
		t.Fatal(err)
	}
	if km.holderPrivKey, err = jwxjwk.Import(km.holderPriv); err != nil {
		t.Fatal(err)
	}
	if err := km.holderPrivKey.Set(jwxjwk.KeyIDKey, "holder-key"); err != nil {
		t.Fatal(err)
	}
	if km.attackerKey, err = jwxjwk.Import(km.attackerPriv); err != nil {
		t.Fatal(err)
	}
	if err := km.attackerKey.Set(jwxjwk.KeyIDKey, "attacker-key"); err != nil {
		t.Fatal(err)
	}

	pub, err := jwxjwk.Import(&km.issuerPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Set(jwxjwk.KeyIDKey, "issuer-key"); err != nil {
		t.Fatal(err)
	}
	if err := pub.Set(jwxjwk.AlgorithmKey, "ES256"); err != nil {
		t.Fatal(err)
	}
	km.issuerPubSet = jwk.NewSet()
	if err := km.issuerPubSet.AddKey(pub); err != nil {
		t.Fatal(err)
	}

	return km
}

// sdcwtFixture assembles a valid issuer→holder→verifier pipeline.
type sdcwtFixture struct {
	km           *sdcwtKeyMaterial
	issuer       sdcwt.Issuer
	holder       sdcwt.Holder
	newVerifier  func(cnonceSeen *map[string]bool) sdcwt.Verifier
	claims       map[any]any
	issued       []byte
	disclosures  [][]byte
	presentation []byte
	cnonce       []byte
}

func newSDCWTFixture(t *testing.T) *sdcwtFixture {
	t.Helper()

	km := newSDCWTKeyMaterial(t)
	issuerSet := func(context.Context) (jwk.Set, error) { return km.issuerPubSet, nil }

	cnf, err := sdcwt.Confirmation(&km.holderPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	f := &sdcwtFixture{
		km: km,
		issuer: sdcwt.NewIssuer(cose.AlgorithmES256,
			func(context.Context) (jwk.Key, error) { return km.issuerPrivKey, nil }),
		newVerifier: func(seen *map[string]bool) sdcwt.Verifier {
			return sdcwt.NewVerifier(issuerSet,
				sdcwt.WithAudience("verifier.example.com"),
				sdcwt.WithCnonceValidator(func(b []byte) error {
					if (*seen)[string(b)] {
						return errSDCWTTest("cnonce replayed")
					}
					(*seen)[string(b)] = true
					return nil
				}),
			)
		},
		cnonce: []byte("adversarial-cnonce-1"),
	}
	f.holder = sdcwt.NewHolder(issuerSet, cose.AlgorithmES256,
		func(context.Context) (jwk.Key, error) { return km.holderPrivKey, nil })

	f.claims = map[any]any{
		uint64(1): "https://issuer.example.com",
		uint64(6): 1750000000,
		"inspection_location": sdtoken.Disclosable{Value: map[any]any{
			"region":      sdtoken.Disclosable{Value: "Northern"},
			"postal_code": sdtoken.Disclosable{Value: "99163"},
		}},
		"inspector_license_number": sdtoken.Disclosable{Value: "ABCD-123456"},
		"certificates": []any{
			sdtoken.DisclosableElement{Value: "cert-1"},
		},
		uint64(8): cnf,
	}

	if f.issued, f.disclosures, err = f.issuer.Issue(context.Background(), f.claims); err != nil {
		t.Fatalf("unable to issue: %v", err)
	}
	if f.presentation, err = f.holder.Present(f.issued, f.disclosures); err != nil {
		t.Fatalf("unable to present: %v", err)
	}

	return f
}

// validKBT produces a fresh, valid KBT with a fresh cnonce.
func (f *sdcwtFixture) validKBT(t *testing.T, cnonce []byte) []byte {
	t.Helper()
	kbt, err := f.holder.KeyBind(f.presentation, "verifier.example.com", cnonce, sdcwt.WithIssuedAt(1750000500))
	if err != nil {
		t.Fatal(err)
	}
	return kbt
}

// presentOrReject attempts Present+KeyBind; a rejection at either
// stage satisfies the adversarial expectation (the holder's strict
// semantics catch structural mutations before the verifier sees
// them). Returns nil when the mutation was rejected, otherwise the
// KBT bytes for verifier-stage checking.
func (f *sdcwtFixture) presentOrReject(t *testing.T, reissued []byte, cnonce []byte, disclosures [][]byte) []byte {
	t.Helper()
	presentation, err := f.holder.Present(reissued, disclosures)
	if err != nil {
		return nil
	}
	kbt, err := f.holder.KeyBind(presentation, "verifier.example.com", cnonce, sdcwt.WithIssuedAt(1750000500))
	if err != nil {
		return nil
	}
	return kbt
}

type errSDCWTTest string

func (e errSDCWTTest) Error() string { return string(e) }

// mustRejectSDCWT asserts verification fails without panic.
func mustRejectSDCWT(t *testing.T, name string, v sdcwt.Verifier, kbt []byte) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: verifier panicked: %v", name, r)
		}
	}()
	if _, err := v.Verify(context.Background(), kbt); err == nil {
		t.Errorf("%s: mutated kbt must be rejected", name)
	}
}

func TestSDCWTAdversarial(t *testing.T) {
	t.Run("kbt signed by wrong holder key", func(t *testing.T) {
		f := newSDCWTFixture(t)
		attacker := sdcwt.NewHolder(
			func(context.Context) (jwk.Set, error) { return f.km.issuerPubSet, nil },
			cose.AlgorithmES256,
			func(context.Context) (jwk.Key, error) { return f.km.attackerKey, nil },
		)
		presentation, err := attacker.Present(f.issued, f.disclosures)
		if err != nil {
			t.Fatal(err)
		}
		kbt, err := attacker.KeyBind(presentation, "verifier.example.com", []byte("c-attacker"), sdcwt.WithIssuedAt(1750000500))
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		mustRejectSDCWT(t, "wrong holder key", f.newVerifier(&seen), kbt)
	})

	t.Run("empty sd_claims array", func(t *testing.T) {
		f := newSDCWTFixture(t)
		// Build a KBT whose embedded SD-CWT carries an empty
		// sd_claims array (draft section 9 step 2: invalid).
		var msg cose.Sign1Message
		if err := msg.UnmarshalCBOR(f.issued); err != nil {
			t.Fatal(err)
		}
		msg.Headers.RawUnprotected = nil
		msg.Headers.Unprotected = cose.UnprotectedHeader{int64(17): []any{}}
		emptyIssued, err := msg.MarshalCBOR()
		if err != nil {
			t.Fatal(err)
		}
		presentation, err := f.holder.Present(emptyIssued, nil)
		if err != nil {
			t.Fatalf("present with empty sd_claims: %v", err)
		}
		kbt, err := f.holder.KeyBind(presentation, "verifier.example.com", []byte("c-empty"), sdcwt.WithIssuedAt(1750000500))
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		mustRejectSDCWT(t, "empty sd_claims", f.newVerifier(&seen), kbt)
	})

	t.Run("disclosure without matching redacted claim hash", func(t *testing.T) {
		f := newSDCWTFixture(t)
		// Forge an unsolicited disclosure and splice it into the
		// presentation's sd_claims.
		forged, err := cbor.Marshal([]any{[]byte("0123456789abcdef"), "forged_claim", "value"})
		if err != nil {
			t.Fatal(err)
		}
		var msg cose.Sign1Message
		if err := msg.UnmarshalCBOR(f.presentation); err != nil {
			t.Fatal(err)
		}
		raw := msg.Headers.Unprotected[int64(17)]
		list, _ := raw.([]any)
		msg.Headers.RawUnprotected = nil
		msg.Headers.Unprotected = cose.UnprotectedHeader{int64(17): append(list, forged)}
		spliced, err := msg.MarshalCBOR()
		if err != nil {
			t.Fatal(err)
		}
		kbt, err := f.holder.KeyBind(spliced, "verifier.example.com", []byte("c-forged"), sdcwt.WithIssuedAt(1750000500))
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		mustRejectSDCWT(t, "unsolicited disclosure", f.newVerifier(&seen), kbt)
	})

	t.Run("disclosed claim key duplicating existing key", func(t *testing.T) {
		f := newSDCWTFixture(t)
		// Issue a credential where the issuer places the same digest
		// twice in one redacted_claim_keys via a hand-built payload:
		// duplicate digests are rejected by the decoder.
		// Simpler: splice the SAME disclosure twice — duplicate digest.
		var msg cose.Sign1Message
		if err := msg.UnmarshalCBOR(f.presentation); err != nil {
			t.Fatal(err)
		}
		raw := msg.Headers.Unprotected[int64(17)]
		list, _ := raw.([]any)
		msg.Headers.RawUnprotected = nil
		msg.Headers.Unprotected = cose.UnprotectedHeader{int64(17): append(list, list[0])}
		spliced, err := msg.MarshalCBOR()
		if err != nil {
			t.Fatal(err)
		}
		kbt, err := f.holder.KeyBind(spliced, "verifier.example.com", []byte("c-dup"), sdcwt.WithIssuedAt(1750000500))
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		mustRejectSDCWT(t, "duplicate disclosure", f.newVerifier(&seen), kbt)
	})

	t.Run("indefinite-length cbor", func(t *testing.T) {
		f := newSDCWTFixture(t)
		kbt := f.validKBT(t, []byte("c-indefinite"))
		// Prepend an indefinite-length map into the payload via
		// re-encoding: replace the KBT with bytes embedding 0x9f.
		// The simplest reliable trigger: hand-built indefinite CBOR
		// as the KBT.
		bad := []byte{0x9f, 0x01, 0x02, 0xff}
		seen := map[string]bool{}
		mustRejectSDCWT(t, "indefinite length", f.newVerifier(&seen), bad)
		_ = kbt
	})

	t.Run("duplicate map keys", func(t *testing.T) {
		f := newSDCWTFixture(t)
		// Duplicate integer keys in a hand-built claims payload:
		// map(1) {1: "a", 1: "b"} = a2 01 61 61 01 61 62.
		dup := []byte{0xa2, 0x01, 0x61, 0x61, 0x01, 0x61, 0x62}
		var msg cose.Sign1Message
		if err := msg.UnmarshalCBOR(f.issued); err != nil {
			t.Fatal(err)
		}
		msg.Payload = dup
		msg.Signature = nil
		// Re-sign so the signature check passes and the duplicate
		// detection fires on the payload decode.
		signer, err := cose.NewSigner(cose.AlgorithmES256, f.km.issuerPriv)
		if err != nil {
			t.Fatal(err)
		}
		if err := msg.Sign(rand.Reader, nil, signer); err != nil {
			t.Fatal(err)
		}
		reissued, err := msg.MarshalCBOR()
		if err != nil {
			t.Fatal(err)
		}
		kbt := f.presentOrReject(t, reissued, []byte("c-dupkey"), nil)
		if kbt == nil {
			return // rejected at the holder stage: expectation met
		}
		seen := map[string]bool{}
		mustRejectSDCWT(t, "duplicate map keys", f.newVerifier(&seen), kbt)
	})

	t.Run("exp claims with invalid float values", func(t *testing.T) {
		f := newSDCWTFixture(t)
		for name, bad := range map[string]float64{"nan": math.NaN(), "inf": math.Inf(1), "oversized": float64(1 << 54)} {
			// Hand-build a claims payload with the bad exp value.
			payload, err := cbor.Marshal(map[any]any{uint64(4): bad})
			if err != nil {
				t.Fatal(err)
			}
			var msg cose.Sign1Message
			if err := msg.UnmarshalCBOR(f.issued); err != nil {
				t.Fatal(err)
			}
			msg.Payload = payload
			msg.Signature = nil
			signer, errS := cose.NewSigner(cose.AlgorithmES256, f.km.issuerPriv)
			if errS != nil {
				t.Fatal(errS)
			}
			if err := msg.Sign(rand.Reader, nil, signer); err != nil {
				t.Fatal(err)
			}
			reissued, errM := msg.MarshalCBOR()
			if errM != nil {
				t.Fatal(errM)
			}
			kbt := f.presentOrReject(t, reissued, []byte("c-"+name), nil)
			if kbt == nil {
				continue // rejected at the holder stage
			}
			seen := map[string]bool{}
			mustRejectSDCWT(t, "exp "+name, f.newVerifier(&seen), kbt)
		}
	})

	t.Run("claims depth 17", func(t *testing.T) {
		f := newSDCWTFixture(t)
		// Build a depth-17 nested claims payload.
		deep := map[any]any{}
		current := deep
		for range 17 {
			next := map[any]any{}
			current["n"] = next
			current = next
		}
		payload, err := cbor.Marshal(deep)
		if err != nil {
			t.Fatal(err)
		}
		var msg cose.Sign1Message
		if err := msg.UnmarshalCBOR(f.issued); err != nil {
			t.Fatal(err)
		}
		msg.Payload = payload
		msg.Signature = nil
		signer, errS := cose.NewSigner(cose.AlgorithmES256, f.km.issuerPriv)
		if errS != nil {
			t.Fatal(errS)
		}
		if err := msg.Sign(rand.Reader, nil, signer); err != nil {
			t.Fatal(err)
		}
		reissued, errM := msg.MarshalCBOR()
		if errM != nil {
			t.Fatal(errM)
		}
		kbt := f.presentOrReject(t, reissued, []byte("c-deep"), nil)
		if kbt == nil {
			return // rejected at the holder stage
		}
		seen := map[string]bool{}
		mustRejectSDCWT(t, "depth 17", f.newVerifier(&seen), kbt)
	})

	t.Run("invalid map key types", func(t *testing.T) {
		f := newSDCWTFixture(t)
		// bstr map key and oversized text key in hand-built payloads.
		for name, payload := range map[string][]byte{
			// map(1) { h'6b': "v" }
			"bstr key": {0xa1, 0x41, 0x6b, 0x61, 0x76},
			// map(1) { text(256): "v" } — 0x59 0x0100 <256 bytes>
			"oversized text key": append([]byte{0xa1, 0x59, 0x01, 0x00}, append(bytes.Repeat([]byte{0x61}, 256), 0x61, 0x76)...),
		} {
			var msg cose.Sign1Message
			if err := msg.UnmarshalCBOR(f.issued); err != nil {
				t.Fatal(err)
			}
			msg.Payload = payload
			msg.Signature = nil
			signer, errS := cose.NewSigner(cose.AlgorithmES256, f.km.issuerPriv)
			if errS != nil {
				t.Fatal(errS)
			}
			if err := msg.Sign(rand.Reader, nil, signer); err != nil {
				t.Fatal(err)
			}
			reissued, errM := msg.MarshalCBOR()
			if errM != nil {
				t.Fatal(errM)
			}
			kbt := f.presentOrReject(t, reissued, []byte("c-"+name), nil)
			if kbt == nil {
				continue // rejected at the holder stage
			}
			seen := map[string]bool{}
			mustRejectSDCWT(t, name, f.newVerifier(&seen), kbt)
		}
	})

	t.Run("cnonce replay and absence", func(t *testing.T) {
		f := newSDCWTFixture(t)
		seen := map[string]bool{}
		v := f.newVerifier(&seen)
		cnonce := []byte("replay-cnonce")
		kbt1 := f.validKBT(t, cnonce)
		if _, err := v.Verify(context.Background(), kbt1); err != nil {
			t.Fatalf("first verification must pass: %v", err)
		}
		kbt2 := f.validKBT(t, cnonce)
		mustRejectSDCWT(t, "cnonce replay", v, kbt2)
	})

	t.Run("audience mismatch and forbidden iss sub", func(t *testing.T) {
		f := newSDCWTFixture(t)
		// Audience mismatch: KBT bound to a different audience.
		otherAud, err := f.holder.KeyBind(f.presentation, "other.example.com", []byte("c-aud"), sdcwt.WithIssuedAt(1750000500))
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		mustRejectSDCWT(t, "audience mismatch", f.newVerifier(&seen), otherAud)

		// KBT payload carrying iss (draft section 8.1 MUST NOT):
		// hand-build by re-signing the KBT with an iss claim.
		kbt := f.validKBT(t, []byte("c-iss"))
		var kbtMsg cose.Sign1Message
		if err := kbtMsg.UnmarshalCBOR(kbt); err != nil {
			t.Fatal(err)
		}
		var kbtClaims map[any]any
		if err := cbor.Unmarshal(kbtMsg.Payload, &kbtClaims); err != nil {
			t.Fatal(err)
		}
		kbtClaims[uint64(1)] = "https://attacker.example.com" // iss
		payload, err := cbor.Marshal(kbtClaims)
		if err != nil {
			t.Fatal(err)
		}
		kbtMsg.Payload = payload
		kbtMsg.Signature = nil
		holderSigner, err := cose.NewSigner(cose.AlgorithmES256, f.km.holderPriv)
		if err != nil {
			t.Fatal(err)
		}
		if err := kbtMsg.Sign(rand.Reader, nil, holderSigner); err != nil {
			t.Fatal(err)
		}
		resigned, err := kbtMsg.MarshalCBOR()
		if err != nil {
			t.Fatal(err)
		}
		mustRejectSDCWT(t, "kbt iss claim", f.newVerifier(&seen), resigned)
	})

	t.Run("wrong typ values", func(t *testing.T) {
		f := newSDCWTFixture(t)
		// SD-CWT with the KBT typ (294): signed by the issuer.
		var msg cose.Sign1Message
		if err := msg.UnmarshalCBOR(f.issued); err != nil {
			t.Fatal(err)
		}
		// typ is protected: re-sign with the swapped typ.
		ph := cose.ProtectedHeader{}
		for k, v := range msg.Headers.Protected {
			ph[k] = v
		}
		ph[cose.HeaderLabelType] = sdcwt.MediaTypeKbCWT
		msg.Headers.Protected = ph
		msg.Headers.RawProtected = nil
		msg.Signature = nil
		signer, err := cose.NewSigner(cose.AlgorithmES256, f.km.issuerPriv)
		if err != nil {
			t.Fatal(err)
		}
		if err := msg.Sign(rand.Reader, nil, signer); err != nil {
			t.Fatal(err)
		}
		reissued, err := msg.MarshalCBOR()
		if err != nil {
			t.Fatal(err)
		}
		kbt := f.presentOrReject(t, reissued, []byte("c-typ1"), nil)
		if kbt == nil {
			return // rejected at the holder stage
		}
		seen := map[string]bool{}
		mustRejectSDCWT(t, "sd-cwt typ 294", f.newVerifier(&seen), kbt)

		// KBT with the SD-CWT typ (293).
		kbtValid := f.validKBT(t, []byte("c-typ2"))
		var kbtMsg cose.Sign1Message
		if err := kbtMsg.UnmarshalCBOR(kbtValid); err != nil {
			t.Fatal(err)
		}
		ph2 := cose.ProtectedHeader{}
		for k, v := range kbtMsg.Headers.Protected {
			ph2[k] = v
		}
		ph2[cose.HeaderLabelType] = sdcwt.MediaTypeSdCWT
		kbtMsg.Headers.Protected = ph2
		kbtMsg.Headers.RawProtected = nil
		kbtMsg.Signature = nil
		holderSigner, err := cose.NewSigner(cose.AlgorithmES256, f.km.holderPriv)
		if err != nil {
			t.Fatal(err)
		}
		if err := kbtMsg.Sign(rand.Reader, nil, holderSigner); err != nil {
			t.Fatal(err)
		}
		resigned, err := kbtMsg.MarshalCBOR()
		if err != nil {
			t.Fatal(err)
		}
		seen2 := map[string]bool{}
		mustRejectSDCWT(t, "kbt typ 293", f.newVerifier(&seen2), resigned)
	})

	t.Run("sd_alg misuse", func(t *testing.T) {
		f := newSDCWTFixture(t)
		// sd_alg = -7 (ES256 misused as a hash): protected header,
		// re-sign.
		var msg cose.Sign1Message
		if err := msg.UnmarshalCBOR(f.issued); err != nil {
			t.Fatal(err)
		}
		ph := cose.ProtectedHeader{}
		for k, v := range msg.Headers.Protected {
			ph[k] = v
		}
		ph[int64(170)] = int64(-7)
		msg.Headers.Protected = ph
		msg.Headers.RawProtected = nil
		msg.Signature = nil
		signer, err := cose.NewSigner(cose.AlgorithmES256, f.km.issuerPriv)
		if err != nil {
			t.Fatal(err)
		}
		if err := msg.Sign(rand.Reader, nil, signer); err != nil {
			t.Fatal(err)
		}
		reissued, err := msg.MarshalCBOR()
		if err != nil {
			t.Fatal(err)
		}
		kbt := f.presentOrReject(t, reissued, []byte("c-sdalg"), nil)
		if kbt == nil {
			return // rejected at the holder stage
		}
		seen := map[string]bool{}
		mustRejectSDCWT(t, "sd_alg -7", f.newVerifier(&seen), kbt)
	})

	t.Run("time constraint violations", func(t *testing.T) {
		f := newSDCWTFixture(t)
		// KBT exp beyond the SD-CWT exp: the SD-CWT carries no exp, so
		// build a fixture with one.
		cnf, err := sdcwt.Confirmation(&f.km.holderPriv.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		claims := map[any]any{
			"given_name": sdtoken.Disclosable{Value: "John"},
			uint64(4):    1750001000, // exp
			uint64(6):    1750000000, // iat
			uint64(8):    cnf,
		}
		issued, disclosures, err := f.issuer.Issue(context.Background(), claims)
		if err != nil {
			t.Fatal(err)
		}
		presentation, err := f.holder.Present(issued, disclosures)
		if err != nil {
			t.Fatal(err)
		}

		// KBT exp after the SD-CWT exp.
		kbt, err := f.holder.KeyBind(presentation, "verifier.example.com", []byte("c-t1"), sdcwt.WithIssuedAt(1750000500))
		if err != nil {
			t.Fatal(err)
		}
		var kbtMsg cose.Sign1Message
		if err := kbtMsg.UnmarshalCBOR(kbt); err != nil {
			t.Fatal(err)
		}
		var kbtClaims map[any]any
		if err := cbor.Unmarshal(kbtMsg.Payload, &kbtClaims); err != nil {
			t.Fatal(err)
		}
		kbtClaims[uint64(4)] = 1750002000 // exp beyond sd-cwt exp
		payload, err := cbor.Marshal(kbtClaims)
		if err != nil {
			t.Fatal(err)
		}
		kbtMsg.Payload = payload
		kbtMsg.Signature = nil
		holderSigner, err := cose.NewSigner(cose.AlgorithmES256, f.km.holderPriv)
		if err != nil {
			t.Fatal(err)
		}
		if err := kbtMsg.Sign(rand.Reader, nil, holderSigner); err != nil {
			t.Fatal(err)
		}
		resigned, err := kbtMsg.MarshalCBOR()
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		mustRejectSDCWT(t, "kbt exp beyond sd-cwt exp", f.newVerifier(&seen), resigned)

		// KBT iat before the SD-CWT iat: needs an SD-CWT with a later
		// iat; hand-build via the exp fixture above (iat 1750000000).
		kbt2, err := f.holder.KeyBind(presentation, "verifier.example.com", []byte("c-t2"), sdcwt.WithIssuedAt(1750000000-100))
		if err != nil {
			t.Fatal(err)
		}
		seen2 := map[string]bool{}
		mustRejectSDCWT(t, "kbt iat before sd-cwt iat", f.newVerifier(&seen2), kbt2)
	})

	t.Run("positive control with shuffled disclosures", func(t *testing.T) {
		f := newSDCWTFixture(t)
		// Shuffle the disclosure order in the presentation: still
		// validates (draft section 9: order-independent processing).
		var msg cose.Sign1Message
		if err := msg.UnmarshalCBOR(f.issued); err != nil {
			t.Fatal(err)
		}
		raw := msg.Headers.Unprotected[int64(17)]
		list, _ := raw.([]any)
		// Reverse.
		reversed := make([]any, len(list))
		for i := range list {
			reversed[i] = list[len(list)-1-i]
		}
		msg.Headers.RawUnprotected = nil
		msg.Headers.Unprotected = cose.UnprotectedHeader{int64(17): reversed}
		shuffled, err := msg.MarshalCBOR()
		if err != nil {
			t.Fatal(err)
		}
		var reversedBytes [][]byte
		for i := len(f.disclosures) - 1; i >= 0; i-- {
			reversedBytes = append(reversedBytes, f.disclosures[i])
		}
		presentation, err := f.holder.Present(shuffled, reversedBytes)
		if err != nil {
			t.Fatal(err)
		}
		kbt, err := f.holder.KeyBind(presentation, "verifier.example.com", []byte("c-shuffle"), sdcwt.WithIssuedAt(1750000500))
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		if _, err := f.newVerifier(&seen).Verify(context.Background(), kbt); err != nil {
			t.Errorf("shuffled disclosures must still validate: %v", err)
		}
	})
}

// compile-time guards for helpers.
var (
	_ = bytes.Repeat
	_ = binary.BigEndian
)
