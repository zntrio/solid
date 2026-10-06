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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/sdtoken"
	"zntr.io/solid/sdk/sdtoken/sdjwt"
	"zntr.io/solid/sdk/token"
	"zntr.io/solid/sdk/token/jwt"
)

// sdjwtKeyMaterial generates issuer and holder key material for the
// adversarial SD-JWT scenarios.
type sdjwtKeyMaterial struct {
	issuerPriv    *ecdsa.PrivateKey
	issuerPrivKey jwk.Key
	issuerPubSet  jwk.Set
	holderPriv    *ecdsa.PrivateKey
	holderPrivKey jwk.Key
	holderClaim   map[string]any
	attackerPriv  *ecdsa.PrivateKey
	attackerKey   jwk.Key
}

func newSDJWTKeyMaterial(t *testing.T) *sdjwtKeyMaterial {
	t.Helper()

	km := &sdjwtKeyMaterial{}

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

	// Issuer public key set.
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

	// Holder public key as the cnf.jwk claim value.
	holderPub, err := jwxjwk.Import(&km.holderPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := holderPub.Set(jwxjwk.KeyIDKey, "holder-key"); err != nil {
		t.Fatal(err)
	}
	if err := holderPub.Set(jwxjwk.AlgorithmKey, "ES256"); err != nil {
		t.Fatal(err)
	}
	pubJSON, err := json.Marshal(holderPub)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(pubJSON, &km.holderClaim); err != nil {
		t.Fatal(err)
	}

	return km
}

// sdjwtFixture assembles a full valid SD-JWT+KB presentation for
// mutation-based adversarial testing.
type sdjwtFixture struct {
	km           *sdjwtKeyMaterial
	issuer       sdjwt.Issuer
	holder       sdjwt.Holder
	verifier     sdjwt.Verifier
	claims       map[string]any
	issued       string
	disclosures  []string
	presentation string
	sdJWT        string
	kb           string
	nonce        string
	nonces       map[string]bool
}

func newSDJWTFixture(t *testing.T) *sdjwtFixture {
	t.Helper()

	km := newSDJWTKeyMaterial(t)

	issuerVerifier := jwt.DefaultVerifier(
		func(context.Context) (jwk.Set, error) { return km.issuerPubSet, nil },
		jwt.SupportedSignAlgorithms(),
	)

	f := &sdjwtFixture{
		km: km,
		issuer: sdjwt.NewIssuer(jwt.RawTypedSigner("vc+sd-jwt", "ES256",
			func(context.Context) (jwk.Key, error) { return km.issuerPrivKey, nil })),
		holder: sdjwt.NewHolder(issuerVerifier,
			jwt.RawTypedSigner(sdjwt.TypeKeyBinding, "ES256",
				func(context.Context) (jwk.Key, error) { return km.holderPrivKey, nil })),
		nonce:  "adversarial-nonce-1",
		nonces: map[string]bool{},
	}
	f.verifier = sdjwt.NewVerifier(issuerVerifier,
		sdjwt.WithAudience("verifier.example.com"),
		sdjwt.WithNonceValidator(func(n string) error {
			if f.nonces[n] {
				return errSDJWTTest("nonce replayed")
			}
			f.nonces[n] = true
			return nil
		}),
	)

	f.claims = map[string]any{
		"iss":         "https://issuer.example.com",
		"iat":         time.Now().Unix(),
		"sub":         "6c5c0a49-b589-431d-bae7-219122a9ec2c",
		"given_name":  sdtoken.Disclosable{Value: "John"},
		"family_name": sdtoken.Disclosable{Value: "Doe"},
		"address": sdtoken.Disclosable{Value: map[string]any{
			"street_address": sdtoken.Disclosable{Value: "123 Main St"},
			"locality":       sdtoken.Disclosable{Value: "Anytown"},
		}},
		"nationalities": []any{
			sdtoken.DisclosableElement{Value: "US"},
			sdtoken.DisclosableElement{Value: "DE"},
		},
		"cnf": map[string]any{"jwk": km.holderClaim},
	}

	var err error
	if f.issued, f.disclosures, err = f.issuer.Issue(context.Background(), f.claims); err != nil {
		t.Fatalf("unable to issue: %v", err)
	}

	// Locate disclosures by claim key.
	byKey := map[string]string{}
	for _, d := range f.disclosures {
		parsed, _, errP := sdjwtParseDisclosureForTest(t, d)
		if errP != nil {
			t.Fatal(errP)
		}
		if parsed != "" {
			byKey[parsed] = d
		}
	}

	// Present everything (full chain) — simplest valid baseline.
	if f.presentation, err = f.holder.Present(context.Background(), f.issued, f.disclosures...); err != nil {
		t.Fatalf("unable to present: %v", err)
	}
	if f.kb, err = f.holder.KeyBind(context.Background(), f.presentation, f.nonce, "verifier.example.com", time.Now().Unix()); err != nil {
		t.Fatalf("unable to key bind: %v", err)
	}

	return f
}

// sdjwtParseDisclosureForTest decodes a disclosure and returns its
// claim key ("" for the element form).
func sdjwtParseDisclosureForTest(t *testing.T, d string) (string, base64Info, error) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(d)
	if err != nil {
		return "", "", err
	}
	var arr []any
	if err := json.Unmarshal(raw, &arr); err != nil {
		return "", "", err
	}
	if len(arr) == 3 {
		if k, ok := arr[1].(string); ok {
			return k, "", nil
		}
	}
	return "", "", nil
}

type base64Info = string

type errSDJWTTest string

func (e errSDJWTTest) Error() string { return string(e) }

// mustReject asserts the verification fails without panic.
func mustReject(t *testing.T, name string, v sdjwt.Verifier, presentation string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: verifier panicked: %v", name, r)
		}
	}()
	if _, err := v.Verify(context.Background(), presentation); err == nil {
		t.Errorf("%s: mutated presentation must be rejected", name)
	}
}

func TestSDJWTAdversarial(t *testing.T) {
	t.Run("tampered disclosure claim value", func(t *testing.T) {
		f := newSDJWTFixture(t)
		// Tamper the first disclosure: change its claim value. The
		// digest no longer matches the redaction site in the issuer
		// JWT, so the holder must reject it (RFC 9901 section 9.2).
		raw, _ := base64.RawURLEncoding.DecodeString(f.disclosures[0])
		var arr []any
		_ = json.Unmarshal(raw, &arr)
		if len(arr) == 3 {
			arr[2] = "tampered-value"
		} else {
			arr[len(arr)-1] = "tampered-value"
		}
		tampered := base64.RawURLEncoding.EncodeToString(mustJSON(t, arr))
		var selected []string
		selected = append(selected, f.disclosures[1:]...)
		if _, err := f.holder.Present(context.Background(), f.issued, append(selected, tampered)...); err == nil {
			t.Error("holder must reject a tampered disclosure")
		}
	})

	t.Run("extra disclosure not in sd-jwt", func(t *testing.T) {
		f := newSDJWTFixture(t)
		// Build a valid-shaped disclosure that was never issued.
		forged := base64.RawURLEncoding.EncodeToString(mustJSON(t, []any{"extra-salt-123", "extra_claim", "value"}))
		// Present the issued chain plus the forged disclosure.
		presentation, err := f.holder.Present(context.Background(), f.issued, f.disclosures...)
		if err != nil {
			t.Fatal(err)
		}
		// Splice the forged disclosure in.
		spliced := presentation[:len(presentation)-1] + "~" + forged + "~"
		kb, err := f.holder.KeyBind(context.Background(), spliced, "nonce-t2", "verifier.example.com", time.Now().Unix())
		if err != nil {
			t.Fatal(err)
		}
		mustReject(t, "extra disclosure", f.verifier, kb)
	})

	t.Run("same disclosure presented twice", func(t *testing.T) {
		f := newSDJWTFixture(t)
		dup := append(append([]string{}, f.disclosures...), f.disclosures[0])
		if _, err := f.holder.Present(context.Background(), f.issued, dup...); err == nil {
			t.Error("duplicate disclosure must be rejected at present time")
		}
	})

	t.Run("forged kb-jwt with different holder key", func(t *testing.T) {
		f := newSDJWTFixture(t)
		issuerVerifier := jwt.DefaultVerifier(
			func(context.Context) (jwk.Set, error) { return f.km.issuerPubSet, nil },
			jwt.SupportedSignAlgorithms(),
		)
		attackerHolder := sdjwt.NewHolder(issuerVerifier,
			jwt.RawTypedSigner(sdjwt.TypeKeyBinding, "ES256",
				func(context.Context) (jwk.Key, error) { return f.km.attackerKey, nil }))
		kb, err := attackerHolder.KeyBind(context.Background(), f.presentation, "nonce-t4", "verifier.example.com", time.Now().Unix())
		if err != nil {
			t.Fatal(err)
		}
		mustReject(t, "forged kb-jwt", f.verifier, kb)
	})

	t.Run("sd_hash over different disclosure subset", func(t *testing.T) {
		f := newSDJWTFixture(t)
		// f.kb carries sd_hash over the full presentation. Swap the
		// SD-JWT part for a half-disclosure presentation: the KB-JWT
		// signature stays valid (it is an independent JWT) but the
		// sd_hash check fails.
		half := f.disclosures[:len(f.disclosures)/2]
		other, err := f.holder.Present(context.Background(), f.issued, half...)
		if err != nil {
			t.Fatal(err)
		}
		// Splice: other's SD-JWT part + f's KB-JWT.
		parsed, err := sdjwt.Parse(f.kb)
		if err != nil {
			t.Fatal(err)
		}
		otherParsed, err := sdjwt.Parse(other)
		if err != nil {
			t.Fatal(err)
		}
		swapped := otherParsed
		swapped.KeyBindingJWT = parsed.KeyBindingJWT
		mustReject(t, "sd_hash mismatch", f.verifier, swapped.Serialize())
	})

	t.Run("kb nonce replay", func(t *testing.T) {
		f := newSDJWTFixture(t)
		// f.kb was already verified with f.nonce? No: it was created
		// but not verified. Verify twice with the same nonce.
		if _, err := f.verifier.Verify(context.Background(), f.kb); err != nil {
			t.Fatalf("first verification must pass: %v", err)
		}
		mustReject(t, "nonce replay", f.verifier, f.kb)
	})

	t.Run("kb required but absent", func(t *testing.T) {
		f := newSDJWTFixture(t)
		mustReject(t, "no kb-jwt", f.verifier, f.presentation)
	})

	t.Run("unsigned issuer jwt", func(t *testing.T) {
		f := newSDJWTFixture(t)
		// alg:none unsigned issuer JWT.
		header := base64.RawURLEncoding.EncodeToString(mustJSON(t, map[string]any{"alg": "none", "typ": "vc+sd-jwt"}))
		payload := base64.RawURLEncoding.EncodeToString(mustJSON(t, map[string]any{"iss": "x", "_sd_alg": "sha-256"}))
		unsigned := header + "." + payload + "."
		mustReject(t, "alg none", f.verifier, unsigned+"~"+f.kb[len(f.kb)-100:])
	})

	t.Run("recursive disclosure child without parent", func(t *testing.T) {
		f := newSDJWTFixture(t)
		// Present only the nested street_address disclosure without
		// its enclosing address disclosure.
		var street string
		for _, d := range f.disclosures {
			key, _, err := sdjwtParseDisclosureForTest(t, d)
			if err != nil {
				t.Fatal(err)
			}
			if key == "street_address" {
				street = d
			}
		}
		if street == "" {
			t.Fatal("street_address disclosure not found")
		}
		presentation, err := f.holder.Present(context.Background(), f.issued, street)
		if err == nil {
			// Holder-side Present rejects unreferenced disclosures;
			// if it accepted, the verifier must reject.
			kb, errKb := f.holder.KeyBind(context.Background(), presentation, "nonce-t9", "verifier.example.com", time.Now().Unix())
			if errKb != nil {
				t.Fatal(errKb)
			}
			mustReject(t, "child without parent", f.verifier, kb)
		}
	})

	t.Run("forged disclosure colliding with plaintext claim", func(t *testing.T) {
		f := newSDJWTFixture(t)
		// A forged disclosure claiming the plaintext "iss" key: its
		// digest matches no redaction site (the attacker cannot
		// produce a digest collision), so it is unreferenced and the
		// presentation is rejected. Should its digest ever match a
		// site, the insertion path rejects the key collision
		// separately (sdk/sdtoken ErrClaimCollision, unit-tested).
		forged := base64.RawURLEncoding.EncodeToString(mustJSON(t, []any{"collision-salt", "iss", "https://attacker.example.com"}))
		// Rebuild the presentation: all issued disclosures plus the
		// forged one spliced in after the holder's legitimate build.
		kb, err := f.holder.KeyBind(context.Background(), f.presentation, "nonce-t10", "verifier.example.com", time.Now().Unix())
		if err != nil {
			t.Fatal(err)
		}
		// Splice the forged disclosure into the SD-JWT part, before
		// the KB-JWT.
		parsed, err := sdjwt.Parse(kb)
		if err != nil {
			t.Fatal(err)
		}
		parsed.Disclosures = append(parsed.Disclosures, forged)
		mustReject(t, "claim collision", f.verifier, parsed.Serialize())
	})

	t.Run("kb iat outside freshness window", func(t *testing.T) {
		f := newSDJWTFixture(t)
		stale, err := f.holder.KeyBind(context.Background(), f.presentation, "nonce-t11", "verifier.example.com", time.Now().Add(-10*time.Minute).Unix())
		if err != nil {
			t.Fatal(err)
		}
		mustReject(t, "stale kb iat", f.verifier, stale)
	})

	t.Run("invalid typ values", func(t *testing.T) {
		f := newSDJWTFixture(t)
		// Issuer JWT with a non-sd-jwt typ.
		plainIssuer := sdjwt.NewIssuer(jwt.RawTypedSigner("jwt", "ES256",
			func(context.Context) (jwk.Key, error) { return f.km.issuerPrivKey, nil }))
		issued, _, err := plainIssuer.Issue(context.Background(), map[string]any{"iss": "x"})
		if err != nil {
			t.Fatal(err)
		}
		mustReject(t, "issuer typ", f.verifier, issued+"~")

		// KB-JWT with a typ other than kb+jwt.
		wrongKB := sdjwt.NewHolder(jwt.DefaultVerifier(
			func(context.Context) (jwk.Set, error) { return f.km.issuerPubSet, nil },
			jwt.SupportedSignAlgorithms(),
		), jwt.RawTypedSigner("other+jwt", "ES256",
			func(context.Context) (jwk.Key, error) { return f.km.holderPrivKey, nil }))
		kb, err := wrongKB.KeyBind(context.Background(), f.presentation, "nonce-t12", "verifier.example.com", time.Now().Unix())
		if err != nil {
			t.Fatal(err)
		}
		mustReject(t, "kb typ", f.verifier, kb)
	})

	t.Run("unsupported _sd_alg", func(t *testing.T) {
		f := newSDJWTFixture(t)
		// Hand-build an issuer JWT with _sd_alg sha-512.
		header := base64.RawURLEncoding.EncodeToString(mustJSON(t, map[string]any{"alg": "ES256", "typ": "vc+sd-jwt", "kid": "issuer-key"}))
		payload := base64.RawURLEncoding.EncodeToString(mustJSON(t, map[string]any{"_sd_alg": "sha-512"}))
		signing := header + "." + payload
		sig, err := ecdaSign(f.km.issuerPriv, signing)
		if err != nil {
			t.Fatal(err)
		}
		signed := signing + "." + base64.RawURLEncoding.EncodeToString(sig)
		mustReject(t, "sha-512", f.verifier, signed+"~")
	})

	t.Run("truncated trailing tilde", func(t *testing.T) {
		f := newSDJWTFixture(t)
		// Drop the trailing "~" from the presentation.
		truncated := f.presentation[:len(f.presentation)-1]
		mustReject(t, "truncated", f.verifier, truncated)
	})

	t.Run("malformed split", func(t *testing.T) {
		f := newSDJWTFixture(t)
		// Append garbage after the KB-JWT.
		mustReject(t, "trailing garbage", f.verifier, f.kb+"~garbage")
	})
}

// sdjwtRebind key-binds an arbitrary presentation with a fresh nonce.
func sdjwtRebind(f *sdjwtFixture, presentation, nonce string) string {
	t := f.presentation // placeholder to access t via closure is not possible
	_ = t
	kb, err := f.holder.KeyBind(context.Background(), presentation, nonce, "verifier.example.com", time.Now().Unix())
	if err != nil {
		return ""
	}
	return kb
}

func ecdaSign(priv *ecdsa.PrivateKey, data string) ([]byte, error) {
	sum := sha256.Sum256([]byte(data))
	r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		return nil, err
	}
	return append(pad32(r.Bytes()), pad32(s.Bytes())...), nil
}

func pad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// compile-time guard: the fixture uses the exported role constructors.
var (
	_ token.Signer = jwt.RawTypedSigner("vc+sd-jwt", "ES256", nil)
	_              = strings.HasPrefix
)
