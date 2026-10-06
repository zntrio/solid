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

package sdjwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/sdtoken"
	"zntr.io/solid/sdk/token/jwt"
)

// benchKeyMaterial builds the issuer/holder key material once per
// benchmark run.
type benchKeyMaterial struct {
	issuerKP  jwk.KeyProviderFunc
	issuerSet jwk.KeySetProviderFunc
	holderKP  jwk.KeyProviderFunc
	holderCnf map[string]any
}

func newBenchKeyMaterial(b *testing.B) *benchKeyMaterial {
	b.Helper()

	issuerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	holderPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	issuerKey, err := jwxjwk.Import(issuerPriv)
	if err != nil {
		b.Fatal(err)
	}
	if err := issuerKey.Set(jwxjwk.KeyIDKey, "issuer-key"); err != nil {
		b.Fatal(err)
	}
	holderKey, err := jwxjwk.Import(holderPriv)
	if err != nil {
		b.Fatal(err)
	}
	if err := holderKey.Set(jwxjwk.KeyIDKey, "holder-key"); err != nil {
		b.Fatal(err)
	}

	issuerPub, err := jwxjwk.Import(&issuerPriv.PublicKey)
	if err != nil {
		b.Fatal(err)
	}
	if err := issuerPub.Set(jwxjwk.KeyIDKey, "issuer-key"); err != nil {
		b.Fatal(err)
	}
	if err := issuerPub.Set(jwxjwk.AlgorithmKey, "ES256"); err != nil {
		b.Fatal(err)
	}
	set := jwk.NewSet()
	if err := set.AddKey(issuerPub); err != nil {
		b.Fatal(err)
	}

	holderPub, err := jwxjwk.Import(&holderPriv.PublicKey)
	if err != nil {
		b.Fatal(err)
	}
	if err := holderPub.Set(jwxjwk.KeyIDKey, "holder-key"); err != nil {
		b.Fatal(err)
	}
	if err := holderPub.Set(jwxjwk.AlgorithmKey, "ES256"); err != nil {
		b.Fatal(err)
	}
	pubJSON, err := json.Marshal(holderPub)
	if err != nil {
		b.Fatal(err)
	}
	cnf := map[string]any{}
	if err := json.Unmarshal(pubJSON, &cnf); err != nil {
		b.Fatal(err)
	}

	return &benchKeyMaterial{
		issuerKP:  func(context.Context) (jwk.Key, error) { return issuerKey, nil },
		issuerSet: func(context.Context) (jwk.Set, error) { return set, nil },
		holderKP:  func(context.Context) (jwk.Key, error) { return holderKey, nil },
		holderCnf: cnf,
	}
}

func benchClaims(km *benchKeyMaterial) map[string]any {
	return map[string]any{
		"iss":         "https://issuer.example.com",
		"sub":         "subject-123",
		"iat":         time.Now().Unix(),
		"given_name":  sdtoken.Disclosable{Value: "John"},
		"family_name": sdtoken.Disclosable{Value: "Doe"},
		"address": sdtoken.Disclosable{Value: map[string]any{
			"street_address": sdtoken.Disclosable{Value: "123 Main St"},
			"locality":       sdtoken.Disclosable{Value: "Anytown"},
			"region":         sdtoken.Disclosable{Value: "Anystate"},
		}},
		"nationalities": []any{
			sdtoken.DisclosableElement{Value: "US"},
			sdtoken.DisclosableElement{Value: "DE"},
		},
		"cnf": map[string]any{"jwk": km.holderCnf},
	}
}

func BenchmarkSDJWTIssue(b *testing.B) {
	km := newBenchKeyMaterial(b)
	iss := NewIssuer(jwt.RawTypedSigner("vc+sd-jwt", "ES256", km.issuerKP))
	ctx := context.Background()
	b.ResetTimer()
	for b.Loop() {
		claims := benchClaims(km)
		if _, _, err := iss.Issue(ctx, claims); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSDJWTPresent(b *testing.B) {
	km := newBenchKeyMaterial(b)
	iss := NewIssuer(jwt.RawTypedSigner("vc+sd-jwt", "ES256", km.issuerKP))
	issuerVerifier := jwt.DefaultVerifier(km.issuerSet, jwt.SupportedSignAlgorithms())
	hold := NewHolder(issuerVerifier, jwt.RawTypedSigner(TypeKeyBinding, "ES256", km.holderKP))

	issued, disclosures, err := iss.Issue(context.Background(), benchClaims(km))
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		if _, err := hold.Present(context.Background(), issued, disclosures...); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSDJWTVerify(b *testing.B) {
	km := newBenchKeyMaterial(b)
	iss := NewIssuer(jwt.RawTypedSigner("vc+sd-jwt", "ES256", km.issuerKP))
	issuerVerifier := jwt.DefaultVerifier(km.issuerSet, jwt.SupportedSignAlgorithms())
	hold := NewHolder(issuerVerifier, jwt.RawTypedSigner(TypeKeyBinding, "ES256", km.holderKP))
	v := NewVerifier(issuerVerifier,
		WithAudience("verifier.example.com"),
		WithNonceValidator(func(string) error { return nil }),
	)

	issued, disclosures, err := iss.Issue(context.Background(), benchClaims(km))
	if err != nil {
		b.Fatal(err)
	}
	presentation, err := hold.Present(context.Background(), issued, disclosures...)
	if err != nil {
		b.Fatal(err)
	}
	kb, err := hold.KeyBind(context.Background(), presentation, "bench-nonce", "verifier.example.com", time.Now().Unix())
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	b.ResetTimer()
	for b.Loop() {
		if _, err := v.Verify(ctx, kb); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSDJWTParse(b *testing.B) {
	km := newBenchKeyMaterial(b)
	iss := NewIssuer(jwt.RawTypedSigner("vc+sd-jwt", "ES256", km.issuerKP))
	issued, _, err := iss.Issue(context.Background(), benchClaims(km))
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		if _, err := Parse(issued); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSDJWTDecodeDisclosure(b *testing.B) {
	// RFC 9901 section 4.2.3 vector.
	d := "WyIyR0xDNDJzS1Z2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
	b.ResetTimer()
	for b.Loop() {
		if _, err := decodeDisclosure(d); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSDJWTEncodeDisclosure(b *testing.B) {
	salt := make([]byte, 16)
	b.ResetTimer()
	for b.Loop() {
		if _, _, err := encodeDisclosure(salt, "given_name", "John"); err != nil {
			b.Fatal(err)
		}
	}
}

var _ = base64.RawURLEncoding
