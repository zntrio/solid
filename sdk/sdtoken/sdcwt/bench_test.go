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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/veraison/go-cose"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/sdtoken"
)

type sdcwtBenchMaterial struct {
	issuerKP  jwk.KeyProviderFunc
	issuerSet jwk.KeySetProviderFunc
	holderKP  jwk.KeyProviderFunc
	holderCnf map[any]any
}

func newSdcwtBenchMaterial(b *testing.B) *sdcwtBenchMaterial {
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

	cnf, err := Confirmation(&holderPriv.PublicKey)
	if err != nil {
		b.Fatal(err)
	}

	return &sdcwtBenchMaterial{
		issuerKP:  func(context.Context) (jwk.Key, error) { return issuerKey, nil },
		issuerSet: func(context.Context) (jwk.Set, error) { return set, nil },
		holderKP:  func(context.Context) (jwk.Key, error) { return holderKey, nil },
		holderCnf: cnf,
	}
}

func sdcwtBenchClaims(km *sdcwtBenchMaterial) map[any]any {
	return map[any]any{
		uint64(1):     "https://issuer.example.com",
		uint64(6):     1750000000,
		"given_name":  sdtoken.Disclosable{Value: "John"},
		"family_name": sdtoken.Disclosable{Value: "Doe"},
		"address": sdtoken.Disclosable{Value: map[any]any{
			"street_address": sdtoken.Disclosable{Value: "123 Main St"},
			"locality":       sdtoken.Disclosable{Value: "Anytown"},
		}},
		"nationalities": []any{
			sdtoken.DisclosableElement{Value: "US"},
			sdtoken.DisclosableElement{Value: "DE"},
		},
		uint64(8): km.holderCnf,
	}
}

func BenchmarkSDCWTIssue(b *testing.B) {
	km := newSdcwtBenchMaterial(b)
	iss := NewIssuer(cose.AlgorithmES256, km.issuerKP)
	ctx := context.Background()
	b.ResetTimer()
	for b.Loop() {
		claims := sdcwtBenchClaims(km)
		if _, _, err := iss.Issue(ctx, claims); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSDCWTPresent(b *testing.B) {
	km := newSdcwtBenchMaterial(b)
	iss := NewIssuer(cose.AlgorithmES256, km.issuerKP)
	hold := NewHolder(km.issuerSet, cose.AlgorithmES256, km.holderKP)

	issued, disclosures, err := iss.Issue(context.Background(), sdcwtBenchClaims(km))
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		if _, err := hold.Present(issued, disclosures); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSDCWTVerify(b *testing.B) {
	km := newSdcwtBenchMaterial(b)
	iss := NewIssuer(cose.AlgorithmES256, km.issuerKP)
	hold := NewHolder(km.issuerSet, cose.AlgorithmES256, km.holderKP)
	v := NewVerifier(km.issuerSet,
		WithAudience("verifier.example.com"),
		WithCnonceValidator(func([]byte) error { return nil }),
	)

	issued, disclosures, err := iss.Issue(context.Background(), sdcwtBenchClaims(km))
	if err != nil {
		b.Fatal(err)
	}
	presentation, err := hold.Present(issued, disclosures)
	if err != nil {
		b.Fatal(err)
	}
	kbt, err := hold.KeyBind(presentation, "verifier.example.com", []byte("bench-cnonce"), WithIssuedAt(1750000500))
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	b.ResetTimer()
	for b.Loop() {
		if _, err := v.Verify(ctx, kbt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSDCWTDecodeDisclosure(b *testing.B) {
	// draft Figure 7 disclosure bytes.
	wire := []byte{0x83, 0x50, 0xba, 0xe6, 0x11, 0x06, 0x7b, 0xb8, 0x23, 0x48, 0x67, 0x97, 0xda, 0x1e, 0xbb, 0xb5, 0x2f, 0x83, 0x6b, 0x41, 0x42, 0x43, 0x44, 0x2d, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x19, 0x01, 0xf5}
	b.ResetTimer()
	for b.Loop() {
		if _, err := decodeDisclosure(wire); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSDCWTEncodeDisclosure(b *testing.B) {
	salt := make([]byte, 16)
	b.ResetTimer()
	for b.Loop() {
		if _, _, err := encodeDisclosure(salt, uint64(501), "ABCD-123456"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSDCWTCheckDefiniteLength(b *testing.B) {
	km := newSdcwtBenchMaterial(b)
	iss := NewIssuer(cose.AlgorithmES256, km.issuerKP)
	issued, _, err := iss.Issue(context.Background(), sdcwtBenchClaims(km))
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		if err := checkDefiniteLength(issued); err != nil {
			b.Fatal(err)
		}
	}
}
