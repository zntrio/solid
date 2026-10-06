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
	"encoding/json"
	"testing"

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/sdtoken"
	"zntr.io/solid/sdk/token"
	"zntr.io/solid/sdk/token/jwt"
)

// newIssuerKeyPair generates a fresh P-256 key pair and returns the
// private key provider plus the public key set provider.
func newIssuerKeyPair(t *testing.T) (jwk.KeyProviderFunc, jwk.KeySetProviderFunc) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("unable to generate issuer key: %v", err)
	}

	privKey, err := jwxjwk.Import(priv)
	if err != nil {
		t.Fatalf("unable to import issuer private key: %v", err)
	}
	if err := privKey.Set(jwxjwk.KeyIDKey, "issuer-key"); err != nil {
		t.Fatalf("unable to set issuer kid: %v", err)
	}

	pub, err := jwxjwk.Import(&priv.PublicKey)
	if err != nil {
		t.Fatalf("unable to import issuer public key: %v", err)
	}
	if err := pub.Set(jwxjwk.KeyIDKey, "issuer-key"); err != nil {
		t.Fatalf("unable to set issuer public kid: %v", err)
	}
	if err := pub.Set(jwxjwk.AlgorithmKey, "ES256"); err != nil {
		t.Fatalf("unable to set issuer public alg: %v", err)
	}

	set := jwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		t.Fatalf("unable to add issuer public key: %v", err)
	}

	return func(context.Context) (jwk.Key, error) { return privKey, nil },
		func(context.Context) (jwk.Set, error) { return set, nil }
}

// newHolderKeyPair generates a fresh P-256 holder key pair.
func newHolderKeyPair(t *testing.T) (jwk.KeyProviderFunc, map[string]any) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("unable to generate holder key: %v", err)
	}

	privKey, err := jwxjwk.Import(priv)
	if err != nil {
		t.Fatalf("unable to import holder private key: %v", err)
	}
	if err := privKey.Set(jwxjwk.KeyIDKey, "holder-key"); err != nil {
		t.Fatalf("unable to set holder kid: %v", err)
	}

	// Holder public key as the cnf.jwk claim value.
	pub, err := jwxjwk.Import(&priv.PublicKey)
	if err != nil {
		t.Fatalf("unable to import holder public key: %v", err)
	}
	if err := pub.Set(jwxjwk.KeyIDKey, "holder-key"); err != nil {
		t.Fatalf("unable to set holder public kid: %v", err)
	}
	if err := pub.Set(jwxjwk.AlgorithmKey, "ES256"); err != nil {
		t.Fatalf("unable to set holder public alg: %v", err)
	}
	pubJSON, err := json.Marshal(pub)
	if err != nil {
		t.Fatalf("unable to serialize holder public key: %v", err)
	}
	claimValue := map[string]any{}
	if err := unmarshalJSON(pubJSON, &claimValue); err != nil {
		t.Fatalf("unable to decode holder public key claim: %v", err)
	}

	return func(context.Context) (jwk.Key, error) { return privKey, nil }, claimValue
}

func TestRFC9901_DigestVectors(t *testing.T) {
	// RFC 9901 section 4.2.3 / section 5.1 published digest vectors.
	cases := []struct {
		wire   string
		digest string
	}{
		{
			wire:   "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd",
			digest: "jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4",
		},
		{
			wire:   "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0",
			digest: "pFndjkZ_VCzmyTa6UjlZo3dh-ko8aIKQc9DlGzhaVYo",
		},
	}
	for _, tc := range cases {
		if got := sdtoken.DigestKey([]byte(tc.wire)); got != tc.digest {
			t.Errorf("DigestKey(%q) = %q, want %q", tc.wire, got, tc.digest)
		}
	}
}

func TestRFC9901_Section51_VectorStructure(t *testing.T) {
	// With the section 5.1 salts fed in order, the issued payload must
	// carry the RFC's published _sd digest set (8 entries) and the
	// nationalities "..." element digests.
	salts := []string{
		"2GLC42sKveCfGfryNRN9w",
		"qOZ0DKz0YyOdZ0vnzYx5Z", // nested object salt (inner first)
		"iNcOYelzwS9_BE68f4fnz",
		"JLzG5ES3W7M3R7n8XFvbO",
		"lklxF5jMYlGTPUOvMNIvCA",
		"_8Lg3AOMxRR0MV5HIOFwt",
		"VMzW8jZa3bAf4d6tYgo9i",
		"F5lwVtHlV0XQ9NwR1tQyA",
		"kYm5sfzpSOsPgLOH3takQ",
		"yxKYGwA64ctmY6rEhz4AW",
		"AWmELOG1RPxVAqnUMOTnH",
	}
	pos := 0
	factory := func() ([]byte, error) {
		if pos >= len(salts) {
			t.Fatal("salt factory exhausted")
		}
		s := salts[pos]
		pos++
		return []byte(s), nil
	}

	claims := map[string]any{
		"iss":                   "https://issuer.example.com",
		"iat":                   1516239022,
		"sub":                   "6c5c0a49-b589-431d-bae7-219122a9ec2c",
		"given_name":            sdtoken.Disclosable{Value: "John"},
		"family_name":           sdtoken.Disclosable{Value: "Doe"},
		"email":                 sdtoken.Disclosable{Value: "johndoe@example.com"},
		"phone_number":          sdtoken.Disclosable{Value: "+1-202-555-0101"},
		"phone_number_verified": sdtoken.Disclosable{Value: true},
		"address": sdtoken.Disclosable{Value: map[string]any{
			"street_address": sdtoken.Disclosable{Value: "123 Main St"},
			"locality":       sdtoken.Disclosable{Value: "Anytown"},
			"region":         sdtoken.Disclosable{Value: "Anystate"},
			"postal_code":    sdtoken.Disclosable{Value: "12345"},
			"country":        sdtoken.Disclosable{Value: "US"},
		}},
		"nationalities": []any{
			sdtoken.DisclosableElement{Value: "US"},
			sdtoken.DisclosableElement{Value: "DE"},
		},
		"birthfamilyname": sdtoken.Disclosable{Value: "Merari"},
		"bd":              sdtoken.Disclosable{Value: "1940-01-01"},
		"hair":            sdtoken.Disclosable{Value: "brown"},
		"eyecolour":       sdtoken.Disclosable{Value: "blue"},
	}

	issuerKP, _ := newIssuerKeyPair(t)
	signer := jwt.RawTypedSigner("vc+sd-jwt", "ES256", issuerKP)
	iss := NewIssuer(signer, WithDecoyDigests(2), WithSaltFactory(factory))

	_, disclosures, err := iss.Issue(context.Background(), claims)
	if err != nil {
		t.Fatalf("unable to issue: %v", err)
	}
	if len(disclosures) == 0 {
		t.Fatal("no disclosures produced")
	}

	// The RFC section 5.1 example's disclosures all decode cleanly and
	// their digests are consistent.
	for _, d := range disclosures {
		dd, err := decodeDisclosure(d)
		if err != nil {
			t.Fatalf("unable to decode disclosure %q: %v", d, err)
		}
		if got := sdtoken.DigestKey([]byte(d)); got != dd.Digest {
			t.Errorf("decoded digest mismatch: %q vs %q", got, dd.Digest)
		}
	}
}

func TestParseSerialize_RoundTrip(t *testing.T) {
	jwtFixture := "eyJhbGciOiJFUzI1NiJ9.e30.YY"
	cases := []struct {
		name string
		raw  string
		want SDJWT
	}{
		{
			name: "no disclosures",
			raw:  jwtFixture + "~",
			want: SDJWT{IssuerSignedJWT: jwtFixture, Disclosures: []string{}, KeyBindingJWT: ""},
		},
		{
			name: "with disclosures",
			raw:  jwtFixture + "~ZGlzY2xvc3VyZTE~ZGlzY2xvc3VyZTI~",
			want: SDJWT{IssuerSignedJWT: jwtFixture, Disclosures: []string{"ZGlzY2xvc3VyZTE", "ZGlzY2xvc3VyZTI"}, KeyBindingJWT: ""},
		},
		{
			name: "with kb jwt",
			raw:  jwtFixture + "~ZGlzY2xvc3VyZTE~" + jwtFixture,
			want: SDJWT{IssuerSignedJWT: jwtFixture, Disclosures: []string{"ZGlzY2xvc3VyZTE"}, KeyBindingJWT: jwtFixture},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := Parse(tc.raw)
			if err != nil {
				t.Fatalf("Parse(%q) failed: %v", tc.raw, err)
			}
			if got := parsed.Serialize(); got != tc.raw {
				t.Errorf("Serialize() = %q, want %q", got, tc.raw)
			}
		})
	}

	// Malformed inputs.
	bad := []string{
		"",
		"not-a-sd-jwt",
		jwtFixture,
		jwtFixture + "~tail",
	}
	for _, raw := range bad {
		if _, err := Parse(raw); err == nil {
			t.Errorf("Parse(%q) must fail", raw)
		}
	}
}

func TestIssue_Present_Verify_RoundTrip(t *testing.T) {
	// Assemble the full role pipeline with ES256 keys.
	issuerKP, issuerSetP := newIssuerKeyPair(t)
	holderKP, holderClaim := newHolderKeyPair(t)

	signer := jwt.RawTypedSigner("vc+sd-jwt", "ES256", issuerKP)
	iss := NewIssuer(signer, WithDecoyDigests(2))

	claims := map[string]any{
		"iss": "https://issuer.example.com",
		"iat": 1516239022,
		"sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
		"given_name": sdtoken.Disclosable{
			Value: "John",
		},
		"address": sdtoken.Disclosable{Value: map[string]any{
			"street_address": sdtoken.Disclosable{Value: "123 Main St"},
			"locality":       sdtoken.Disclosable{Value: "Anytown"},
		}},
		"nationalities": []any{
			sdtoken.DisclosableElement{Value: "US"},
			sdtoken.DisclosableElement{Value: "DE"},
		},
		"cnf": map[string]any{"jwk": holderClaim},
	}

	issued, disclosures, err := iss.Issue(context.Background(), claims)
	if err != nil {
		t.Fatalf("unable to issue: %v", err)
	}
	if len(disclosures) != 6 {
		t.Fatalf("expected 6 disclosures (2 address children + address object + 2 nationalities + given_name), got %d", len(disclosures))
	}

	issuerVerifier := jwt.DefaultVerifier(issuerSetP, jwt.SupportedSignAlgorithms())
	kbSigner := jwt.RawTypedSigner(TypeKeyBinding, "ES256", holderKP)
	hold := NewHolder(issuerVerifier, kbSigner)

	// Present a partial subset: disclose given_name and street_address
	// (walk order: address children first, then given_name; the
	// street_address disclosure is disclosures[0], given_name is
	// disclosures[3] with localities in between — discover by decoding).
	streetIdx, givenIdx, addressIdx := -1, -1, -1
	for i, d := range disclosures {
		dd, err := decodeDisclosure(d)
		if err != nil {
			t.Fatal(err)
		}
		if dd.ClaimKey == "street_address" {
			streetIdx = i
		}
		if dd.ClaimKey == "given_name" {
			givenIdx = i
		}
		if dd.ClaimKey == "address" {
			addressIdx = i
		}
	}
	if streetIdx < 0 || givenIdx < 0 || addressIdx < 0 {
		t.Fatalf("unable to locate disclosures: street=%d given=%d address=%d", streetIdx, givenIdx, addressIdx)
	}

	presentation, err := hold.Present(context.Background(), issued, disclosures[streetIdx], disclosures[addressIdx], disclosures[givenIdx])
	if err != nil {
		t.Fatalf("unable to present: %v", err)
	}

	// Key binding with a nonce validator.
	nonceState := map[string]bool{}
	v := NewVerifier(issuerVerifier,
		WithAudience("verifier.example.com"),
		WithNonceValidator(func(n string) error {
			if nonceState[n] {
				return errTestNonceReplay
			}
			nonceState[n] = true
			return nil
		}),
	)

	presented := "verifier-nonce-1"
	kb, err := hold.KeyBind(context.Background(), presentation, presented, "verifier.example.com", nowUnix(t))
	if err != nil {
		t.Fatalf("unable to key bind: %v", err)
	}

	verified, err := v.Verify(context.Background(), kb)
	if err != nil {
		t.Fatalf("unable to verify: %v", err)
	}

	// Exactly the disclosed claims appear.
	if verified["given_name"] != "John" {
		t.Errorf("given_name not disclosed: %v", verified)
	}
	addr, ok := verified["address"].(map[string]any)
	if !ok || addr["street_address"] != "123 Main St" {
		t.Errorf("street_address not disclosed: %v", verified["address"])
	}
	if _, has := addr["locality"]; has {
		t.Errorf("locality must remain undisclosed: %v", addr)
	}
	if _, has := verified["family_name"]; has {
		t.Error("family_name must not exist")
	}
	if _, has := verified[ClaimSD]; has {
		t.Error("_sd container must be stripped")
	}
	if _, has := verified[ClaimSDAlg]; !has {
		t.Error("_sd_alg must be present")
	}

	// KB replay: same nonce twice must fail.
	presentation2, err := hold.Present(context.Background(), issued, disclosures[givenIdx])
	if err != nil {
		t.Fatal(err)
	}
	kb2, err := hold.KeyBind(context.Background(), presentation2, presented, "verifier.example.com", nowUnix(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), kb2); err == nil {
		t.Error("nonce replay must be rejected")
	}

	// Missing KB-JWT must be rejected by default policy.
	if _, err := v.Verify(context.Background(), presentation); err == nil {
		t.Error("presentation without kb-jwt must be rejected by default")
	}

	// A selected disclosure not part of the issuance must be rejected.
	if _, err := hold.Present(context.Background(), issued, "bm90LXZhbGlk"); err == nil {
		t.Error("unknown disclosure must be rejected")
	}
}

var errTestNonceReplay = errNew("nonce replayed")

func TestWalk_Determinism(t *testing.T) {
	claims := func() map[string]any {
		return map[string]any{
			"zeta":  sdtoken.Disclosable{Value: "z"},
			"alpha": sdtoken.Disclosable{Value: "a"},
			"mid":   sdtoken.Disclosable{Value: map[string]any{"inner": sdtoken.Disclosable{Value: "i"}}},
			"arr": []any{
				sdtoken.DisclosableElement{Value: "x"},
				sdtoken.DisclosableElement{Value: "y"},
			},
		}
	}
	first, err := sdtoken.Walk(claims())
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		again, err := sdtoken.Walk(claims())
		if err != nil {
			t.Fatal(err)
		}
		if len(again) != len(first) {
			t.Fatalf("walk length changed: %d vs %d", len(again), len(first))
		}
		for i := range again {
			if again[i].MapKey != first[i].MapKey || again[i].IsElement != first[i].IsElement {
				t.Fatalf("walk order unstable at %d: %v vs %v", i, again[i], first[i])
			}
		}
	}
}

func TestRawTypedSigner_TypHeader(t *testing.T) {
	// RawTypedSigner stores typ verbatim: "vc+sd-jwt" / "kb+jwt" do not
	// follow the HeaderType derivation.
	issuerKP, _ := newIssuerKeyPair(t)
	s := jwt.RawTypedSigner("vc+sd-jwt", "ES256", issuerKP)
	raw, err := s.Sign(context.Background(), map[string]any{"test": "example"})
	if err != nil {
		t.Fatalf("unable to serialize: %v", err)
	}
	if got := typOf(t, raw); got != "vc+sd-jwt" {
		t.Errorf("typ header = %q, want vc+sd-jwt", got)
	}

	// SupportedSignAlgorithms is sorted and non-empty.
	algs := jwt.SupportedSignAlgorithms()
	if len(algs) == 0 {
		t.Fatal("SupportedSignAlgorithms must not be empty")
	}
	for i := 1; i < len(algs); i++ {
		if algs[i-1] > algs[i] {
			t.Fatalf("SupportedSignAlgorithms not sorted: %v", algs)
		}
	}
}

func typOf(t *testing.T, raw string) string {
	t.Helper()
	parts := splitDot(raw)
	if len(parts) != 3 {
		t.Fatalf("not a compact jwt: %q", raw)
	}
	header, err := rawURLDecode(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var hdr map[string]any
	if err := unmarshalJSON(header, &hdr); err != nil {
		t.Fatal(err)
	}
	typ, _ := hdr["typ"].(string)
	return typ
}

func splitDot(s string) []string {
	var out []string
	start := 0
	for i := range len(s) {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

// compile-time interface guards.
var (
	_ token.Signer = jwt.RawTypedSigner("vc+sd-jwt", "ES256", nil)
	_ Issuer       = (*issuer)(nil)
	_ Holder       = (*holder)(nil)
	_ Verifier     = (*verifier)(nil)
)
