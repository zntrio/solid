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

package jwt_test

import (
	"context"
	"crypto"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"

	"zntr.io/solid/sdk/jwk"
	solidjwt "zntr.io/solid/sdk/token/jwt"
)

func TestMLDSAEndToEnd(t *testing.T) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}

	key, err := jwk.NewMLDSAKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	kid := base64.RawURLEncoding.EncodeToString(tp)
	if err := key.Set(jwxjwk.KeyIDKey, kid); err != nil {
		t.Fatal(err)
	}

	provider := func(context.Context) (jwk.Key, error) { return key, nil }

	// Sign an access token.
	signer := solidjwt.MLDSASigner("ML-DSA-65", provider)
	raw, err := signer.Serialize(context.Background(), map[string]any{"sub": "alice", "iss": "https://as.example"})
	if err != nil {
		t.Fatal(err)
	}

	// Wire-format check: header alg/kid.
	parts := strings.Split(raw, ".")
	hdrJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var hdr map[string]any
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		t.Fatal(err)
	}
	if hdr["alg"] != "ML-DSA-65" {
		t.Fatalf("alg = %v", hdr["alg"])
	}
	if hdr["kid"] != kid {
		t.Fatalf("kid = %v want %v", hdr["kid"], kid)
	}

	// Verify with DefaultVerifier through a keyset.
	pubKey, _ := key.PublicKey()
	set := jwxjwk.NewSet()
	if err := set.AddKey(pubKey); err != nil {
		t.Fatal(err)
	}
	verifier := solidjwt.DefaultVerifier(func(context.Context) (jwk.Set, error) { return set, nil },
		[]string{"ML-DSA-65"})

	claims := map[string]any{}
	if err := verifier.Claims(context.Background(), raw, &claims); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if claims["sub"] != "alice" {
		t.Fatalf("sub = %v", claims["sub"])
	}

	// Negative: wrong alg allowlist must reject.
	wrongVerifier := solidjwt.DefaultVerifier(func(context.Context) (jwk.Set, error) { return set, nil },
		[]string{"ES256"})
	if err := wrongVerifier.Claims(context.Background(), raw, &claims); err == nil {
		t.Fatal("expected rejection with ES-only allowlist")
	}

	// golang-jwt registry check.
	if jwt.GetSigningMethod("ML-DSA-65") == nil {
		t.Fatal("ML-DSA-65 not registered in golang-jwt registry")
	}

	// Thumbprint canonical form is stable.
	tp2, err := key.Thumbprint(crypto.SHA256)
	if err != nil || base64.RawURLEncoding.EncodeToString(tp2) != kid {
		t.Fatal("thumbprint not stable")
	}

	t.Log("E2E OK — token bytes:", len(raw))
}

func TestMLDSADPoPEmbedRoundTrip(t *testing.T) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.NewMLDSAKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Set(jwxjwk.KeyIDKey, "akp-dpop-test"); err != nil {
		t.Fatal(err)
	}

	signer := solidjwt.DPoPSigner("ML-DSA-65", func(context.Context) (jwk.Key, error) { return key, nil })
	raw, err := signer.Serialize(context.Background(), map[string]any{"htm": "GET", "htu": "https://rs.example", "jti": "x1", "iat": 1234567890})
	if err != nil {
		t.Fatal(err)
	}

	// Header check: embedded jwk, no private material.
	parts := strings.Split(raw, ".")
	hdrJSON, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var hdr map[string]any
	json.Unmarshal(hdrJSON, &hdr)
	if hdr["typ"] != "dpop+jwt" {
		t.Errorf("typ = %v", hdr["typ"])
	}
	jwkMap, ok := hdr["jwk"].(map[string]any)
	if !ok {
		t.Fatalf("jwk header missing: %v", hdr["jwk"])
	}
	if jwkMap["kty"] != "AKP" {
		t.Errorf("jwk.kty = %v", jwkMap["kty"])
	}
	if _, has := jwkMap["d"]; has {
		t.Error("embedded jwk leaks private d member")
	}

	// AKP JWK round-trip through jwk.Parse.
	pubJSON, err := json.Marshal(hdr["jwk"])
	if err != nil {
		t.Fatal(err)
	}
	set, err := jwk.Parse(pubJSON)
	if err != nil {
		t.Fatalf("jwk.Parse of embedded AKP jwk failed: %v", err)
	}
	if set.Len() != 1 {
		t.Fatalf("set len = %d", set.Len())
	}

	t.Log("DPoP ML-DSA embed OK")
}
