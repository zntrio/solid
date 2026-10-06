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

// The round-trip tests of the draft-forten profile factory import the
// serialization adapters, so this file lives in the external test
// package — the sdtoken package itself deliberately imports neither.
package sdtoken_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/veraison/go-cose"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/sdtoken"
	"zntr.io/solid/sdk/sdtoken/sdcwt"
	"zntr.io/solid/sdk/sdtoken/sdjwt"
	"zntr.io/solid/sdk/token/jwt"
)

// -----------------------------------------------------------------------------
// fixtures.

type sdatKeys struct {
	asPriv      *ecdsa.PrivateKey
	asPrivKey   jwk.Key
	asKeyProv   jwk.KeyProviderFunc
	asPubSet    jwk.Set
	dpopPriv    *ecdsa.PrivateKey
	dpopKey     jwk.Key
	dpopKeyProv jwk.KeyProviderFunc
	attnPriv    *ecdsa.PrivateKey
	attnKey     jwk.Key
}

func newSDATKeys(t *testing.T) *sdatKeys {
	t.Helper()

	k := &sdatKeys{}
	var err error
	for pair := range 3 {
		var priv *ecdsa.PrivateKey
		if priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			t.Fatal(err)
		}
		switch pair {
		case 0:
			k.asPriv = priv
		case 1:
			k.dpopPriv = priv
		case 2:
			k.attnPriv = priv
		}
	}

	if k.asPrivKey, err = jwxjwk.Import(k.asPriv); err != nil {
		t.Fatal(err)
	}
	if err := k.asPrivKey.Set(jwxjwk.KeyIDKey, "as-key"); err != nil {
		t.Fatal(err)
	}
	k.asKeyProv = func(context.Context) (jwk.Key, error) { return k.asPrivKey, nil }

	asPub, err := jwxjwk.Import(&k.asPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := asPub.Set(jwxjwk.KeyIDKey, "as-key"); err != nil {
		t.Fatal(err)
	}
	if err := asPub.Set(jwxjwk.AlgorithmKey, "ES256"); err != nil {
		t.Fatal(err)
	}
	k.asPubSet = jwk.NewSet()
	if err := k.asPubSet.AddKey(asPub); err != nil {
		t.Fatal(err)
	}

	if k.dpopKey, err = jwxjwk.Import(k.dpopPriv); err != nil {
		t.Fatal(err)
	}
	if err := k.dpopKey.Set(jwxjwk.KeyIDKey, "dpop-key"); err != nil {
		t.Fatal(err)
	}
	k.dpopKeyProv = func(context.Context) (jwk.Key, error) { return k.dpopKey, nil }

	if k.attnKey, err = jwxjwk.Import(k.attnPriv); err != nil {
		t.Fatal(err)
	}
	if err := k.attnKey.Set(jwxjwk.KeyIDKey, "attacker-key"); err != nil {
		t.Fatal(err)
	}

	return k
}

// dpopJKT computes the RFC 7638 SHA-256 thumbprint of the DPoP key:
// the cnf.jkt value (RFC 9449 section 4.4).
func (k *sdatKeys) dpopJKT(t *testing.T) string {
	t.Helper()
	tp, err := k.dpopKey.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(tp)
}

func (k *sdatKeys) attnJKT(t *testing.T) string {
	t.Helper()
	tp, err := k.attnKey.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(tp)
}

// -----------------------------------------------------------------------------
// construction fail-closed.

func TestNewMissingDeps(t *testing.T) {
	k := newSDATKeys(t)

	// SD-JWT: verifier without IssuerKeys.
	if _, err := sdjwt.NewAccessTokenVerifier(sdtoken.AccessTokenProfile, sdjwt.Deps{}); err == nil || !strings.Contains(err.Error(), "IssuerKeys") {
		t.Fatalf("verifier err = %v", err)
	}
	// SD-JWT: issuer without Signer.
	if _, err := sdjwt.NewAccessTokenIssuer(sdtoken.AccessTokenProfile, sdjwt.Deps{}); err == nil || !strings.Contains(err.Error(), "Signer") {
		t.Fatalf("issuer err = %v", err)
	}
	// SD-JWT: holder without KBSigner.
	if _, err := sdjwt.NewAccessTokenHolder(sdtoken.AccessTokenProfile, sdjwt.Deps{
		IssuerKeys: func(context.Context) (jwk.Set, error) { return k.asPubSet, nil },
	}); err == nil || !strings.Contains(err.Error(), "KBSigner") {
		t.Fatalf("holder err = %v", err)
	}
	// SD-CWT: verifier without IssuerKeys.
	if _, err := sdcwt.NewAccessTokenVerifier(sdtoken.AccessTokenProfile, sdcwt.Deps{
		Algorithm:   cose.AlgorithmES256,
		KeyProvider: k.asKeyProv,
	}); err == nil || !strings.Contains(err.Error(), "IssuerKeys") {
		t.Fatalf("cwt verifier err = %v", err)
	}
	// SD-CWT: issuer without KeyProvider.
	if _, err := sdcwt.NewAccessTokenIssuer(sdtoken.AccessTokenProfile, sdcwt.Deps{
		Algorithm: cose.AlgorithmES256,
	}); err == nil || !strings.Contains(err.Error(), "KeyProvider") {
		t.Fatalf("cwt issuer err = %v", err)
	}
}

// -----------------------------------------------------------------------------
// JWT kind round-trips.

func TestSDATJWTAccessTokenRoundTrip(t *testing.T) {
	k := newSDATKeys(t)
	profile := sdtoken.AccessTokenProfile

	issuer, err := sdjwt.NewAccessTokenIssuer(profile, sdjwt.Deps{
		Signer: jwt.AccessTokenSigner("ES256", k.asKeyProv),
	}, sdtoken.WithDecoyDigests(2))
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	claims := map[string]any{
		"iss":       "https://as.example.com",
		"sub":       "user-123",
		"aud":       "https://rs.example.com",
		"exp":       now + 3600,
		"iat":       now,
		"jti":       "at-jti-1",
		"client_id": "client-1",
		"scope":     "read write",
		"cnf":       map[string]any{"jkt": k.dpopJKT(t)},
		"email":     sdtoken.Disclosable{Value: "user@example.com"},
		"name":      sdtoken.Disclosable{Value: "Alice Doe"},
	}

	tokenString, disclosures, err := issuer.Issue(context.Background(), claims)
	if err != nil {
		t.Fatal(err)
	}

	// The token is a bare JWT (no tildes), typ at+jwt, payload carrying
	// digests and NO cleartext email / name.
	if strings.Contains(tokenString, "~") {
		t.Fatal("draft-forten token string must not carry disclosures")
	}
	if strings.Count(tokenString, ".") != 2 {
		t.Fatal("token must be a compact JWT")
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(strings.Split(tokenString, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		t.Fatal(err)
	}
	if _, has := payload["email"]; has {
		t.Fatal("payload must not carry the email value")
	}
	if _, has := payload["name"]; has {
		t.Fatal("payload must not carry the name value")
	}
	if _, has := payload["_sd"]; !has {
		t.Fatal("payload must carry the _sd digest array")
	}
	if payload["_sd_alg"] != "sha-256" {
		t.Fatalf("_sd_alg = %v", payload["_sd_alg"])
	}
	if payload["typ_header_checked"] != nil {
		t.Fatal("unexpected member")
	}

	// Holder selects by claim name, without parsing the token.
	holder, err := sdjwt.NewAccessTokenHolder(profile, sdjwt.Deps{
		IssuerKeys: func(context.Context) (jwk.Set, error) { return k.asPubSet, nil },
		KBSigner:   jwt.RawTypedSigner(sdtoken.TypeKeyBindingJWT, "ES256", k.dpopKeyProv),
	})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := holder.Select(context.Background(), tokenString, disclosures, "email")
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 1 {
		t.Fatalf("selected %d disclosures, want 1", len(selected))
	}

	// Key binding over exactly the selected disclosure.
	kb, err := holder.KeyBind(context.Background(), tokenString, selected, "rs-nonce", "https://rs.example.com", now)
	if err != nil {
		t.Fatal(err)
	}

	// Verifier: DPoP key, audience, one-shot nonce.
	nonceSeen := map[string]bool{}
	verifier, err := sdjwt.NewAccessTokenVerifier(profile, sdjwt.Deps{
		IssuerKeys: func(context.Context) (jwk.Set, error) { return k.asPubSet, nil },
	}, sdtoken.WithAudience("https://rs.example.com"),
		sdtoken.WithNonceValidator(func(n string) error {
			if nonceSeen[n] {
				return errors.New("nonce replay")
			}
			nonceSeen[n] = true
			return nil
		}))
	if err != nil {
		t.Fatal(err)
	}

	processed, err := verifier.Verify(context.Background(), tokenString, selected, kb, k.dpopKey)
	if err != nil {
		t.Fatal(err)
	}
	if processed["email"] != "user@example.com" {
		t.Fatalf("email = %v", processed["email"])
	}
	if _, has := processed["name"]; has {
		t.Fatal("withheld name must not appear in the processed payload")
	}
	if processed["sub"] != "user-123" {
		t.Fatalf("sub = %v", processed["sub"])
	}
	if cnf, ok := processed["cnf"].(map[string]any); !ok || cnf["jkt"] != k.dpopJKT(t) {
		t.Fatalf("cnf = %v", processed["cnf"])
	}
}

func TestSDATJWTIDTokenRoundTrip(t *testing.T) {
	k := newSDATKeys(t)
	profile := sdtoken.IDTokenProfile

	issuer, err := sdjwt.NewAccessTokenIssuer(profile, sdjwt.Deps{
		Signer: jwt.RawTypedSigner("id+jwt", "ES256", k.asKeyProv),
	})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	claims := map[string]any{
		"iss":       "https://as.example.com",
		"sub":       "user-123",
		"aud":       "client-1",
		"exp":       now + 3600,
		"iat":       now,
		"nonce":     "n-0S6_WzA2Mj",
		"auth_time": now - 60,
		"email":     sdtoken.Disclosable{Value: "user@example.com"},
		"name":      sdtoken.Disclosable{Value: "Alice Doe"},
	}

	tokenString, disclosures, err := issuer.Issue(context.Background(), claims)
	if err != nil {
		t.Fatal(err)
	}

	// typ id+jwt, no cleartext user claims.
	headerJSON, err := base64.RawURLEncoding.DecodeString(strings.Split(tokenString, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatal(err)
	}
	if header["typ"] != "id+jwt" {
		t.Fatalf("typ = %v", header["typ"])
	}

	holder, err := sdjwt.NewAccessTokenHolder(profile, sdjwt.Deps{
		IssuerKeys: func(context.Context) (jwk.Set, error) { return k.asPubSet, nil },
		KBSigner:   jwt.RawTypedSigner(sdtoken.TypeKeyBindingJWT, "ES256", k.dpopKeyProv),
	})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := holder.Select(context.Background(), tokenString, disclosures, "name")
	if err != nil {
		t.Fatal(err)
	}

	// The ID-token profile is verified with no KB and the client
	// audience.
	verifier, err := sdjwt.NewAccessTokenVerifier(profile, sdjwt.Deps{
		IssuerKeys: func(context.Context) (jwk.Set, error) { return k.asPubSet, nil },
	}, sdtoken.WithAudience("client-1"), sdtoken.WithOptionalKeyBinding())
	if err != nil {
		t.Fatal(err)
	}
	processed, err := verifier.Verify(context.Background(), tokenString, selected, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if processed["name"] != "Alice Doe" {
		t.Fatalf("name = %v", processed["name"])
	}
	if _, has := processed["email"]; has {
		t.Fatal("disclosed email must be absent when its disclosure is withheld")
	}
	if processed["nonce"] != "n-0S6_WzA2Mj" {
		t.Fatalf("nonce = %v", processed["nonce"])
	}

	// Cross-profile typ confusion: the ID-token verifier must reject an
	// at+jwt access token.
	atIssuer, err := sdjwt.NewAccessTokenIssuer(sdtoken.AccessTokenProfile, sdjwt.Deps{
		Signer: jwt.AccessTokenSigner("ES256", k.asKeyProv),
	})
	if err != nil {
		t.Fatal(err)
	}
	atToken, atDisclosures, err := atIssuer.Issue(context.Background(), map[string]any{
		"iss": "https://as.example.com", "sub": "user-123", "aud": "client-1",
		"exp": now + 3600, "iat": now,
		"email": sdtoken.Disclosable{Value: "user@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(context.Background(), atToken, atDisclosures, "", nil); err == nil {
		t.Fatal("id-token-profile verifier must reject an at+jwt token")
	}
}

// -----------------------------------------------------------------------------
// CWT kind round-trips.

func TestSDATCWTAccessTokenRoundTrip(t *testing.T) {
	k := newSDATKeys(t)
	profile := sdtoken.AccessTokenProfile

	issuer, err := sdcwt.NewAccessTokenIssuer(profile, sdcwt.Deps{
		Algorithm:   cose.AlgorithmES256,
		KeyProvider: k.asKeyProv,
	}, sdtoken.WithRequiredConfirmation(), sdtoken.WithDecoyDigests(2))
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	claims := map[string]any{
		"iss":       "https://as.example.com",
		"sub":       "user-123",
		"aud":       "https://rs.example.com",
		"exp":       now + 3600,
		"iat":       now,
		"jti":       "at-jti-2",
		"client_id": "client-1",
		"scope":     "read",
		"cnf":       map[string]any{"jkt": k.dpopJKT(t)},
		"email":     sdtoken.Disclosable{Value: "user@example.com"},
		"name":      sdtoken.Disclosable{Value: "Alice Doe"},
	}

	tokenString, disclosures, err := issuer.Issue(context.Background(), claims)
	if err != nil {
		t.Fatal(err)
	}

	if len(disclosures) < 2 {
		t.Fatalf("expected email+name disclosures, got %d", len(disclosures))
	}

	holder, err := sdcwt.NewAccessTokenHolder(profile, sdcwt.Deps{
		IssuerKeys:  func(context.Context) (jwk.Set, error) { return k.asPubSet, nil },
		Algorithm:   cose.AlgorithmES256,
		KeyProvider: k.dpopKeyProv,
	})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := holder.Select(context.Background(), tokenString, disclosures, "email")
	if err != nil {
		t.Fatal(err)
	}
	kb, err := holder.KeyBind(context.Background(), tokenString, selected, "rs-nonce", "https://rs.example.com", now)
	if err != nil {
		t.Fatal(err)
	}

	nonceSeen := map[string]bool{}
	verifier, err := sdcwt.NewAccessTokenVerifier(profile, sdcwt.Deps{
		IssuerKeys: func(context.Context) (jwk.Set, error) { return k.asPubSet, nil },
	}, sdtoken.WithAudience("https://rs.example.com"),
		sdtoken.WithNonceValidator(func(n string) error {
			if nonceSeen[n] {
				return errors.New("nonce replay")
			}
			nonceSeen[n] = true
			return nil
		}))
	if err != nil {
		t.Fatal(err)
	}

	processed, err := verifier.Verify(context.Background(), tokenString, selected, kb, k.dpopKey)
	if err != nil {
		t.Fatal(err)
	}
	if processed["email"] != "user@example.com" {
		t.Fatalf("email = %v", processed["email"])
	}
	if _, has := processed["name"]; has {
		t.Fatal("withheld name must not appear")
	}
	if processed["sub"] != "user-123" {
		t.Fatalf("sub = %v", processed["sub"])
	}
	if processed["aud"] != "https://rs.example.com" {
		t.Fatalf("aud = %v", processed["aud"])
	}
	if cnf, ok := processed["cnf"].(map[any]any); !ok || cnf["jkt"] != k.dpopJKT(t) {
		t.Fatalf("cnf = %v", processed["cnf"])
	}
}

func TestSDATCWTIDTokenRoundTrip(t *testing.T) {
	k := newSDATKeys(t)
	profile := sdtoken.IDTokenProfile

	issuer, err := sdcwt.NewAccessTokenIssuer(profile, sdcwt.Deps{
		Algorithm:   cose.AlgorithmES256,
		KeyProvider: k.asKeyProv,
	})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	claims := map[string]any{
		"iss":       "https://as.example.com",
		"sub":       "user-123",
		"aud":       "client-1",
		"exp":       now + 3600,
		"iat":       now,
		"nonce":     "n-0S6_WzA2Mj",
		"auth_time": now - 60,
		"email":     sdtoken.Disclosable{Value: "user@example.com"},
		"name":      sdtoken.Disclosable{Value: "Alice Doe"},
	}

	tokenString, disclosures, err := issuer.Issue(context.Background(), claims)
	if err != nil {
		t.Fatal(err)
	}

	holder, err := sdcwt.NewAccessTokenHolder(profile, sdcwt.Deps{
		IssuerKeys:  func(context.Context) (jwk.Set, error) { return k.asPubSet, nil },
		Algorithm:   cose.AlgorithmES256,
		KeyProvider: k.dpopKeyProv,
	})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := holder.Select(context.Background(), tokenString, disclosures, "name")
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := sdcwt.NewAccessTokenVerifier(profile, sdcwt.Deps{
		IssuerKeys: func(context.Context) (jwk.Set, error) { return k.asPubSet, nil },
	}, sdtoken.WithAudience("client-1"), sdtoken.WithOptionalKeyBinding())
	if err != nil {
		t.Fatal(err)
	}
	processed, err := verifier.Verify(context.Background(), tokenString, selected, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if processed["name"] != "Alice Doe" {
		t.Fatalf("name = %v", processed["name"])
	}
	if _, has := processed["email"]; has {
		t.Fatal("withheld email must not appear")
	}
	if processed["nonce"] != "n-0S6_WzA2Mj" {
		t.Fatalf("nonce = %v", processed["nonce"])
	}
}

// -----------------------------------------------------------------------------
// issuer-side rejections.

func TestSDATProtectedClaimRejected(t *testing.T) {
	k := newSDATKeys(t)
	for _, jwtKind := range []bool{true, false} {
		var issuer sdtoken.AccessTokenIssuer
		var err error
		if jwtKind {
			issuer, err = sdjwt.NewAccessTokenIssuer(sdtoken.AccessTokenProfile, sdjwt.Deps{
				Signer: jwt.AccessTokenSigner("ES256", k.asKeyProv),
			})
		} else {
			issuer, err = sdcwt.NewAccessTokenIssuer(sdtoken.AccessTokenProfile, sdcwt.Deps{
				Algorithm:   cose.AlgorithmES256,
				KeyProvider: k.asKeyProv,
			})
		}
		if err != nil {
			t.Fatal(err)
		}

		// Each protected claim marked Disclosable must be rejected.
		for name, value := range map[string]any{
			"sub": "user-123", "aud": "rs", "exp": 4102444800, "scope": "read",
			"cnf": map[string]any{"jkt": "x"},
		} {
			claims := map[string]any{
				"iss": "https://as.example.com", "sub": "user-123", "aud": "rs",
				"exp": time.Now().Unix() + 3600, "iat": time.Now().Unix(),
				name: sdtoken.Disclosable{Value: value},
			}
			_, _, err := issuer.Issue(context.Background(), claims)
			if !errors.Is(err, sdtoken.ErrProtectedClaim) {
				t.Fatalf("jwt %v: protected claim %s err = %v, want ErrProtectedClaim", jwtKind, name, err)
			}
		}

		// ID-token protected claims under the ID-token profile.
		var idIssuer sdtoken.AccessTokenIssuer
		if jwtKind {
			idIssuer, err = sdjwt.NewAccessTokenIssuer(sdtoken.IDTokenProfile, sdjwt.Deps{
				Signer: jwt.RawTypedSigner("id+jwt", "ES256", k.asKeyProv),
			})
		} else {
			idIssuer, err = sdcwt.NewAccessTokenIssuer(sdtoken.IDTokenProfile, sdcwt.Deps{
				Algorithm:   cose.AlgorithmES256,
				KeyProvider: k.asKeyProv,
			})
		}
		if err != nil {
			t.Fatal(err)
		}
		for name := range sdtoken.IDTokenProfile.ProtectedClaims {
			claims := map[string]any{
				"iss": "https://as.example.com", "sub": "user-123", "aud": "client-1",
				"exp": time.Now().Unix() + 3600, "iat": time.Now().Unix(),
				"email": sdtoken.Disclosable{Value: "user@example.com"},
				name:    sdtoken.Disclosable{Value: "x"},
			}
			if _, protected := map[string]bool{"iss": true, "sub": true, "aud": true, "exp": true, "iat": true, "jti": true}[name]; protected && name != "jti" {
				// avoid double-claim collision in the fixture; jti is
				// not present in the base map
			}
			if name == "iss" || name == "sub" || name == "aud" || name == "exp" || name == "iat" || name == "nbf" {
				continue // already present as plaintext in the fixture
			}
			_, _, err := idIssuer.Issue(context.Background(), claims)
			if !errors.Is(err, sdtoken.ErrProtectedClaim) {
				t.Fatalf("jwt %v: id-token protected claim %s err = %v, want ErrProtectedClaim", jwtKind, name, err)
			}
		}
	}
}

func TestSDATNestedMarkerRejected(t *testing.T) {
	k := newSDATKeys(t)
	issuer, err := sdjwt.NewAccessTokenIssuer(sdtoken.AccessTokenProfile, sdjwt.Deps{
		Signer: jwt.AccessTokenSigner("ES256", k.asKeyProv),
	})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	claims := map[string]any{
		"iss": "https://as.example.com", "sub": "user-123", "aud": "rs",
		"exp": now + 3600, "iat": now,
		"address": map[string]any{
			"street": sdtoken.Disclosable{Value: "Main St"},
		},
	}
	if _, _, err := issuer.Issue(context.Background(), claims); !errors.Is(err, sdtoken.ErrNestedDisclosable) {
		t.Fatalf("nested marker err = %v, want ErrNestedDisclosable", err)
	}

	// Element markers directly under a top-level array ARE allowed.
	claimsOK := map[string]any{
		"iss": "https://as.example.com", "sub": "user-123", "aud": "rs",
		"exp": now + 3600, "iat": now,
		"roles": []any{
			sdtoken.DisclosableElement{Value: "admin"},
			"user",
		},
	}
	if _, _, err := issuer.Issue(context.Background(), claimsOK); err != nil {
		t.Fatalf("top-level element marker must be allowed: %v", err)
	}
}

func TestSDATConfirmationRequired(t *testing.T) {
	k := newSDATKeys(t)
	for _, jwtKind := range []bool{true, false} {
		var issuer sdtoken.AccessTokenIssuer
		var err error
		if jwtKind {
			issuer, err = sdjwt.NewAccessTokenIssuer(sdtoken.AccessTokenProfile, sdjwt.Deps{
				Signer: jwt.AccessTokenSigner("ES256", k.asKeyProv),
			}, sdtoken.WithRequiredConfirmation())
		} else {
			issuer, err = sdcwt.NewAccessTokenIssuer(sdtoken.AccessTokenProfile, sdcwt.Deps{
				Algorithm:   cose.AlgorithmES256,
				KeyProvider: k.asKeyProv,
			}, sdtoken.WithRequiredConfirmation())
		}
		if err != nil {
			t.Fatal(err)
		}

		now := time.Now().Unix()
		claims := map[string]any{
			"iss": "https://as.example.com", "sub": "user-123", "aud": "rs",
			"exp": now + 3600, "iat": now,
			"email": sdtoken.Disclosable{Value: "user@example.com"},
		}
		if _, _, err := issuer.Issue(context.Background(), claims); !errors.Is(err, sdtoken.ErrConfirmationRequired) {
			t.Fatalf("jwt %v: err = %v, want ErrConfirmationRequired", jwtKind, err)
		}
	}
}

// TestSDATCallerClaimsMapIntact asserts the adapters deep-copy the
// claims before the marker-replacing walk: after Issue, the caller's
// map still carries the markers and the original array elements —
// the engines must not corrupt caller data (map-form deletions and
// element-form array rewrites both stay internal).
func TestSDATCallerClaimsMapIntact(t *testing.T) {
	k := newSDATKeys(t)
	now := time.Now().Unix()

	for _, jwtKind := range []bool{true, false} {
		var issuer sdtoken.AccessTokenIssuer
		var err error
		if jwtKind {
			issuer, err = sdjwt.NewAccessTokenIssuer(sdtoken.AccessTokenProfile, sdjwt.Deps{
				Signer: jwt.AccessTokenSigner("ES256", k.asKeyProv),
			})
		} else {
			issuer, err = sdcwt.NewAccessTokenIssuer(sdtoken.AccessTokenProfile, sdcwt.Deps{
				Algorithm:   cose.AlgorithmES256,
				KeyProvider: k.asKeyProv,
			})
		}
		if err != nil {
			t.Fatal(err)
		}

		roles := []any{sdtoken.DisclosableElement{Value: "admin"}, "user"}
		claims := map[string]any{
			"iss": "https://as.example.com", "sub": "user-123", "aud": "rs",
			"exp": now + 3600, "iat": now,
			"email": sdtoken.Disclosable{Value: "user@example.com"},
			"roles": roles,
		}
		if _, _, err := issuer.Issue(context.Background(), claims); err != nil {
			t.Fatalf("jwt %v: issue: %v", jwtKind, err)
		}

		if _, isMarker := claims["email"].(sdtoken.Disclosable); !isMarker {
			t.Errorf("jwt %v: caller email marker was consumed (got %T)", jwtKind, claims["email"])
		}
		if len(claims) < 6 {
			t.Errorf("jwt %v: caller claims map lost entries: %v", jwtKind, claims)
		}
		if _, isMarker := roles[0].(sdtoken.DisclosableElement); !isMarker {
			t.Errorf("jwt %v: caller array element was rewritten (got %T)", jwtKind, roles[0])
		}
		if roles[1] != "user" {
			t.Errorf("jwt %v: caller array second element changed: %v", jwtKind, roles[1])
		}
	}
}
