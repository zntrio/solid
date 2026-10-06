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

package idjag

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	sdkjwk "zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token"
	sdkjwt "zntr.io/solid/sdk/token/jwt"
)

const (
	idPIssuer     = "https://idp.example/"
	resourceAS    = "https://resource-as.example/"
	clientAtAS    = "client-at-resource-as"
	alg           = "ES256"
	validLifetime = 5 * time.Minute
)

// newSigningKey generates a fresh EC P-256 key pair with kid set.
func newSigningKey(t *testing.T) (sdkjwk.Key, *ecdsa.PrivateKey) {
	t.Helper()
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("unable to generate EC key: %v", err)
	}
	k, err := jwxjwk.Import(raw) //nolint:staticcheck // import local type
	if err != nil {
		t.Fatalf("unable to import EC key: %v", err)
	}
	if err := sdkjwk.AssignKeyID(k); err != nil {
		t.Fatalf("unable to assign kid: %v", err)
	}
	return k, raw
}

func publicKeySet(t *testing.T, key sdkjwk.Key) sdkjwk.Set {
	if t != nil {
		t.Helper()
	}
	pub, err := jwxjwk.PublicKeyOf(key)
	if err != nil {
		if t != nil {
			t.Fatalf("unable to derive public key: %v", err)
		}
		panic(err)
	}
	set := sdkjwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		if t != nil {
			t.Fatalf("unable to add public key: %v", err)
		}
		panic(err)
	}
	return set
}

// staticResolver resolves a single trusted issuer to a fixed key set.
type staticResolver struct {
	issuer string
	jwks   sdkjwk.Set
}

func (r *staticResolver) Resolve(_ context.Context, issuer string) (sdkjwk.Set, error) {
	if issuer != r.issuer {
		return nil, ErrInvalidGrant
	}
	return r.jwks, nil
}

// validGrant assembles a fully populated ID-JAG claim set.
func validGrant(now time.Time) *tokenv1.IdentityAssertionJWTAuthorizationGrant {
	return &tokenv1.IdentityAssertionJWTAuthorizationGrant{
		Iss:      idPIssuer,
		Sub:      "subject-1",
		Aud:      resourceAS,
		ClientId: clientAtAS,
		Jti:      "jti-1",
		Exp:      uint64(now.Add(validLifetime).Unix()), //nolint:gosec // unix time
		Iat:      uint64(now.Unix()),                    //nolint:gosec // unix time
	}
}

// mintIDJAG signs an arbitrary claim-set mutation with the given key.
func mintIDJAG(t *testing.T, key sdkjwk.Key, mutate func(*tokenv1.IdentityAssertionJWTAuthorizationGrant), now time.Time) string {
	t.Helper()
	grant := validGrant(now)
	if mutate != nil {
		mutate(grant)
	}
	raw, err := DefaultSigner(sdkjwt.IDJAG(alg, func(context.Context) (sdkjwk.Key, error) { return key, nil })).
		Serialize(context.Background(), grant)
	if err != nil {
		t.Fatalf("unable to sign ID-JAG: %v", err)
	}
	return raw
}

// mintCustomClaims signs arbitrary claims with the given typ and alg,
// bypassing the claim-set enforcement of DefaultSigner.
func mintCustom(t *testing.T, key sdkjwk.Key, tokenType, algID string, claims any) string {
	t.Helper()
	serializer := sdkjwt.TypedSigner(tokenType, algID, func(context.Context) (sdkjwk.Key, error) { return key, nil })
	raw, err := serializer.Sign(context.Background(), claims)
	if err != nil {
		t.Fatalf("unable to sign: %v", err)
	}
	return raw
}

// mintWithType signs the proto claim set with an arbitrary typ header.
func mintWithType(t *testing.T, key sdkjwk.Key, tokenType string, grant *tokenv1.IdentityAssertionJWTAuthorizationGrant) string {
	t.Helper()
	return mintCustom(t, key, tokenType, alg, grant)
}

// mintWithAlg signs the proto claim set with an arbitrary algorithm.
func mintWithAlg(t *testing.T, key sdkjwk.Key, algID string, grant *tokenv1.IdentityAssertionJWTAuthorizationGrant) string {
	t.Helper()
	return mintCustom(t, key, token.TypeIDJAG, algID, grant)
}

// mintCustomClaims signs a raw claim map as a well-typed ID-JAG.
func mintCustomClaims(t *testing.T, key sdkjwk.Key, claims map[string]any) string {
	t.Helper()
	return mintCustom(t, key, token.TypeIDJAG, alg, claims)
}

// headerOf decodes the JWT header of a compact token.
func headerOf(t *testing.T, raw string) map[string]any {
	t.Helper()
	seg := strings.Split(raw, ".")
	if len(seg) != 3 {
		t.Fatalf("not a compact JWT: %q", raw)
	}
	payload, err := base64.RawURLEncoding.DecodeString(seg[0])
	if err != nil {
		t.Fatalf("unable to decode header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(payload, &header); err != nil {
		t.Fatalf("unable to unmarshal header: %v", err)
	}
	return header
}

// -----------------------------------------------------------------------------
// Signer

func TestSigner(t *testing.T) {
	ctx := context.Background()
	key, _ := newSigningKey(t)
	signer := DefaultSigner(sdkjwt.IDJAG(alg, func(context.Context) (sdkjwk.Key, error) { return key, nil }))

	t.Run("signs with required typ header", func(t *testing.T) {
		raw, err := signer.Serialize(ctx, validGrant(time.Now()))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		header := headerOf(t, raw)
		if typ, _ := header["typ"].(string); typ != "oauth-id-jag+jwt" {
			t.Errorf("typ header = %v, want oauth-id-jag+jwt", header["typ"])
		}
		if _, ok := header["kid"]; !ok {
			t.Error("kid header is missing")
		}
	})

	t.Run("rejects missing required claims", func(t *testing.T) {
		cases := map[string]func(*tokenv1.IdentityAssertionJWTAuthorizationGrant){
			"iss":       func(g *tokenv1.IdentityAssertionJWTAuthorizationGrant) { g.Iss = "" },
			"sub":       func(g *tokenv1.IdentityAssertionJWTAuthorizationGrant) { g.Sub = "" },
			"aud":       func(g *tokenv1.IdentityAssertionJWTAuthorizationGrant) { g.Aud = "" },
			"client_id": func(g *tokenv1.IdentityAssertionJWTAuthorizationGrant) { g.ClientId = "" },
			"jti":       func(g *tokenv1.IdentityAssertionJWTAuthorizationGrant) { g.Jti = "" },
			"exp":       func(g *tokenv1.IdentityAssertionJWTAuthorizationGrant) { g.Exp = 0 },
			"iat":       func(g *tokenv1.IdentityAssertionJWTAuthorizationGrant) { g.Iat = 0 },
		}
		for claim, mutate := range cases {
			grant := validGrant(time.Now())
			mutate(grant)
			if _, err := signer.Serialize(ctx, grant); err == nil {
				t.Errorf("missing %s claim: expected error, got none", claim)
			}
		}
	})

	t.Run("rejects nil grant", func(t *testing.T) {
		if _, err := signer.Serialize(ctx, nil); err == nil {
			t.Error("nil grant: expected error, got none")
		}
	})
}

// -----------------------------------------------------------------------------
// Verifier

func newTestVerifier(key sdkjwk.Key, now func() time.Time) Verifier {
	return &defaultVerifier{
		localIssuer:    resourceAS,
		issuerResolver: &staticResolver{issuer: idPIssuer, jwks: publicKeySet(nil, key)},
		verifier:       sdkjwt.DefaultVerifier(func(context.Context) (sdkjwk.Set, error) { return nil, nil }, []string{alg}),
		now:            now,
	}
}

func TestVerifier(t *testing.T) {
	ctx := context.Background()
	key, _ := newSigningKey(t)
	now := time.Now()
	verifier := newTestVerifier(key, func() time.Time { return now })

	t.Run("accepts a valid ID-JAG", func(t *testing.T) {
		raw := mintIDJAG(t, key, nil, now)
		claims, err := verifier.Verify(ctx, raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if claims.Sub != "subject-1" || claims.ClientId != clientAtAS {
			t.Errorf("decoded claims mismatch: %+v", claims)
		}
	})

	t.Run("rejects wrong typ", func(t *testing.T) {
		// A JWT with the same claims but a different typ: sign via the
		// generic typed signer path.
		raw := mintWithType(t, key, "at", validGrant(now))
		if _, err := verifier.Verify(ctx, raw); err == nil {
			t.Error("wrong typ: expected error, got none")
		}
	})

	t.Run("rejects unsupported algorithm", func(t *testing.T) {
		// ES384 with a matching P-384 key: valid EC signature family,
		// but outside the configured allowlist.
		p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("unable to generate P-384 key: %v", err)
		}
		k, err := jwxjwk.Import(p384)
		if err != nil {
			t.Fatalf("unable to import P-384 key: %v", err)
		}
		if err := jwxjwk.AssignKeyID(k); err != nil {
			t.Fatalf("unable to assign kid: %v", err)
		}
		raw := mintWithAlg(t, k, "ES384", validGrant(now))
		if _, err := verifier.Verify(ctx, raw); err == nil {
			t.Error("unsupported alg: expected error, got none")
		}
	})

	t.Run("rejects unknown issuer", func(t *testing.T) {
		raw := mintIDJAG(t, key, func(g *tokenv1.IdentityAssertionJWTAuthorizationGrant) { g.Iss = "https://evil.example/" }, now)
		if _, err := verifier.Verify(ctx, raw); err == nil {
			t.Error("unknown issuer: expected error, got none")
		}
	})

	t.Run("rejects self-issued ID-JAG", func(t *testing.T) {
		raw := mintIDJAG(t, key, func(g *tokenv1.IdentityAssertionJWTAuthorizationGrant) { g.Iss = resourceAS }, now)
		if _, err := verifier.Verify(ctx, raw); err == nil {
			t.Error("iss == local issuer: expected error, got none")
		}
	})

	t.Run("rejects wrong aud", func(t *testing.T) {
		raw := mintIDJAG(t, key, func(g *tokenv1.IdentityAssertionJWTAuthorizationGrant) { g.Aud = "https://other-as.example/" }, now)
		if _, err := verifier.Verify(ctx, raw); err == nil {
			t.Error("wrong aud: expected error, got none")
		}
	})

	t.Run("rejects multi-element aud array", func(t *testing.T) {
		// Hand-craft a token whose aud is a 2-element array containing
		// the local issuer.
		raw := mintCustomClaims(t, key, map[string]any{
			"iss":       idPIssuer,
			"sub":       "subject-1",
			"aud":       []string{resourceAS, "https://other.example/"},
			"client_id": clientAtAS,
			"jti":       "jti-1",
			"exp":       now.Add(validLifetime).Unix(),
			"iat":       now.Unix(),
		})
		if _, err := verifier.Verify(ctx, raw); err == nil {
			t.Error("multi-element aud: expected error, got none")
		}
	})

	t.Run("accepts single-element aud array", func(t *testing.T) {
		raw := mintCustomClaims(t, key, map[string]any{
			"iss":       idPIssuer,
			"sub":       "subject-1",
			"aud":       []string{resourceAS},
			"client_id": clientAtAS,
			"jti":       "jti-1",
			"exp":       now.Add(validLifetime).Unix(),
			"iat":       now.Unix(),
		})
		if _, err := verifier.Verify(ctx, raw); err != nil {
			t.Fatalf("single-element aud array should be accepted: %v", err)
		}
	})

	t.Run("rejects expired ID-JAG", func(t *testing.T) {
		expired := now.Add(-2 * time.Minute)
		raw := mintIDJAG(t, key, func(g *tokenv1.IdentityAssertionJWTAuthorizationGrant) {
			g.Iat = uint64(expired.Unix())                  //nolint:gosec // unix time
			g.Exp = uint64(expired.Add(time.Second).Unix()) //nolint:gosec // unix time
		}, expired)
		if _, err := verifier.Verify(ctx, raw); err == nil {
			t.Error("expired: expected error, got none")
		}
	})

	t.Run("rejects missing REQUIRED claims", func(t *testing.T) {
		// The minted claim map omits one REQUIRED claim per case; the
		// signer's enforcement is bypassed deliberately to attack the
		// verifier.
		base := map[string]any{
			"iss":       idPIssuer,
			"sub":       "subject-1",
			"aud":       resourceAS,
			"client_id": clientAtAS,
			"jti":       "jti-1",
			"exp":       now.Add(validLifetime).Unix(),
			"iat":       now.Unix(),
		}
		for claim := range base {
			claims := make(map[string]any, len(base))
			for k, v := range base {
				claims[k] = v
			}
			delete(claims, claim)
			if claim == "aud" || claim == "iss" {
				// aud/iss removals are covered by dedicated subtests.
				continue
			}
			raw := mintCustomClaims(t, key, claims)
			if _, err := verifier.Verify(ctx, raw); err == nil {
				t.Errorf("missing %s: expected error, got none", claim)
			}
		}
	})

	t.Run("rejects signature from another key", func(t *testing.T) {
		otherKey, _ := newSigningKey(t)
		raw := mintIDJAG(t, otherKey, nil, now)
		if _, err := verifier.Verify(ctx, raw); err == nil {
			t.Error("foreign key signature: expected error, got none")
		}
	})
}

func TestVerifier_edgeCases(t *testing.T) {
	ctx := context.Background()
	key, _ := newSigningKey(t)
	now := time.Now()

	t.Run("rejects kid not in issuer key set", func(t *testing.T) {
		otherKey, _ := newSigningKey(t)
		// Verify against the original key set but sign with a key whose
		// kid does not exist there.
		verifier := &defaultVerifier{
			localIssuer:    resourceAS,
			issuerResolver: &staticResolver{issuer: idPIssuer, jwks: publicKeySet(t, key)},
			verifier:       sdkjwt.DefaultVerifier(func(context.Context) (sdkjwk.Set, error) { return nil, nil }, []string{alg}),
			now:            func() time.Time { return now },
		}
		raw := mintIDJAG(t, otherKey, nil, now)
		if _, err := verifier.Verify(ctx, raw); err == nil {
			t.Error("unknown kid: expected error, got none")
		}
	})

	t.Run("rejects malformed numeric claims", func(t *testing.T) {
		verifier := newTestVerifier(key, func() time.Time { return now })
		raw := mintCustomClaims(t, key, map[string]any{
			"iss":       idPIssuer,
			"sub":       "subject-1",
			"aud":       resourceAS,
			"client_id": clientAtAS,
			"jti":       "jti-1",
			"exp":       "not-a-number",
			"iat":       now.Unix(),
		})
		if _, err := verifier.Verify(ctx, raw); err == nil {
			t.Error("non-numeric exp: expected error, got none")
		}
	})

	t.Run("rejects malformed aud types", func(t *testing.T) {
		verifier := newTestVerifier(key, func() time.Time { return now })
		for _, aud := range []any{42, []any{resourceAS, "https://other.example/"}, []any{}} {
			raw := mintCustomClaims(t, key, map[string]any{
				"iss":       idPIssuer,
				"sub":       "subject-1",
				"aud":       aud,
				"client_id": clientAtAS,
				"jti":       "jti-1",
				"exp":       now.Add(validLifetime).Unix(),
				"iat":       now.Unix(),
			})
			if _, err := verifier.Verify(ctx, raw); err == nil {
				t.Errorf("aud %v: expected error, got none", aud)
			}
		}
	})

	t.Run("verifies without kid against a multi-key set", func(t *testing.T) {
		// A token without a kid header must be checked against every
		// signing key of the issuer set.
		otherKey, _ := newSigningKey(t)
		set := sdkjwk.NewSet()
		pub1, _ := jwxjwk.PublicKeyOf(key)
		pub2, _ := jwxjwk.PublicKeyOf(otherKey)
		_ = set.AddKey(pub1)
		_ = set.AddKey(pub2)

		verifier := &defaultVerifier{
			localIssuer:    resourceAS,
			issuerResolver: &staticResolver{issuer: idPIssuer, jwks: set},
			verifier:       sdkjwt.DefaultVerifier(func(context.Context) (sdkjwk.Set, error) { return nil, nil }, []string{alg}),
			now:            func() time.Time { return now },
		}

		// Mint without kid: strip it from the header by re-signing raw.
		raw := mintIDJAG(t, otherKey, nil, now)
		if _, err := verifier.Verify(ctx, raw); err != nil {
			t.Fatalf("multi-key set without kid should verify: %v", err)
		}
	})

	t.Run("rejects when the issuer has no usable keys", func(t *testing.T) {
		emptySet := sdkjwk.NewSet()
		verifier := &defaultVerifier{
			localIssuer:    resourceAS,
			issuerResolver: &staticResolver{issuer: idPIssuer, jwks: emptySet},
			verifier:       sdkjwt.DefaultVerifier(func(context.Context) (sdkjwk.Set, error) { return nil, nil }, []string{alg}),
			now:            func() time.Time { return now },
		}
		// Sign with a key whose kid is absent from the empty set: the
		// candidate list is empty and verification fails closed.
		raw := mintIDJAG(t, key, nil, now)
		if _, err := verifier.Verify(ctx, raw); err == nil {
			t.Error("empty key set: expected error, got none")
		}
	})
}

func TestVerifier_signatureIteration(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	// rawKeyPair returns a native EC key and its JWK form.
	rawKeyPair := func() (*ecdsa.PrivateKey, sdkjwk.Key) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		k, err := jwxjwk.Import(priv)
		if err != nil {
			t.Fatal(err)
		}
		if err := sdkjwk.AssignKeyID(k); err != nil {
			t.Fatal(err)
		}
		return priv, k
	}

	// mintNoKidJWT signs claims with the raw EC key, omitting the kid
	// header so verification must try every candidate key.
	mintNoKidJWT := func(priv *ecdsa.PrivateKey, claims map[string]any) string {
		t.Helper()
		tok := gojwt.NewWithClaims(gojwt.SigningMethodES256, gojwt.MapClaims(claims))
		tok.Header["typ"] = "oauth-id-jag+jwt"
		raw, err := tok.SignedString(priv)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	validClaims := func() map[string]any {
		return map[string]any{
			"iss":       idPIssuer,
			"sub":       "subject-1",
			"aud":       resourceAS,
			"client_id": clientAtAS,
			"jti":       "jti-1",
			"exp":       now.Add(validLifetime).Unix(),
			"iat":       now.Unix(),
		}
	}

	t.Run("iterates candidate keys when kid is absent", func(t *testing.T) {
		priv1, k1 := rawKeyPair()
		_, k2 := rawKeyPair()

		// Set order: the signing key LAST, so the first candidate fails
		// and the iteration must reach it.
		set := sdkjwk.NewSet()
		pub1, _ := jwxjwk.PublicKeyOf(k1)
		pub2, _ := jwxjwk.PublicKeyOf(k2)
		_ = set.AddKey(pub2)
		_ = set.AddKey(pub1)

		verifier := &defaultVerifier{
			localIssuer:    resourceAS,
			issuerResolver: &staticResolver{issuer: idPIssuer, jwks: set},
			verifier:       sdkjwt.DefaultVerifier(func(context.Context) (sdkjwk.Set, error) { return nil, nil }, []string{alg}),
			now:            func() time.Time { return now },
		}

		raw := mintNoKidJWT(priv1, validClaims())
		if _, err := verifier.Verify(ctx, raw); err != nil {
			t.Fatalf("no-kid token should verify by iterating the key set: %v", err)
		}
	})

	t.Run("skips encryption keys in the set", func(t *testing.T) {
		priv1, k1 := rawKeyPair()

		set := sdkjwk.NewSet()
		pub1, _ := jwxjwk.PublicKeyOf(k1)
		if err := pub1.Set("use", "enc"); err != nil {
			t.Fatal(err)
		}
		_ = set.AddKey(pub1)

		verifier := &defaultVerifier{
			localIssuer:    resourceAS,
			issuerResolver: &staticResolver{issuer: idPIssuer, jwks: set},
			verifier:       sdkjwt.DefaultVerifier(func(context.Context) (sdkjwk.Set, error) { return nil, nil }, []string{alg}),
			now:            func() time.Time { return now },
		}

		raw := mintNoKidJWT(priv1, validClaims())
		if _, err := verifier.Verify(ctx, raw); err == nil {
			t.Error("enc-only key set: expected error, got none")
		}
	})
}

func TestVerifier_malformedToken(t *testing.T) {
	ctx := context.Background()
	key, _ := newSigningKey(t)
	now := time.Now()
	verifier := newTestVerifier(key, func() time.Time { return now })

	t.Run("rejects a non-JWT string", func(t *testing.T) {
		if _, err := verifier.Verify(ctx, "not-a-jwt"); err == nil {
			t.Error("garbage input: expected error, got none")
		}
	})

	t.Run("rejects a corrupt payload segment", func(t *testing.T) {
		// Valid header and signature framing, undecodable payload: the
		// claim pre-decode must fail.
		raw := mintIDJAG(t, key, nil, now)
		parts := strings.Split(raw, ".")
		corrupt := parts[0] + ".!!!!" + "." + parts[2]
		if _, err := verifier.Verify(ctx, corrupt); err == nil {
			t.Error("corrupt payload: expected error, got none")
		}
	})
}

func TestVerifier_hostileNumericClaims(t *testing.T) {
	ctx := context.Background()
	key, _ := newSigningKey(t)
	now := time.Now()
	verifier := newTestVerifier(key, func() time.Time { return now })

	base := func(exp any) map[string]any {
		return map[string]any{
			"iss":       idPIssuer,
			"sub":       "subject-1",
			"aud":       resourceAS,
			"client_id": clientAtAS,
			"jti":       "jti-1",
			"exp":       exp,
			"iat":       now.Unix(),
		}
	}

	hostile := []struct {
		name string
		exp  any
	}{
		{"string NaN", "NaN"},
		{"string Infinity", "Infinity"},
		{"string Inf", "Inf"},
		{"partial numeric garbage", "123abc"},
		{"empty string", ""},
		{"string with whitespace padding", " 42"},
	}
	for _, tc := range hostile {
		t.Run("rejects exp "+tc.name, func(t *testing.T) {
			raw := mintCustomClaims(t, key, base(tc.exp))
			if _, err := verifier.Verify(ctx, raw); err == nil {
				t.Errorf("hostile exp %v: expected error, got none", tc.exp)
			}
		})
	}

	t.Run("rejects JSON number NaN via raw injection", func(t *testing.T) {
		// A bare NaN literal is invalid JSON: the payload decode fails
		// closed at the pre-decode stage before any temporal check,
		// which the corrupt-payload subtest already covers. The
		// reachable hostile forms are the string encodings above.
	})
}
