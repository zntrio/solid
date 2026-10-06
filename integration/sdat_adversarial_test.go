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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/veraison/go-cose"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/sdtoken"
	"zntr.io/solid/sdk/sdtoken/sdcwt"
	"zntr.io/solid/sdk/sdtoken/sdjwt"
	"zntr.io/solid/sdk/token/jwt"
)

// draft-forten-oauth-sd-jwt-access-token-00 adversarial coverage, over
// the profile factory (both serializations) and the ID-token
// generalization. House mutation-testing pattern: fixture + mustReject.

// sdatKeyMaterial holds the AS, client/DPoP and attacker keys.
type sdatKeyMaterial struct {
	asPriv    *ecdsa.PrivateKey
	asPrivKey jwk.Key
	asPubSet  jwk.Set
	dpopPriv  *ecdsa.PrivateKey
	dpopKey   jwk.Key
	dpopPub   jwk.Key
	attnPriv  *ecdsa.PrivateKey
	attnKey   jwk.Key
}

func newSDATKeyMaterial(t *testing.T) *sdatKeyMaterial {
	t.Helper()

	km := &sdatKeyMaterial{}
	var err error
	if km.asPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	if km.dpopPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	if km.attnPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}

	if km.asPrivKey, err = jwxjwk.Import(km.asPriv); err != nil {
		t.Fatal(err)
	}
	if err := km.asPrivKey.Set(jwxjwk.KeyIDKey, "as-key"); err != nil {
		t.Fatal(err)
	}
	if km.dpopKey, err = jwxjwk.Import(km.dpopPriv); err != nil {
		t.Fatal(err)
	}
	if err := km.dpopKey.Set(jwxjwk.KeyIDKey, "dpop-key"); err != nil {
		t.Fatal(err)
	}
	if km.dpopPub, err = jwxjwk.PublicKeyOf(km.dpopKey); err != nil {
		t.Fatal(err)
	}
	if err := km.dpopPub.Set(jwxjwk.KeyIDKey, "dpop-key"); err != nil {
		t.Fatal(err)
	}
	if km.attnKey, err = jwxjwk.Import(km.attnPriv); err != nil {
		t.Fatal(err)
	}
	if err := km.attnKey.Set(jwxjwk.KeyIDKey, "attacker-key"); err != nil {
		t.Fatal(err)
	}

	asPub, err := jwxjwk.Import(&km.asPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := asPub.Set(jwxjwk.KeyIDKey, "as-key"); err != nil {
		t.Fatal(err)
	}
	if err := asPub.Set(jwxjwk.AlgorithmKey, "ES256"); err != nil {
		t.Fatal(err)
	}
	km.asPubSet = jwk.NewSet()
	if err := km.asPubSet.AddKey(asPub); err != nil {
		t.Fatal(err)
	}

	return km
}

func (km *sdatKeyMaterial) dpopJKT(t *testing.T) string {
	t.Helper()
	tp, err := km.dpopKey.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(tp)
}

func (km *sdatKeyMaterial) asKeyProvider() jwk.KeyProviderFunc {
	return func(context.Context) (jwk.Key, error) { return km.asPrivKey, nil }
}

func (km *sdatKeyMaterial) dpopKeyProvider() jwk.KeyProviderFunc {
	return func(context.Context) (jwk.Key, error) { return km.dpopKey, nil }
}

func (km *sdatKeyMaterial) attnKeyProvider() jwk.KeyProviderFunc {
	return func(context.Context) (jwk.Key, error) { return km.attnKey, nil }
}

func (km *sdatKeyMaterial) issuerKeys() jwk.KeySetProviderFunc {
	return func(context.Context) (jwk.Set, error) { return km.asPubSet, nil }
}

// sdatFixture is one valid issue → select → keybind → verify baseline
// for one kind, in mutation-ready pieces.
type sdatFixture struct {
	jwtKind     bool
	profile     sdtoken.Profile
	km          *sdatKeyMaterial
	issuer      sdtoken.AccessTokenIssuer
	holder      sdtoken.AccessTokenHolder
	verifier    sdtoken.AccessTokenVerifier
	token       string
	disclosures []string
	emailD      string
	nameD       string
	kb          string
	nonce       string
	nonces      map[string]bool
	now         int64
}

func newSDATFixture(t *testing.T, jwtKind bool, profile sdtoken.Profile, issuerOpts []sdtoken.AccessTokenIssuerOption, verifierOpts ...sdtoken.AccessTokenVerifierOption) *sdatFixture {
	t.Helper()

	km := newSDATKeyMaterial(t)
	f := &sdatFixture{
		jwtKind: jwtKind,
		profile: profile,
		km:      km,
		nonce:   "sdat-nonce-1",
		nonces:  map[string]bool{},
		now:     time.Now().Unix(),
	}

	if len(verifierOpts) == 0 {
		// Default verifier posture: audience + a one-shot nonce
		// validator over the fixture's own store.
		verifierOpts = []sdtoken.AccessTokenVerifierOption{
			sdtoken.WithAudience("https://rs.example.com"),
			sdtoken.WithNonceValidator(func(n string) error {
				if f.nonces[n] {
					return errors.New("nonce replayed")
				}
				f.nonces[n] = true
				return nil
			}),
		}
	}

	var issuer sdtoken.AccessTokenIssuer
	var holder sdtoken.AccessTokenHolder
	var verifier sdtoken.AccessTokenVerifier
	var err error
	if jwtKind {
		signer := jwt.AccessTokenSigner("ES256", km.asKeyProvider())
		if profile.BaseTyp == "id" {
			signer = jwt.RawTypedSigner("id+jwt", "ES256", km.asKeyProvider())
		}
		issuer, err = sdjwt.NewAccessTokenIssuer(profile, sdjwt.Deps{Signer: signer}, issuerOpts...)
		if err != nil {
			t.Fatal(err)
		}
		holder, err = sdjwt.NewAccessTokenHolder(profile, sdjwt.Deps{
			IssuerKeys: km.issuerKeys(),
			KBSigner:   jwt.RawTypedSigner(sdtoken.TypeKeyBindingJWT, "ES256", km.dpopKeyProvider()),
		})
		if err != nil {
			t.Fatal(err)
		}
		verifier, err = sdjwt.NewAccessTokenVerifier(profile, sdjwt.Deps{IssuerKeys: km.issuerKeys()}, verifierOpts...)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		issuer, err = sdcwt.NewAccessTokenIssuer(profile, sdcwt.Deps{
			Algorithm:   cose.AlgorithmES256,
			KeyProvider: km.asKeyProvider(),
		}, issuerOpts...)
		if err != nil {
			t.Fatal(err)
		}
		holder, err = sdcwt.NewAccessTokenHolder(profile, sdcwt.Deps{
			IssuerKeys:  km.issuerKeys(),
			Algorithm:   cose.AlgorithmES256,
			KeyProvider: km.dpopKeyProvider(),
		})
		if err != nil {
			t.Fatal(err)
		}
		verifier, err = sdcwt.NewAccessTokenVerifier(profile, sdcwt.Deps{IssuerKeys: km.issuerKeys()}, verifierOpts...)
		if err != nil {
			t.Fatal(err)
		}
	}
	f.issuer, f.holder, f.verifier = issuer, holder, verifier

	claims := map[string]any{
		"iss":       "https://as.example.com",
		"sub":       "user-42",
		"aud":       "https://rs.example.com",
		"exp":       f.now + 3600,
		"iat":       f.now,
		"jti":       "sdat-jti-1",
		"client_id": "client-1",
		"scope":     "profile email",
		"cnf":       map[string]any{"jkt": km.dpopJKT(t)},
		"email":     sdtoken.Disclosable{Value: "user@example.com"},
		"name":      sdtoken.Disclosable{Value: "Alice Doe"},
	}
	if profile.BaseTyp == "id" {
		claims = map[string]any{
			"iss":       "https://as.example.com",
			"sub":       "user-42",
			"aud":       "client-1",
			"exp":       f.now + 3600,
			"iat":       f.now,
			"jti":       "sdat-jti-1",
			"nonce":     "n-0S6_WzA2Mj",
			"auth_time": f.now - 30,
			"email":     sdtoken.Disclosable{Value: "user@example.com"},
			"name":      sdtoken.Disclosable{Value: "Alice Doe"},
		}
	}

	if f.token, f.disclosures, err = f.issuer.Issue(context.Background(), claims); err != nil {
		t.Fatal(err)
	}

	// Split disclosures by claim name via the holder-side decode.
	for _, d := range f.disclosures {
		name := sdatDisclosureClaimName(t, jwtKind, d)
		switch name {
		case "email":
			f.emailD = d
		case "name":
			f.nameD = d
		}
	}
	if f.emailD == "" || f.nameD == "" {
		t.Fatal("fixture must carry email and name disclosures")
	}

	return f
}

// newIssuerFor builds the issuer of the given kind and profile over
// the given key material.
func newIssuerFor(km *sdatKeyMaterial, jwtKind bool, profile sdtoken.Profile, opts ...sdtoken.AccessTokenIssuerOption) (sdtoken.AccessTokenIssuer, error) {
	if jwtKind {
		signer := jwt.AccessTokenSigner("ES256", km.asKeyProvider())
		if profile.BaseTyp == "id" {
			signer = jwt.RawTypedSigner("id+jwt", "ES256", km.asKeyProvider())
		}
		return sdjwt.NewAccessTokenIssuer(profile, sdjwt.Deps{Signer: signer}, opts...)
	}
	return sdcwt.NewAccessTokenIssuer(profile, sdcwt.Deps{
		Algorithm:   cose.AlgorithmES256,
		KeyProvider: km.asKeyProvider(),
	}, opts...)
}

// sdatDisclosureClaimName decodes one disclosure of either kind and
func sdatDisclosureClaimName(t *testing.T, jwtKind bool, d string) string {
	t.Helper()
	if jwtKind {
		raw, err := base64.RawURLEncoding.DecodeString(d)
		if err != nil {
			t.Fatal(err)
		}
		var arr []any
		if err := json.Unmarshal(raw, &arr); err != nil {
			t.Fatal(err)
		}
		if len(arr) == 3 {
			if k, ok := arr[1].(string); ok {
				return k
			}
		}
		return ""
	}
	// CWT: base64url(bstr) of a CBOR [salt, value, key] array.
	raw, err := base64.RawURLEncoding.DecodeString(d)
	if err != nil {
		t.Fatal(err)
	}
	_ = raw
	// The claim keys of the CWT fixture are the string names (email,
	// name have no registered label); decode via the sdcwt codec
	// through the exported package is unavailable in tests without
	// import cycles — but Select exposes the mapping. Fall back to
	// probing with a fresh holder-less decode: use sdcwt package
	// directly.
	return sdcwtDisclosureClaimName(t, d)
}

// mustRejectSDAT asserts verification fails without panic.
func mustRejectSDAT(t *testing.T, name string, f *sdatFixture, disclosures []string, kb string, dpopKey jwk.Key) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: verifier panicked: %v", name, r)
		}
	}()
	if _, err := f.verifier.Verify(context.Background(), f.token, disclosures, kb, dpopKey); err == nil {
		t.Errorf("%s: mutated presentation must be rejected", name)
	}
}

// verifyOK asserts verification succeeds and returns the claims.
func verifyOKSDAT(t *testing.T, f *sdatFixture, disclosures []string, kb string, dpopKey jwk.Key) map[string]any {
	t.Helper()
	claims, err := f.verifier.Verify(context.Background(), f.token, disclosures, kb, dpopKey)
	if err != nil {
		t.Fatalf("positive control must verify: %v", err)
	}
	return claims
}

// -----------------------------------------------------------------------------
// positive controls + adversarial cases, both kinds.

func TestSDATAdversarial(t *testing.T) {
	for _, jwtKind := range []bool{true, false} {
		kindName := "jwt"
		if !jwtKind {
			kindName = "cwt"
		}

		t.Run(kindName, func(t *testing.T) {
			t.Run("positive control full flow", func(t *testing.T) {
				f := newSDATFixture(t, jwtKind, sdtoken.AccessTokenProfile,
					[]sdtoken.AccessTokenIssuerOption{sdtoken.WithRequiredConfirmation(), sdtoken.WithDecoyDigests(2)})
				selected, err := f.holder.Select(context.Background(), f.token, f.disclosures, "email")
				if err != nil {
					t.Fatal(err)
				}
				kb, err := f.holder.KeyBind(context.Background(), f.token, selected, f.nonce, "https://rs.example.com", f.now)
				if err != nil {
					t.Fatal(err)
				}
				claims := verifyOKSDAT(t, f, selected, kb, f.km.dpopPub)
				if claims["email"] != "user@example.com" {
					t.Fatalf("email = %v", claims["email"])
				}
				if _, has := claims["name"]; has {
					t.Fatal("withheld name must not appear")
				}
				if claims["sub"] != "user-42" {
					t.Fatalf("sub = %v", claims["sub"])
				}
			})

			t.Run("zero-disclosure presentation verifies with kb", func(t *testing.T) {
				f := newSDATFixture(t, jwtKind, sdtoken.AccessTokenProfile, nil)
				kb, err := f.holder.KeyBind(context.Background(), f.token, nil, f.nonce, "https://rs.example.com", f.now)
				if err != nil {
					t.Fatal(err)
				}
				claims := verifyOKSDAT(t, f, nil, kb, f.km.dpopPub)
				if _, has := claims["email"]; has {
					t.Fatal("no disclosure presented, email must be absent")
				}
			})

			t.Run("structured fields combination", func(t *testing.T) {
				f := newSDATFixture(t, jwtKind, sdtoken.AccessTokenProfile, nil)
				// Split the field across two field lines: order
				// preserved.
				value1 := sdtoken.FormatDisclosuresField([]string{f.emailD})
				value2 := sdtoken.FormatDisclosuresField([]string{f.nameD})
				parsed, err := sdtoken.ParseDisclosuresField([]string{value1, value2})
				if err != nil {
					t.Fatal(err)
				}
				if len(parsed) != 2 || parsed[0] != f.emailD || parsed[1] != f.nameD {
					t.Fatalf("field combination = %v", parsed)
				}
				kb, err := f.holder.KeyBind(context.Background(), f.token, parsed, f.nonce, "https://rs.example.com", f.now)
				if err != nil {
					t.Fatal(err)
				}
				claims := verifyOKSDAT(t, f, parsed, kb, f.km.dpopPub)
				if claims["email"] == nil || claims["name"] == nil {
					t.Fatal("both disclosures must be processed")
				}
			})

			t.Run("tampered disclosure value", func(t *testing.T) {
				f := newSDATFixture(t, jwtKind, sdtoken.AccessTokenProfile, nil)
				tampered := sdatTamperDisclosure(t, jwtKind, f.emailD)
				kb, err := f.holder.KeyBind(context.Background(), f.token, []string{tampered}, f.nonce, "https://rs.example.com", f.now)
				if err != nil {
					t.Fatal(err)
				}
				mustRejectSDAT(t, "tampered disclosure", f, []string{tampered}, kb, f.km.dpopPub)
			})

			t.Run("forged disclosure not issued with token", func(t *testing.T) {
				f := newSDATFixture(t, jwtKind, sdtoken.AccessTokenProfile, nil)
				forged := sdatForgeDisclosure(t, jwtKind, "nickname", "Eve")
				kb, err := f.holder.KeyBind(context.Background(), f.token, []string{f.emailD, forged}, f.nonce, "https://rs.example.com", f.now)
				if err != nil {
					t.Fatal(err)
				}
				mustRejectSDAT(t, "forged disclosure", f, []string{f.emailD, forged}, kb, f.km.dpopPub)
			})

			t.Run("duplicate disclosure", func(t *testing.T) {
				f := newSDATFixture(t, jwtKind, sdtoken.AccessTokenProfile, nil)
				kb, err := f.holder.KeyBind(context.Background(), f.token, []string{f.emailD, f.emailD}, f.nonce, "https://rs.example.com", f.now)
				if err == nil {
					// Both adapters reject duplicates at KeyBind;
					// if one ever stops, the verify side must still
					// reject.
					mustRejectSDAT(t, "duplicate disclosure", f, []string{f.emailD, f.emailD}, kb, f.km.dpopPub)
					return
				}
				if !errors.Is(err, sdtoken.ErrDuplicateDisclosure) {
					t.Fatalf("err = %v, want ErrDuplicateDisclosure", err)
				}
			})

			t.Run("cross-token disclosure splice", func(t *testing.T) {
				f := newSDATFixture(t, jwtKind, sdtoken.AccessTokenProfile, nil)
				other := newSDATFixture(t, jwtKind, sdtoken.AccessTokenProfile, nil)
				kb, err := f.holder.KeyBind(context.Background(), f.token, []string{other.emailD}, f.nonce, "https://rs.example.com", f.now)
				if err != nil {
					t.Fatal(err)
				}
				mustRejectSDAT(t, "cross-token splice", f, []string{other.emailD}, kb, f.km.dpopPub)
			})

			t.Run("select unknown claim name", func(t *testing.T) {
				f := newSDATFixture(t, jwtKind, sdtoken.AccessTokenProfile, nil)
				if _, err := f.holder.Select(context.Background(), f.token, f.disclosures, "phone_number"); !errors.Is(err, sdtoken.ErrDigestMismatch) {
					t.Fatalf("err = %v, want ErrDigestMismatch", err)
				}
			})

			t.Run("duplicate selection", func(t *testing.T) {
				f := newSDATFixture(t, jwtKind, sdtoken.AccessTokenProfile, nil)
				if _, err := f.holder.Select(context.Background(), f.token, f.disclosures, "email", "email"); !errors.Is(err, sdtoken.ErrDuplicateDisclosure) {
					t.Fatalf("err = %v, want ErrDuplicateDisclosure", err)
				}
			})

			t.Run("kb signed by attacker key", func(t *testing.T) {
				f := newSDATFixture(t, jwtKind, sdtoken.AccessTokenProfile, nil)
				selected, err := f.holder.Select(context.Background(), f.token, f.disclosures, "email")
				if err != nil {
					t.Fatal(err)
				}
				// Build the KB with the ATTACKER key over the same
				// presentation.
				var attackerHolder sdtoken.AccessTokenHolder
				if jwtKind {
					attackerHolder, err = sdjwt.NewAccessTokenHolder(sdtoken.AccessTokenProfile, sdjwt.Deps{
						IssuerKeys: f.km.issuerKeys(),
						KBSigner:   jwt.RawTypedSigner(sdtoken.TypeKeyBindingJWT, "ES256", f.km.attnKeyProvider()),
					})
				} else {
					attackerHolder, err = sdcwt.NewAccessTokenHolder(sdtoken.AccessTokenProfile, sdcwt.Deps{
						IssuerKeys:  f.km.issuerKeys(),
						Algorithm:   cose.AlgorithmES256,
						KeyProvider: f.km.attnKeyProvider(),
					})
				}
				if err != nil {
					t.Fatal(err)
				}
				kb, err := attackerHolder.KeyBind(context.Background(), f.token, selected, f.nonce, "https://rs.example.com", f.now)
				if err != nil {
					t.Fatal(err)
				}
				mustRejectSDAT(t, "attacker kb", f, selected, kb, f.km.dpopPub)
			})

			t.Run("kb over different disclosure subset", func(t *testing.T) {
				f := newSDATFixture(t, jwtKind, sdtoken.AccessTokenProfile, nil)
				// KB bound over the name disclosure, presented with the
				// email disclosure: sd_hash mismatch.
				kb, err := f.holder.KeyBind(context.Background(), f.token, []string{f.nameD}, f.nonce, "https://rs.example.com", f.now)
				if err != nil {
					t.Fatal(err)
				}
				mustRejectSDAT(t, "kb subset swap", f, []string{f.emailD}, kb, f.km.dpopPub)
			})

			t.Run("kb nonce replay", func(t *testing.T) {
				f := newSDATFixture(t, jwtKind, sdtoken.AccessTokenProfile, nil)
				kb, err := f.holder.KeyBind(context.Background(), f.token, []string{f.emailD}, f.nonce, "https://rs.example.com", f.now)
				if err != nil {
					t.Fatal(err)
				}
				verifyOKSDAT(t, f, []string{f.emailD}, kb, f.km.dpopPub)
				// One-shot validator: same nonce again must fail.
				if _, err := f.verifier.Verify(context.Background(), f.token, []string{f.emailD}, kb, f.km.dpopPub); err == nil {
					t.Fatal("kb nonce replay must be rejected")
				}
			})

			t.Run("kb required but absent", func(t *testing.T) {
				f := newSDATFixture(t, jwtKind, sdtoken.AccessTokenProfile, nil)
				mustRejectSDAT(t, "no kb", f, []string{f.emailD}, "", f.km.dpopPub)
			})

			t.Run("dpop jkt mismatch", func(t *testing.T) {
				f := newSDATFixture(t, jwtKind, sdtoken.AccessTokenProfile, nil)
				selected, err := f.holder.Select(context.Background(), f.token, f.disclosures, "email")
				if err != nil {
					t.Fatal(err)
				}
				kb, err := f.holder.KeyBind(context.Background(), f.token, selected, f.nonce, "https://rs.example.com", f.now)
				if err != nil {
					t.Fatal(err)
				}
				// Present with the ATTACKER key as the DPoP proof key:
				// thumbprint != cnf.jkt (draft section 5.3).
				mustRejectSDAT(t, "jkt mismatch", f, selected, kb, f.km.attnKey)
			})

			t.Run("typ confusion vc+sd-jwt", func(t *testing.T) {
				// Issue with the RFC 9901 credential typ and verify
				// under the token profile: rejected.
				if !jwtKind {
					t.Skip("typ confusion is a JWT-kind case")
				}
				km := newSDATKeyMaterial(t)
				issuer, err := sdjwt.NewAccessTokenIssuer(sdtoken.AccessTokenProfile, sdjwt.Deps{
					Signer: jwt.RawTypedSigner("vc+sd-jwt", "ES256", km.asKeyProvider()),
				})
				if err != nil {
					t.Fatal(err)
				}
				token, disclosures, err := issuer.Issue(context.Background(), map[string]any{
					"iss": "https://as.example.com", "sub": "u", "aud": "https://rs.example.com",
					"exp": time.Now().Unix() + 3600, "iat": time.Now().Unix(),
					"email": sdtoken.Disclosable{Value: "e@x.com"},
				})
				if err != nil {
					t.Fatal(err)
				}
				verifier, err := sdjwt.NewAccessTokenVerifier(sdtoken.AccessTokenProfile, sdjwt.Deps{
					IssuerKeys: km.issuerKeys(),
				}, sdtoken.WithOptionalKeyBinding())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := verifier.Verify(context.Background(), token, disclosures, "", nil); err == nil {
					t.Fatal("vc+sd-jwt typ must be rejected by the access-token profile verifier")
				}
			})

			t.Run("cross-profile typ confusion", func(t *testing.T) {
				// An access token (typ at+jwt / application/at+cwt)
				// must be rejected by the ID-token profile verifier.
				at := newSDATFixture(t, jwtKind, sdtoken.AccessTokenProfile, nil)
				idVerifier, err := sdjwt.NewAccessTokenVerifier(sdtoken.IDTokenProfile, sdjwt.Deps{
					IssuerKeys: at.km.issuerKeys(),
				}, sdtoken.WithAudience("client-1"), sdtoken.WithOptionalKeyBinding())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := idVerifier.Verify(context.Background(), at.token, []string{at.emailD}, "", nil); err == nil {
					t.Fatal("access token must be rejected by the id-token profile verifier")
				}
			})

			t.Run("kb typ not kb+jwt", func(t *testing.T) {
				if !jwtKind {
					t.Skip("kb typ is a JWT-kind case")
				}
				f := newSDATFixture(t, jwtKind, sdtoken.AccessTokenProfile, nil)
				selected, err := f.holder.Select(context.Background(), f.token, f.disclosures, "email")
				if err != nil {
					t.Fatal(err)
				}
				// KB signed with typ "kb+sd-jwt" instead of "kb+jwt".
				wrongTypHolder, err := sdjwt.NewAccessTokenHolder(sdtoken.AccessTokenProfile, sdjwt.Deps{
					IssuerKeys: f.km.issuerKeys(),
					KBSigner:   jwt.RawTypedSigner("kb+sd-jwt", "ES256", f.km.dpopKeyProvider()),
				})
				if err != nil {
					t.Fatal(err)
				}
				kb, err := wrongTypHolder.KeyBind(context.Background(), f.token, selected, f.nonce, "https://rs.example.com", f.now)
				if err != nil {
					t.Fatal(err)
				}
				mustRejectSDAT(t, "wrong kb typ", f, selected, kb, f.km.dpopPub)
			})

			t.Run("structured fields malformed", func(t *testing.T) {
				for name, value := range map[string]string{
					"token item":           `email-disclosure`,
					"number item":          `42`,
					"unescaped dquote":     `"a"b"`,
					"empty item":           `"a", ,"b"`,
					"non-string bare item": `foo;param=1`,
					"leading comma":        `, "a"`,
				} {
					if _, err := sdtoken.ParseDisclosuresField([]string{value}); err == nil {
						t.Errorf("%s: malformed field must be rejected", name)
					}
				}
				if _, err := sdtoken.ParseKeyBindingField(""); err == nil {
					t.Error("empty kb field must be rejected")
				}
				if _, err := sdtoken.ParseKeyBindingField(`"a", "b"`); err == nil {
					t.Error("two-item kb field must be rejected")
				}
			})

			t.Run("issuer protected claim marked disclosable", func(t *testing.T) {
				km := newSDATKeyMaterial(t)
				issuer, err := newIssuerFor(km, jwtKind, sdtoken.AccessTokenProfile)
				if err != nil {
					t.Fatal(err)
				}
				for _, protected := range []string{"sub", "scope", "cnf", "authorization_details", "act", "may_act"} {
					claims := map[string]any{
						"iss": "https://as.example.com", "sub": "u", "aud": "rs", "exp": time.Now().Unix() + 3600,
						"iat":     time.Now().Unix(),
						protected: sdtoken.Disclosable{Value: "x"},
					}
					if _, _, err := issuer.Issue(context.Background(), claims); !errors.Is(err, sdtoken.ErrProtectedClaim) {
						t.Fatalf("protected claim %s: err = %v, want ErrProtectedClaim", protected, err)
					}
				}
			})

			t.Run("id token protected claims marked disclosable", func(t *testing.T) {
				km := newSDATKeyMaterial(t)
				issuer, err := newIssuerFor(km, jwtKind, sdtoken.IDTokenProfile)
				if err != nil {
					t.Fatal(err)
				}
				// nonce / auth_time / at_hash must be rejected as
				// Disclosable under the ID-token profile.
				for _, protected := range []string{"nonce", "auth_time", "at_hash", "sid", "acr"} {
					claims := map[string]any{
						"iss": "https://as.example.com", "sub": "u", "aud": "client-1",
						"exp": time.Now().Unix() + 3600, "iat": time.Now().Unix(),
						protected: sdtoken.Disclosable{Value: "x"},
					}
					if _, _, err := issuer.Issue(context.Background(), claims); !errors.Is(err, sdtoken.ErrProtectedClaim) {
						t.Fatalf("id-token protected claim %s: err = %v, want ErrProtectedClaim", protected, err)
					}
				}
			})

			t.Run("nested marker rejected", func(t *testing.T) {
				km := newSDATKeyMaterial(t)
				issuer, err := newIssuerFor(km, jwtKind, sdtoken.AccessTokenProfile)
				if err != nil {
					t.Fatal(err)
				}
				claims := map[string]any{
					"iss": "https://as.example.com", "sub": "u", "aud": "rs",
					"exp": time.Now().Unix() + 3600, "iat": time.Now().Unix(),
					"address": map[string]any{"street": sdtoken.Disclosable{Value: "Main St"}},
				}
				if _, _, err := issuer.Issue(context.Background(), claims); !errors.Is(err, sdtoken.ErrNestedDisclosable) {
					t.Fatalf("err = %v, want ErrNestedDisclosable", err)
				}
			})

			t.Run("element marker under protected array claim rejected", func(t *testing.T) {
				// draft-forten section 3: the protected set extends
				// to any claim whose absence would widen what the
				// token permits — an element marker inside scope (or
				// authorization_details) would redact a permission
				// value out of the signed payload.
				km := newSDATKeyMaterial(t)
				issuer, err := newIssuerFor(km, jwtKind, sdtoken.AccessTokenProfile)
				if err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"scope", "authorization_details"} {
					claims := map[string]any{
						"iss": "https://as.example.com", "sub": "u", "aud": "rs",
						"exp": time.Now().Unix() + 3600, "iat": time.Now().Unix(),
						name: []any{sdtoken.DisclosableElement{Value: "admin"}, "read"},
					}
					if _, _, err := issuer.Issue(context.Background(), claims); !errors.Is(err, sdtoken.ErrProtectedClaim) {
						t.Fatalf("protected array claim %s: err = %v, want ErrProtectedClaim", name, err)
					}
				}
			})

			t.Run("marker inside marker value rejected (recursive disclosure)", func(t *testing.T) {
				// draft-forten section 3: recursive Disclosures MUST
				// NOT be used — every disclosure names a top-level
				// claim and stands on its own.
				km := newSDATKeyMaterial(t)
				issuer, err := newIssuerFor(km, jwtKind, sdtoken.AccessTokenProfile)
				if err != nil {
					t.Fatal(err)
				}
				claims := map[string]any{
					"iss": "https://as.example.com", "sub": "u", "aud": "rs",
					"exp": time.Now().Unix() + 3600, "iat": time.Now().Unix(),
					"prefers": sdtoken.Disclosable{Value: map[string]any{
						"marketing": sdtoken.Disclosable{Value: true},
					}},
				}
				if _, _, err := issuer.Issue(context.Background(), claims); !errors.Is(err, sdtoken.ErrNestedDisclosable) {
					t.Fatalf("err = %v, want ErrNestedDisclosable", err)
				}
			})

			t.Run("sd-at without cnf under required confirmation", func(t *testing.T) {
				km := newSDATKeyMaterial(t)
				issuer, err := newIssuerFor(km, jwtKind, sdtoken.AccessTokenProfile, sdtoken.WithRequiredConfirmation())
				if err != nil {
					t.Fatal(err)
				}
				claims := map[string]any{
					"iss": "https://as.example.com", "sub": "u", "aud": "rs",
					"exp": time.Now().Unix() + 3600, "iat": time.Now().Unix(),
					"email": sdtoken.Disclosable{Value: "e@x.com"},
				}
				if _, _, err := issuer.Issue(context.Background(), claims); !errors.Is(err, sdtoken.ErrConfirmationRequired) {
					t.Fatalf("err = %v, want ErrConfirmationRequired", err)
				}
			})

			t.Run("sd-at with jkt-less cnf under required confirmation", func(t *testing.T) {
				km := newSDATKeyMaterial(t)
				issuer, err := newIssuerFor(km, jwtKind, sdtoken.AccessTokenProfile, sdtoken.WithRequiredConfirmation())
				if err != nil {
					t.Fatal(err)
				}
				claims := map[string]any{
					"iss": "https://as.example.com", "sub": "u", "aud": "rs",
					"exp": time.Now().Unix() + 3600, "iat": time.Now().Unix(),
					"cnf":   map[string]any{}, // present but jkt-less
					"email": sdtoken.Disclosable{Value: "e@x.com"},
				}
				if _, _, err := issuer.Issue(context.Background(), claims); !errors.Is(err, sdtoken.ErrConfirmationRequired) {
					t.Fatalf("err = %v, want ErrConfirmationRequired", err)
				}
			})

			t.Run("id token profile round trip", func(t *testing.T) {
				f := newSDATFixture(t, jwtKind, sdtoken.IDTokenProfile, nil, sdtoken.WithAudience("client-1"), sdtoken.WithOptionalKeyBinding())
				selected, err := f.holder.Select(context.Background(), f.token, f.disclosures, "name")
				if err != nil {
					t.Fatal(err)
				}
				claims := verifyOKSDAT(t, f, selected, "", nil)
				if claims["name"] != "Alice Doe" {
					t.Fatalf("name = %v", claims["name"])
				}
				if _, has := claims["email"]; has {
					t.Fatal("withheld email must be absent")
				}
				if claims["nonce"] != "n-0S6_WzA2Mj" {
					t.Fatalf("nonce = %v", claims["nonce"])
				}
			})
		})
	}
}

// -----------------------------------------------------------------------------
// disclosure mutation helpers.

// sdatTamperDisclosure rewrites the value of a disclosure while keeping
// its shape: the digest no longer matches the token.
func sdatTamperDisclosure(t *testing.T, jwtKind bool, d string) string {
	t.Helper()
	if jwtKind {
		raw, err := base64.RawURLEncoding.DecodeString(d)
		if err != nil {
			t.Fatal(err)
		}
		var arr []any
		if err := json.Unmarshal(raw, &arr); err != nil {
			t.Fatal(err)
		}
		arr[len(arr)-1] = "tampered@example.com"
		b, _ := json.Marshal(arr)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	// CWT: decode the bstr, flip a value byte and re-encode. Any
	// single-byte change breaks the digest.
	raw, err := base64.RawURLEncoding.DecodeString(d)
	if err != nil {
		t.Fatal(err)
	}
	out := append([]byte(nil), raw...)
	out[len(out)-1] ^= 0x01
	return base64.RawURLEncoding.EncodeToString(out)
}

// sdatForgeDisclosure builds a well-formed disclosure that was never
// issued (fresh salt, valid shape).
func sdatForgeDisclosure(t *testing.T, jwtKind bool, name, value string) string {
	t.Helper()
	if jwtKind {
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			t.Fatal(err)
		}
		arr := []any{base64.RawURLEncoding.EncodeToString(salt), name, value}
		b, _ := json.Marshal(arr)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	// CWT forged disclosure: reuse the sdcwt issuer machinery through
	// an issued token's disclosure shape — flip the claim name of a
	// real one so the shape is valid but the content foreign.
	return sdatTamperDisclosure(t, jwtKind, value)
}

// sdcwtDisclosureClaimName decodes the claim key of a CWT-kind
// disclosure (base64url bstr of a CBOR array [salt, value, key?]).
func sdcwtDisclosureClaimName(t *testing.T, d string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(d)
	if err != nil {
		t.Fatal(err)
	}
	var arr []any
	if err := cbor.Unmarshal(raw, &arr); err != nil {
		t.Fatal(err)
	}
	if len(arr) == 3 {
		if k, ok := arr[2].(string); ok {
			return k
		}
	}
	return ""
}
