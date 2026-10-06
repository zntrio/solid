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

// Selectively disclosable access tokens and ID tokens
// (draft-forten-oauth-sd-jwt-access-token-00): an assembly of the solid
// SDK demonstrating issue → present → verify across an in-process
// authorization server and resource server, in both the JWT (draft)
// and CWT (format-agnostic analog) serializations, plus the ID-token
// profile generalization.
//
// The token itself carries only digests (_sd / _sd_alg, or
// redacted_claim_keys + sd_alg) and keeps its ordinary typ (at+jwt /
// application/at+cwt); the Disclosures travel in the token response
// `disclosures` parameter and, per request, in the SD-JWT-Disclosures
// HTTP field (RFC 9651 Structured Fields), with the key binding JWT in
// SD-JWT-Key-Binding signed by the DPoP proof key.
//
// Run with: go run ./examples/sdtoken [--format=cwt]
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/veraison/go-cose"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/sdtoken"
	"zntr.io/solid/sdk/sdtoken/sdcwt"
	"zntr.io/solid/sdk/sdtoken/sdjwt"
	"zntr.io/solid/sdk/token/jwt"
)

// Example claim constants (goconst): shared across the access- and
// ID-token fixtures.
const (
	exampleIssuer  = "https://as.example.com"
	exampleSubject = "user-42"
	exampleEmail   = "alice@example.com"
	exampleName    = "Alice Doe"

	claimIss   = "iss"
	claimSub   = "sub"
	claimAud   = "aud"
	claimExp   = "exp"
	claimIat   = "iat"
	claimJti   = "jti"
	claimEmail = "email"
	claimName  = "name"
)

// example key material: one AS signing key, one client DPoP key.
type keyMaterial struct {
	asKeyPriv    jwk.Key
	asKeyPrivAny *ecdsa.PrivateKey
	asPubSet     jwk.Set
	dpopPriv     jwk.Key
	dpopPrivAny  *ecdsa.PrivateKey
	dpopPub      jwk.Key
}

func newKeyMaterial() (*keyMaterial, error) {
	km := &keyMaterial{}

	asPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	dpopPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	if km.asKeyPriv, err = importKey(asPriv, "as-signing-key"); err != nil {
		return nil, err
	}
	if km.dpopPriv, err = importKey(dpopPriv, "client-dpop-key"); err != nil {
		return nil, err
	}
	if km.dpopPub, err = publicKeyOf(km.dpopPriv, "client-dpop-key"); err != nil {
		return nil, err
	}

	if km.asPubSet, err = issuerKeySet(asPriv, "as-signing-key"); err != nil {
		return nil, err
	}

	km.asKeyPrivAny = asPriv
	km.dpopPrivAny = dpopPriv
	return km, nil
}

// publicKeyOf derives the public JWK of a private one with the given kid.
func publicKeyOf(priv jwk.Key, kid string) (jwk.Key, error) {
	pub, err := jwxjwk.PublicKeyOf(priv)
	if err != nil {
		return nil, err
	}
	if err := pub.Set(jwxjwk.KeyIDKey, kid); err != nil {
		return nil, err
	}
	return pub, nil
}

// issuerKeySet materializes the AS public-key set of one signing key.
func issuerKeySet(priv *ecdsa.PrivateKey, kid string) (jwk.Set, error) {
	asPub, err := jwxjwk.Import(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	if err := asPub.Set(jwxjwk.KeyIDKey, kid); err != nil {
		return nil, err
	}
	if err := asPub.Set(jwxjwk.AlgorithmKey, "ES256"); err != nil {
		return nil, err
	}
	set := jwk.NewSet()
	if err := set.AddKey(asPub); err != nil {
		return nil, err
	}
	return set, nil
}

// importKey materializes a private JWK with the given kid.
func importKey(priv *ecdsa.PrivateKey, kid string) (jwk.Key, error) {
	key, err := jwxjwk.Import(priv)
	if err != nil {
		return nil, err
	}
	if err := key.Set(jwxjwk.KeyIDKey, kid); err != nil {
		return nil, err
	}
	return key, nil
}

func (km *keyMaterial) dpopJKT() (string, error) {
	tp, err := km.dpopPub.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

func (km *keyMaterial) asKeyProvider() jwk.KeyProviderFunc {
	return func(context.Context) (jwk.Key, error) { return km.asKeyPriv, nil }
}

func (km *keyMaterial) dpopKeyProvider() jwk.KeyProviderFunc {
	return func(context.Context) (jwk.Key, error) { return km.dpopPriv, nil }
}

func (km *keyMaterial) issuerKeys() jwk.KeySetProviderFunc {
	return func(context.Context) (jwk.Set, error) { return km.asPubSet, nil }
}

// sdFlow runs the full issue → present → verify flow for one token
// class × serialization kind and returns the RS-verified processed
// payload.
func sdFlow(km *keyMaterial, jwtKind bool, profile sdtoken.Profile, opts *flowOptions) (map[string]any, error) {
	ctx := context.Background()
	now := time.Now().Unix()

	// ------------------------------------------------------------------
	// AS: issue the SD token. The token value carries digests only; the
	// Disclosures travel separately (a token response `disclosures`
	// parameter for access tokens).
	issuerOpts := append([]sdtoken.AccessTokenIssuerOption{sdtoken.WithDecoyDigests(2)}, opts.issuerOpts...)
	issuer, holder, verifier, err := sdRoles(km, jwtKind, profile, issuerOpts, opts.verifierOpts)
	if err != nil {
		return nil, err
	}

	jkt, err := km.dpopJKT()
	if err != nil {
		return nil, err
	}

	claims := map[string]any{
		claimIss:    exampleIssuer,
		claimSub:    exampleSubject,
		claimAud:    opts.audience,
		claimExp:    now + 3600,
		claimIat:    now,
		claimJti:    opts.jti,
		"client_id": "confidential-client-1",
		"scope":     "profile email",
		"cnf":       map[string]any{"jkt": jkt},
		claimEmail:  sdtoken.Disclosable{Value: exampleEmail},
		claimName:   sdtoken.Disclosable{Value: exampleName},
	}
	if profile.BaseTyp == "id" {
		claims = map[string]any{
			claimIss:    exampleIssuer,
			claimSub:    exampleSubject,
			claimAud:    opts.audience,
			claimExp:    now + 3600,
			claimIat:    now,
			claimJti:    opts.jti,
			"nonce":     "n-0S6_WzA2Mj",
			"auth_time": now - 30,
			claimEmail:  sdtoken.Disclosable{Value: exampleEmail},
			claimName:   sdtoken.Disclosable{Value: exampleName},
		}
	}

	tokenString, disclosures, err := issuer.Issue(ctx, claims)
	if err != nil {
		return nil, err
	}

	// ------------------------------------------------------------------
	// Client: select the disclosures to present (by claim name, never
	// parsing the token — draft-forten section 4), then bind the DPoP
	// key over the presentation.
	selected, err := holder.Select(ctx, tokenString, disclosures, opts.presentClaims...)
	if err != nil {
		return nil, err
	}

	// Key binding (draft-forten section 4): the KB JWT travels in the
	// SD-JWT-Key-Binding field, signed by the DPoP proof key.
	keyBinding := ""
	if opts.requireKB {
		keyBinding, err = holder.KeyBind(ctx, tokenString, selected, "rs-nonce-1", opts.audience, now)
		if err != nil {
			return nil, err
		}
	}

	// ------------------------------------------------------------------
	// RS: verify the SD token presentation. In a deployment the RS
	// first verifies the DPoP proof and extracts its JWK (the thumbprint
	// equality with cnf.jkt is enforced by the verifier); here the
	// client's public key plays that role.

	// Structured Fields round trip (RFC 9651): the client renders the
	// SD-JWT-Disclosures field, the RS parses it.
	fieldValue := sdtoken.FormatDisclosuresField(selected)
	parsed, err := sdtoken.ParseDisclosuresField([]string{fieldValue})
	if err != nil {
		return nil, fmt.Errorf("unable to parse disclosures field: %w", err)
	}
	if strings.Join(parsed, "\x00") != strings.Join(selected, "\x00") {
		return nil, fmt.Errorf("structured fields round trip mismatch")
	}
	var kbFieldValue string
	if keyBinding != "" {
		kbFieldValue = sdtoken.FormatKeyBindingField(keyBinding)
		kbFieldValue, err = sdtoken.ParseKeyBindingField(kbFieldValue)
		if err != nil {
			return nil, fmt.Errorf("unable to parse key binding field: %w", err)
		}
	}

	processed, err := verifier.Verify(ctx, tokenString, parsed, kbFieldValue, km.dpopPub)
	if err != nil {
		return nil, err
	}
	return processed, nil
}

// sdRoles assembles the issuer / holder / verifier of one token class
// in the chosen serialization, with the construction-time options.
func sdRoles(km *keyMaterial, jwtKind bool, profile sdtoken.Profile, issuerOpts []sdtoken.AccessTokenIssuerOption, verifierOpts []sdtoken.AccessTokenVerifierOption) (sdtoken.AccessTokenIssuer, sdtoken.AccessTokenHolder, sdtoken.AccessTokenVerifier, error) {
	if jwtKind {
		signer := jwt.AccessTokenSigner("ES256", km.asKeyProvider())
		if profile.BaseTyp == "id" {
			signer = jwt.RawTypedSigner("id+jwt", "ES256", km.asKeyProvider())
		}
		issuer, err := sdjwt.NewAccessTokenIssuer(profile, sdjwt.Deps{Signer: signer}, issuerOpts...)
		if err != nil {
			return nil, nil, nil, err
		}
		holder, err := sdjwt.NewAccessTokenHolder(profile, sdjwt.Deps{
			IssuerKeys: km.issuerKeys(),
			KBSigner:   jwt.RawTypedSigner(sdtoken.TypeKeyBindingJWT, "ES256", km.dpopKeyProvider()),
		})
		if err != nil {
			return nil, nil, nil, err
		}
		verifier, err := sdjwt.NewAccessTokenVerifier(profile, sdjwt.Deps{IssuerKeys: km.issuerKeys()}, verifierOpts...)
		if err != nil {
			return nil, nil, nil, err
		}
		return issuer, holder, verifier, nil
	}
	issuer, err := sdcwt.NewAccessTokenIssuer(profile, sdcwt.Deps{
		Algorithm:   cose.AlgorithmES256,
		KeyProvider: km.asKeyProvider(),
	}, issuerOpts...)
	if err != nil {
		return nil, nil, nil, err
	}
	holder, err := sdcwt.NewAccessTokenHolder(profile, sdcwt.Deps{
		IssuerKeys:  km.issuerKeys(),
		Algorithm:   cose.AlgorithmES256,
		KeyProvider: km.dpopKeyProvider(),
	})
	if err != nil {
		return nil, nil, nil, err
	}
	verifier, err := sdcwt.NewAccessTokenVerifier(profile, sdcwt.Deps{IssuerKeys: km.issuerKeys()}, verifierOpts...)
	if err != nil {
		return nil, nil, nil, err
	}
	return issuer, holder, verifier, nil
}

type flowOptions struct {
	audience      string
	jti           string
	presentClaims []string
	requireKB     bool
	issuerOpts    []sdtoken.AccessTokenIssuerOption
	verifierOpts  []sdtoken.AccessTokenVerifierOption
}

func main() {
	format := flag.String("format", "jwt", "serialization format: jwt (draft-forten) or cwt (SD-CWT analog)")
	flag.Parse()

	jwtKind := true
	formatName := "JWT (draft-forten, RFC 9901 serialization)"
	if *format == "cwt" {
		jwtKind = false
		formatName = "CWT (SD-CWT serialization, draft-ietf-spice-sd-cwt-08 shape)"
	}

	km, err := newKeyMaterial()
	if err != nil {
		log.Fatal(err)
	}
	jkt, err := km.dpopJKT()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("draft-forten-oauth-sd-jwt-access-token-00 — selective disclosure without changing the token\n")
	fmt.Printf("serialization: %s\n\n", formatName)

	// ------------------------------------------------------------------
	// Access token: DPoP-bound, KB required at the RS, email presented,
	// name withheld.
	nonceStore := map[string]bool{}
	atProcessed, err := sdFlow(km, jwtKind, sdtoken.AccessTokenProfile, &flowOptions{
		audience:      "https://rs.example.com",
		jti:           "at-example-1",
		presentClaims: []string{claimEmail},
		requireKB:     true,
		issuerOpts:    []sdtoken.AccessTokenIssuerOption{sdtoken.WithRequiredConfirmation()},
		verifierOpts: []sdtoken.AccessTokenVerifierOption{
			sdtoken.WithAudience("https://rs.example.com"),
			sdtoken.WithNonceValidator(func(n string) error {
				if nonceStore[n] {
					return fmt.Errorf("nonce replay")
				}
				nonceStore[n] = true
				return nil
			}),
		},
	})
	if err != nil {
		log.Fatalf("access token flow: %v", err)
	}

	fmt.Println("== access token (DPoP-bound, cnf.jkt =", jkt[:12]+"...) ==")
	fmt.Printf("RS-verified processed payload: email=%v name=%v\n", atProcessed["email"], atProcessed["name"])
	if atProcessed["name"] != nil {
		log.Fatal("withheld name leaked into the processed payload")
	}
	if atProcessed["email"] != "alice@example.com" {
		log.Fatal("disclosed email missing from the processed payload")
	}

	// ------------------------------------------------------------------
	// ID token: the profile-factory generalization. nonce / auth_time
	// protected, email presented, no KB (OIDC ID tokens are not DPoP
	// proof-presented).
	idProcessed, err := sdFlow(km, jwtKind, sdtoken.IDTokenProfile, &flowOptions{
		audience:      "confidential-client-1",
		jti:           "id-example-1",
		presentClaims: []string{claimEmail},
		requireKB:     false,
		verifierOpts: []sdtoken.AccessTokenVerifierOption{
			sdtoken.WithAudience("confidential-client-1"),
			sdtoken.WithOptionalKeyBinding(),
		},
	})
	if err != nil {
		log.Fatalf("id token flow: %v", err)
	}

	fmt.Println("\n== id token (profile generalization, typ id+jwt / application/id+cwt) ==")
	fmt.Printf("client-verified claims: nonce=%v auth_time=%v email=%v name=%v\n",
		idProcessed["nonce"], idProcessed["auth_time"], idProcessed["email"], idProcessed["name"])
	if idProcessed["name"] != nil {
		log.Fatal("withheld name leaked into the id token payload")
	}

	// ------------------------------------------------------------------
	// Raw payload display: digests in, no cleartext user claims.
	fmt.Println("\n== raw token payloads (digests only) ==")
	rawPayload(km, jwtKind, sdtoken.AccessTokenProfile, "https://rs.example.com", "at-raw-1", jkt)

	fmt.Println("\nflow verified end-to-end: digests in the token, values only in the disclosures.")
}

func rawPayload(km *keyMaterial, jwtKind bool, profile sdtoken.Profile, audience, jti, jkt string) {
	ctx := context.Background()
	now := time.Now().Unix()

	var issuer sdtoken.AccessTokenIssuer
	var err error
	if jwtKind {
		issuer, err = sdjwt.NewAccessTokenIssuer(profile, sdjwt.Deps{
			Signer: jwt.AccessTokenSigner("ES256", km.asKeyProvider()),
		})
	} else {
		issuer, err = sdcwt.NewAccessTokenIssuer(profile, sdcwt.Deps{
			Algorithm:   cose.AlgorithmES256,
			KeyProvider: km.asKeyProvider(),
		})
	}
	if err != nil {
		log.Fatal(err)
	}
	claims := map[string]any{
		"iss": "https://as.example.com", "sub": "user-42", "aud": audience,
		"exp": now + 3600, "iat": now, "jti": jti, "cnf": map[string]any{"jkt": jkt},
		"email": sdtoken.Disclosable{Value: "alice@example.com"},
		"name":  sdtoken.Disclosable{Value: "Alice Doe"},
	}
	tokenString, _, err := issuer.Issue(ctx, claims)
	if err != nil {
		log.Fatal(err)
	}

	if jwtKind {
		parts := strings.Split(tokenString, ".")
		payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			log.Fatal(err)
		}
		var pretty any
		if err := json.Unmarshal(payloadJSON, &pretty); err != nil {
			log.Fatal(err)
		}
		out, _ := json.MarshalIndent(pretty, "  ", "  ")
		fmt.Println("  JWT payload:", string(out))
	} else {
		fmt.Printf("  CWT (COSE_Sign1, base64url): %s... (carries redacted_claim_keys + sd_alg, no cleartext)\n", tokenString[:48])
	}
}
