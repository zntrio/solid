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
	"crypto"
	"encoding/base64"
	"fmt"
	"strings"

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/sdtoken"
	"zntr.io/solid/sdk/token"
	"zntr.io/solid/sdk/token/jwt"
	"zntr.io/solid/sdk/types"
)

// draft-forten-oauth-sd-jwt-access-token-00 profile adapter over the
// RFC 9901 machinery of this package. The token itself is an ordinary
// JWT (typ "at+jwt" for the access-token profile, "id+jwt" for the
// ID-token one) carrying _sd / _sd_alg; the Disclosures travel out of
// band — in the token response `disclosures` parameter and, per
// request, in the SD-JWT-Disclosures HTTP field — with an optional
// key-binding JWT in SD-JWT-Key-Binding signed by the DPoP proof key.

// -----------------------------------------------------------------------------
// Dependencies.

// Deps carries the serialization dependencies of the SD-JWT profile
// roles. Which members are required depends on the role; the
// constructors fail closed (return an error) on a missing one.
type Deps struct {
	// Signer signs the token itself (required: issuer), e.g.
	// jwt.AccessTokenSigner("ES256", kp) for the access-token
	// profile, jwt.RawTypedSigner("id+jwt", "ES256", kp) for the
	// ID-token one.
	Signer token.Signer

	// IssuerKeys resolves the issuer public-key set (required: holder,
	// verifier).
	IssuerKeys jwk.KeySetProviderFunc

	// KBSigner signs the key binding JWT (required: holder): the
	// holder key is the DPoP proof key, e.g.
	// jwt.RawTypedSigner(sdtoken.TypeKeyBindingJWT, "ES256", holderKP).
	KBSigner token.Signer
}

type issuerAdapter struct {
	profile sdtoken.Profile
	signer  token.Signer
	cfg     *sdtoken.IssueSettings
}

// NewAccessTokenIssuer returns the draft-forten SD-JWT AccessTokenIssuer
// of the given profile, enforcing the profile rules on every Issue call.
// Role-required dependencies are validated at construction.
func NewAccessTokenIssuer(profile sdtoken.Profile, deps Deps, opts ...sdtoken.AccessTokenIssuerOption) (sdtoken.AccessTokenIssuer, error) {
	if deps.Signer == nil {
		return nil, fmt.Errorf("unable to build the SD-JWT issuer: Signer is required")
	}
	cfg := sdtoken.ResolveIssueSettings(opts...)
	return &issuerAdapter{
		profile: profile,
		signer:  deps.Signer,
		cfg:     cfg,
	}, nil
}

// Issue implements the draft-forten section 3 issuance: an ordinary
// JWT carrying digests only, disclosures returned separately (no
// tildes: the response carries the JWT alone).
func (a *issuerAdapter) Issue(ctx context.Context, claims map[string]any) (tokenString string, disclosures []string, err error) {
	if claims == nil {
		return "", nil, fmt.Errorf("%w: claims map is nil", sdtoken.ErrInvalidToken)
	}
	if a.signer == nil {
		return "", nil, fmt.Errorf("%w: no signer configured", sdtoken.ErrInvalidToken)
	}

	// Profile rules first: protected claims and nested markers are
	// rejected before any encoding work.
	if errRules := sdtoken.ValidateDisclosableClaims(a.profile, claims); errRules != nil {
		return "", nil, errRules
	}

	// Optional draft-forten section 6 posture: SD access tokens MUST
	// be DPoP-bound — require a non-empty cnf.jkt (the §5.3 binding
	// is jkt-based; a jkt-less cnf would fail every verification).
	if a.cfg.RequiredConfirmation && !sdtoken.HasJKT(claims) {
		return "", nil, fmt.Errorf("%w: the %s profile requires a cnf.jkt confirmation", sdtoken.ErrConfirmationRequired, a.profile.Name)
	}

	// Translate the root options to the RFC 9901 issuer options.
	var issueOpts []IssueOption
	if a.cfg.SaltFactory != nil {
		issueOpts = append(issueOpts, WithSaltFactory(a.cfg.SaltFactory))
	}
	if a.cfg.DecoyDigests > 0 {
		issueOpts = append(issueOpts, WithDecoyDigests(a.cfg.DecoyDigests))
	}

	// Deep-copy the claims: the RFC 9901 issuer replaces markers with
	// digests IN the tree (map deletions AND array element rewrites),
	// so the caller's map and slices stay intact.
	copied := sdtoken.CloneClaims(claims)

	inner := NewIssuer(a.signer)
	sdjwtCompact, disclosures, err := inner.Issue(ctx, copied, issueOpts...)
	if err != nil {
		return "", nil, err
	}

	// The draft-forten token string is the issuer-signed JWT alone
	// (Parse of the compact form; the tilde tail never leaves the AS).
	parsed, err := Parse(sdjwtCompact)
	if err != nil {
		return "", nil, fmt.Errorf("%w: unable to split issued sd-jwt: %w", sdtoken.ErrInvalidToken, err)
	}
	return parsed.IssuerSignedJWT, disclosures, nil
}

// -----------------------------------------------------------------------------
// Holder.

type holderAdapter struct {
	inner Holder
}

// NewAccessTokenHolder returns the draft-forten SD-JWT AccessTokenHolder
// of the given profile. Role-required dependencies are validated at
// construction.
func NewAccessTokenHolder(profile sdtoken.Profile, deps Deps, opts ...sdtoken.AccessTokenHolderOption) (sdtoken.AccessTokenHolder, error) {
	if deps.IssuerKeys == nil {
		return nil, fmt.Errorf("unable to build the SD-JWT holder: IssuerKeys is required")
	}
	if deps.KBSigner == nil {
		return nil, fmt.Errorf("unable to build the SD-JWT holder: KBSigner is required")
	}
	_ = sdtoken.ResolveHolderSettings(opts...) // seam: no holder setting exists yet
	return &holderAdapter{
		inner: NewHolder(jwt.DefaultVerifier(deps.IssuerKeys, jwt.SupportedSignAlgorithms()), deps.KBSigner),
	}, nil
}

// Select implements the draft-forten section 4 client rule: pick the
// disclosures carrying the named claims from the set received with the
// token, by claim name, WITHOUT parsing or inspecting the token.
func (a *holderAdapter) Select(ctx context.Context, tokenString string, disclosures []string, claimNames ...string) ([]string, error) {
	_ = ctx         // no context-dependent work: local decoding only
	_ = tokenString // deliberately unread: draft-forten section 4

	// Decode each disclosure; key it by its claim name.
	byName := make(map[string]string, len(disclosures))
	seenWire := make(map[string]struct{}, len(disclosures))
	for _, d := range disclosures {
		if _, dup := seenWire[d]; dup {
			return nil, fmt.Errorf("%w: the same disclosure was received twice", sdtoken.ErrDuplicateDisclosure)
		}
		seenWire[d] = struct{}{}

		decoded, err := decodeDisclosure(d)
		if err != nil {
			return nil, err
		}
		name, ok := decoded.ClaimKey.(string)
		if !ok {
			// Element-form and decoy disclosures carry no claim name;
			// they are never selected by name.
			continue
		}
		if _, exists := byName[name]; exists {
			return nil, fmt.Errorf("%w: two disclosures claim %q", sdtoken.ErrDuplicateDisclosure, name)
		}
		byName[name] = d
	}

	// Select by claim name; a requested name not present in the
	// disclosure set is rejected (the client must not present a
	// disclosure the AS never issued for this token).
	var selected []string
	seen := make(map[string]struct{}, len(claimNames))
	for _, name := range claimNames {
		if _, dup := seen[name]; dup {
			return nil, fmt.Errorf("%w: claim %q selected twice", sdtoken.ErrDuplicateDisclosure, name)
		}
		seen[name] = struct{}{}

		d, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("%w: no disclosure carries claim %q", sdtoken.ErrDigestMismatch, name)
		}
		selected = append(selected, d)
	}
	return selected, nil
}

// KeyBind implements the draft-forten section 4 key binding: assemble
// token~D1~...~Dn~ (the RFC 9901 presentation form of exactly the
// selected disclosures) and delegate to the RFC 9901 holder KeyBind —
// its sd_hash / trailing-tilde semantics are exactly the draft's.
// A duplicate selection is rejected upfront (the SD-JWT-Key-Binding
// field MUST NOT carry the same disclosure twice).
func (a *holderAdapter) KeyBind(ctx context.Context, tokenString string, selected []string, nonce, audience string, issuedAt int64) (string, error) {
	seen := make(map[string]struct{}, len(selected))
	for _, d := range selected {
		if _, dup := seen[d]; dup {
			return "", fmt.Errorf("%w: disclosure presented twice", sdtoken.ErrDuplicateDisclosure)
		}
		seen[d] = struct{}{}
	}
	presentation := tokenString
	for _, d := range selected {
		presentation += "~" + d
	}
	presentation += "~"
	sdkbt, err := a.inner.KeyBind(ctx, presentation, nonce, audience, issuedAt)
	if err != nil {
		return "", err
	}
	// The RFC 9901 holder returns the full SD-JWT+KB (presentation
	// without the trailing "~", plus the KB-JWT). The draft-forten
	// SD-JWT-Key-Binding field carries the KB-JWT alone: return the
	// trailing component.
	idx := strings.LastIndex(sdkbt, "~")
	if idx < 0 {
		return "", fmt.Errorf("%w: unable to split the key binding jwt", sdtoken.ErrInvalidKeyBinding)
	}
	return sdkbt[idx+1:], nil
}

// -----------------------------------------------------------------------------
// Verifier.

type verifierAdapter struct {
	profile sdtoken.Profile
	keys    jwk.KeySetProviderFunc
	cfg     *sdtoken.VerifySettings
}

// NewAccessTokenVerifier returns the draft-forten SD-JWT
// AccessTokenVerifier of the given profile. Role-required dependencies
// are validated at construction.
func NewAccessTokenVerifier(profile sdtoken.Profile, deps Deps, opts ...sdtoken.AccessTokenVerifierOption) (sdtoken.AccessTokenVerifier, error) {
	if deps.IssuerKeys == nil {
		return nil, fmt.Errorf("unable to build the SD-JWT verifier: IssuerKeys is required")
	}
	return &verifierAdapter{
		profile: profile,
		keys:    deps.IssuerKeys,
		cfg:     sdtoken.NewVerifySettings(opts...),
	}, nil
}

// Verify implements the draft-forten section 5 processing: assemble
// the presentation (token + presented disclosures + key binding), run
// the RFC 9901 verifier with the profile typ expectation and the DPoP
// key binding seam, then enforce the section 5.3 thumbprint equality
// (DPoP proof JWK thumbprint == cnf.jkt).
//
//nolint:gocyclo // linear draft-forten section 5 verification chain
func (a *verifierAdapter) Verify(ctx context.Context, tokenString string, disclosures []string, keyBinding string, dpopProofJWK jwk.Key) (map[string]any, error) {
	if a.keys == nil {
		return nil, fmt.Errorf("%w: no issuer keys configured", sdtoken.ErrInvalidToken)
	}

	// Assemble the RFC 9901 compact form: JWT~D1~...~Dn~ then the
	// KB-JWT, or the bare trailing "~" with no binding (section 5.1:
	// holds with zero Disclosures too).
	presentation := tokenString
	for _, d := range disclosures {
		presentation += "~" + d
	}
	if keyBinding != "" {
		presentation += "~" + keyBinding
	} else {
		presentation += "~"
	}

	// Verifier options: exact profile typ (draft-forten section 3 keeps
	// RFC 9068's at+jwt — the RFC 9901 "+sd-jwt" default is wrong for
	// token profiles), audience / nonce / leeway translations, optional
	// KB only when relaxed, and the DPoP-key KB seam.
	var verifyOpts []VerifyOption
	verifyOpts = append(verifyOpts, WithExpectedTyp(a.profile.ExpectedTyp))
	if a.cfg.Audience != "" {
		verifyOpts = append(verifyOpts, WithAudience(a.cfg.Audience))
	}
	if a.cfg.NonceValidator != nil {
		verifyOpts = append(verifyOpts, WithNonceValidator(a.cfg.NonceValidator))
	}
	if a.cfg.Leeway > 0 {
		verifyOpts = append(verifyOpts, WithLeeway(a.cfg.Leeway))
	}
	if !a.cfg.RequiredKeyBinding {
		verifyOpts = append(verifyOpts, WithOptionalKeyBinding())
	}
	// Draft-forten section 5.3: the KB-JWT is verified with the DPoP
	// proof key — a key binding with no DPoP key supplied is rejected
	// upfront rather than silently falling back to RFC 9901's cnf.jwk.
	if keyBinding != "" && dpopProofJWK == nil {
		return nil, fmt.Errorf("%w: no dpop proof key available for the key binding check", sdtoken.ErrInvalidKeyBinding)
	}
	if dpopProofJWK != nil {
		verifyOpts = append(verifyOpts, WithKeyBindingKeyProvider(func(_ map[string]any) (token.Verifier, error) {
			return oneKeyJWTVerifier(dpopProofJWK)
		}))
	}

	inner := NewVerifier(jwt.DefaultVerifier(a.keys, jwt.SupportedSignAlgorithms()), verifyOpts...)
	processedClaims, err := inner.Verify(ctx, presentation)
	if err != nil {
		return nil, err
	}

	// Draft-forten section 5.3: when a key binding is present, the DPoP
	// proof key thumbprint MUST equal cnf.jkt — the cnf.jkt binding is
	// what makes the DPoP-key KB sound. No KB, no thumbprint check.
	if keyBinding != "" {
		if err := checkDPoPThumbprint(processedClaims, dpopProofJWK); err != nil {
			return nil, err
		}
	}

	// Audience of the token itself when configured (the KB audience is
	// checked by the inner verifier; the token audience is part of the
	// profile contract at the RS). RFC 9068 section 5: aud is a string
	// or an array of strings; membership suffices.
	if a.cfg.Audience != "" {
		if !claimCoversAudience(processedClaims["aud"], a.cfg.Audience) {
			return nil, fmt.Errorf("%w: token audience mismatch", sdtoken.ErrInvalidToken)
		}
	}

	return processedClaims, nil
}

// claimCoversAudience reports whether an aud claim (string or array of
// strings, RFC 9068 section 5) covers the required audience.
func claimCoversAudience(audClaim any, audience string) bool {
	switch typed := audClaim.(type) {
	case string:
		return typed == audience
	case []any:
		for _, a := range typed {
			if s, isString := a.(string); isString && s == audience {
				return true
			}
		}
	}
	return false
}

// checkDPoPThumbprint enforces the draft-forten section 5.3 equality:
// base64url(SHA-256 RFC 7638 thumbprint of the DPoP proof JWK) ==
// cnf.jkt of the processed payload.
func checkDPoPThumbprint(processedClaims map[string]any, dpopProofJWK jwk.Key) error {
	if dpopProofJWK == nil {
		return fmt.Errorf("%w: no dpop proof key available for the key binding check", sdtoken.ErrInvalidKeyBinding)
	}
	cnfAny, has := processedClaims["cnf"]
	if !has {
		return fmt.Errorf("%w: token carries no cnf claim", sdtoken.ErrInvalidKeyBinding)
	}
	cnf, ok := cnfAny.(map[string]any)
	if !ok {
		return fmt.Errorf("%w: cnf claim is not an object", sdtoken.ErrInvalidKeyBinding)
	}
	jkt, ok := cnf["jkt"].(string)
	if !ok || jkt == "" {
		return fmt.Errorf("%w: cnf carries no jkt member", sdtoken.ErrInvalidKeyBinding)
	}

	thumbprint, err := dpopProofJWK.Thumbprint(crypto.SHA256)
	if err != nil {
		return fmt.Errorf("%w: unable to compute dpop key thumbprint: %w", sdtoken.ErrInvalidKeyBinding, err)
	}
	if !types.SecureCompareString(jkt, base64.RawURLEncoding.EncodeToString(thumbprint)) {
		return fmt.Errorf("%w: dpop key thumbprint does not equal cnf.jkt", sdtoken.ErrInvalidKeyBinding)
	}
	return nil
}

// oneKeyJWTVerifier assembles the single-key JWT verifier for the
// KB-JWT over the DPoP proof key (same assembly as kbJWTVerifierFor).
func oneKeyJWTVerifier(key jwk.Key) (token.Verifier, error) {
	// Normalize to the public form: DPoP proof headers carry public
	// JWKs, and a private key here would be a caller error.
	pub, err := jwxjwk.PublicKeyOf(key)
	if err != nil {
		return nil, fmt.Errorf("%w: unable to derive the dpop public key: %w", sdtoken.ErrInvalidKeyBinding, err)
	}
	keySet := jwxjwk.NewSet()
	if err := keySet.AddKey(pub); err != nil {
		return nil, fmt.Errorf("%w: unable to assemble dpop key set", sdtoken.ErrInvalidKeyBinding)
	}
	return jwt.DefaultVerifier(func(context.Context) (jwk.Set, error) { return keySet, nil }, jwt.SupportedSignAlgorithms()), nil
}
