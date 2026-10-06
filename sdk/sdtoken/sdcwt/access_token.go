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
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/sdtoken"
	"zntr.io/solid/sdk/token"
	"zntr.io/solid/sdk/types"
)

// draft-forten-oauth-sd-jwt-access-token-00 profile adapter over the
// SD-CWT machinery of this package (the format-agnostic analog: the
// draft defines the JWT form; the CWT kind carries the same roles over
// draft-ietf-spice-sd-cwt-08 primitives). The token is an ordinary
// COSE_Sign1 CWT (typ "application/at+cwt" for the access-token
// profile, "application/id+cwt" for the ID-token one) carrying
// redacted_claim_keys (simple 59) arrays + sd_alg and NO embedded
// sd_claims: the Disclosures travel out of band — in the token
// response `disclosures` parameter (base64url bstr strings at this
// boundary) and, per request, in the SD-JWT-Disclosures HTTP field —
// with the key binding KBT (base64url COSE_Sign1, typ 294) in
// SD-JWT-Key-Binding, signed by the DPoP proof key.

// Deps carries the serialization dependencies of the SD-CWT profile
// roles. Which members are required depends on the role; the
// constructors fail closed (return an error) on a missing one.
type Deps struct {
	// Algorithm is the COSE signing algorithm, e.g. ES256
	// (required: issuer, holder — the holder signs the KBT with
	// holder key material).
	Algorithm cose.Algorithm

	// KeyProvider resolves the CWT signing key (required: issuer,
	// holder — holder key material is the DPoP proof key).
	KeyProvider jwk.KeyProviderFunc

	// IssuerKeys resolves the issuer public-key set (required:
	// holder, verifier).
	IssuerKeys jwk.KeySetProviderFunc
}

// -----------------------------------------------------------------------------
// Issuer.

// NewAccessTokenIssuer returns the draft-forten SD-CWT AccessTokenIssuer
// of the given profile, enforcing the profile rules on every Issue
// call. Role-required dependencies are validated at construction.
func NewAccessTokenIssuer(profile sdtoken.Profile, deps Deps, opts ...sdtoken.AccessTokenIssuerOption) (sdtoken.AccessTokenIssuer, error) {
	if deps.Algorithm == 0 {
		return nil, fmt.Errorf("unable to build the SD-CWT issuer: Algorithm is required")
	}
	if deps.KeyProvider == nil {
		return nil, fmt.Errorf("unable to build the SD-CWT issuer: KeyProvider is required")
	}
	return &issuerAdapter{
		profile: profile,
		alg:     deps.Algorithm,
		keys:    deps.KeyProvider,
		cfg:     sdtoken.ResolveIssueSettings(opts...),
	}, nil
}

// -----------------------------------------------------------------------------
// claim-name ↔ CWT label mapping (mirrors the sdk/token access-token
// struct tags, RFC 8392 registered claims + the repo's 100+ private
// labels). Unlisted names keep their string keys.

// CWT claim-name string keys, shared by the label map and the KBT
// forbidden-claim checks.
const (
	claimNameIss = "iss"
	claimNameSub = "sub"
)

var claimNameToLabel = map[string]int64{
	claimNameIss:            1,
	claimNameSub:            2,
	"aud":                   3,
	"exp":                   4,
	"nbf":                   5,
	"iat":                   6,
	"jti":                   7,
	"client_id":             100,
	"scope":                 101,
	"cnf":                   102,
	"authorization_details": 103,
}

// labelToName is the precomputed reverse of claimNameToLabel, keyed by
// both uint64 (CBOR-decoded) and int64 (Go-built map) label forms.
var labelToName = func() map[any]string {
	out := make(map[any]string, 2*len(claimNameToLabel))
	for name, label := range claimNameToLabel {
		out[uint64(label)] = name // CBOR-decoded maps carry uint64 keys
		out[label] = name         // Go-built maps carry int64 keys
	}
	return out
}()

// cwtTyp derives the COSE typ header value of a profile: the media
// type form of token.HeaderType(base, "CWT") — "application/at+cwt" /
// "application/id+cwt". The profile ExpectedTyp ("at+jwt"/"id+jwt")
// maps to the same base derivation.
func cwtTyp(profile sdtoken.Profile) (string, error) {
	switch profile.BaseTyp {
	case token.TypeAccessToken:
		return "application/at+cwt", nil
	case token.TypeIDToken:
		return "application/id+cwt", nil
	default:
		return "", fmt.Errorf("%w: no cwt typ mapping for base type %q", sdtoken.ErrInvalidToken, profile.BaseTyp)
	}
}

// checkProfileTyp enforces the profile media type exactly (RFC 8725
// section 3.11: cross-profile typ confusion is rejected).
func checkProfileTyp(profile sdtoken.Profile) func(cose.ProtectedHeader) error {
	// Derive the expected media type once; the per-header check only
	// compares.
	expected, typErr := cwtTyp(profile)
	return func(ph cose.ProtectedHeader) error {
		if typErr != nil {
			return typErr
		}
		if ph[cose.HeaderLabelType] != expected {
			return fmt.Errorf("%w: invalid %s typ", ErrInvalidSDCWT, profile.Name)
		}
		return nil
	}
}

// toCWTClaims maps name-keyed root claims to the map[any]any tree the
// SD-CWT engine consumes: registered claim names become their integer
// labels, everything else keeps its string key. Values are deep-
// copied: the issuance walk replaces markers with digests IN the tree
// (map deletions AND array element rewrites), so the caller's map and
// slices stay intact.
func toCWTClaims(claims map[string]any) map[any]any {
	source := sdtoken.CloneClaims(claims)
	out := make(map[any]any, len(source))
	for name, value := range source {
		if label, ok := claimNameToLabel[name]; ok {
			out[uint64(label)] = value //nolint:gosec // labels are small registered CWT claim constants
		} else {
			out[name] = value
		}
	}
	return out
}

// fromCWTClaims maps a processed label-keyed claims map back to a
// name-keyed one (the verifier surface). Registered labels take their
// claim names; unmapped integer labels surface under their decimal
// string form ("39" for cnonce) since the string-keyed surface has no
// integer-key form — callers wanting raw labels read the sdcwt
// credential verifier instead.
func fromCWTClaims(claims map[any]any) map[string]any {
	out := make(map[string]any, len(claims))
	for k, v := range claims {
		if name, ok := labelToName[k]; ok {
			out[name] = v
		} else {
			out[fmt.Sprintf("%v", k)] = v
		}
	}
	return out
}

type issuerAdapter struct {
	profile sdtoken.Profile
	alg     cose.Algorithm
	keys    jwk.KeyProviderFunc
	cfg     *sdtoken.IssueSettings
}

// Issue implements the draft-forten section 3 issuance in the CWT
// form: an ordinary COSE_Sign1 CWT carrying redacted_claim_keys
// digest arrays + sd_alg and NO sd_claims header (the values must not
// travel inside the token string — an unaware recipient sees an
// ordinary CWT access token, draft section 1). The digests still
// commit the claim tree, so the signature covers the redacted form
// identically.
func (a *issuerAdapter) Issue(ctx context.Context, claims map[string]any) (tokenString string, disclosures []string, err error) {
	if claims == nil {
		return "", nil, fmt.Errorf("%w: claims map is nil", sdtoken.ErrInvalidToken)
	}
	if a.keys == nil {
		return "", nil, fmt.Errorf("%w: no key provider configured", sdtoken.ErrInvalidToken)
	}

	// Profile rules first.
	if errRules := sdtoken.ValidateDisclosableClaims(a.profile, claims); errRules != nil {
		return "", nil, errRules
	}
	// draft-forten section 6: SD access tokens MUST be DPoP-bound —
	// require a non-empty cnf.jkt (the §5.3 binding is jkt-based).
	if a.cfg.RequiredConfirmation && !sdtoken.HasJKT(claims) {
		return "", nil, fmt.Errorf("%w: the %s profile requires a cnf.jkt confirmation", sdtoken.ErrConfirmationRequired, a.profile.Name)
	}

	// Name-keyed → label-keyed tree.
	tree := toCWTClaims(claims)

	// Walk + encode disclosures + replace markers with digests (the
	// credential issuance internals, minus the sd_claims embedding).
	cfg := newIssueConfig()
	if a.cfg.SaltFactory != nil {
		cfg.saltFactory = a.cfg.SaltFactory
	}
	cfg.decoys = a.cfg.DecoyDigests
	if cfg.saltFactory == nil {
		cfg.saltFactory = sdtoken.NewSalt
	}
	disclosuresRaw, err := forgeSDCWTClaims(tree, cfg)
	if err != nil {
		return "", nil, err
	}

	// Signing key + headers: protected alg/kid/typ/sd_alg, NO
	// unprotected sd_claims.
	signer, kid, err := coseSignerFor(ctx, a.alg, a.keys)
	if err != nil {
		return "", nil, err
	}
	typ, err := cwtTyp(a.profile)
	if err != nil {
		return "", nil, err
	}
	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: a.alg,
			cose.HeaderLabelKeyID:     []byte(kid),
			cose.HeaderLabelType:      typ,
			HeaderLabelSdAlg:          HashAlgSHA256,
		},
	}

	payload, err := cbor.Marshal(tree)
	if err != nil {
		return "", nil, fmt.Errorf("unable to serialize claims as cbor: %w", err)
	}
	msg := cose.Sign1Message{Headers: headers, Payload: payload}
	if err = msg.Sign(rand.Reader, nil, signer); err != nil {
		return "", nil, fmt.Errorf("unable to sign sd-cwt: %w", err)
	}
	assertion, err := msg.MarshalCBOR()
	if err != nil {
		return "", nil, fmt.Errorf("unable to marshal sd-cwt: %w", err)
	}

	// base64url bstr disclosures at the profile string boundary.
	disclosures = make([]string, len(disclosuresRaw))
	for i, d := range disclosuresRaw {
		disclosures[i] = base64.RawURLEncoding.EncodeToString(d)
	}
	return base64.RawURLEncoding.EncodeToString(assertion), disclosures, nil
}

// -----------------------------------------------------------------------------
// Holder.

type holderAdapter struct {
	inner Holder
}

// NewAccessTokenHolder returns the draft-forten SD-CWT
// AccessTokenHolder of the given profile. Role-required dependencies
// are validated at construction.
func NewAccessTokenHolder(profile sdtoken.Profile, deps Deps, opts ...sdtoken.AccessTokenHolderOption) (sdtoken.AccessTokenHolder, error) {
	if deps.IssuerKeys == nil {
		return nil, fmt.Errorf("unable to build the SD-CWT holder: IssuerKeys is required")
	}
	if deps.Algorithm == 0 {
		return nil, fmt.Errorf("unable to build the SD-CWT holder: Algorithm is required")
	}
	if deps.KeyProvider == nil {
		return nil, fmt.Errorf("unable to build the SD-CWT holder: KeyProvider is required")
	}
	_ = sdtoken.ResolveHolderSettings(opts...) // seam: no holder setting exists yet
	return &holderAdapter{
		inner: NewHolder(deps.IssuerKeys, deps.Algorithm, deps.KeyProvider),
	}, nil
}

// decodeDisclosureString decodes one base64url bstr disclosure from
// the profile boundary.
func decodeDisclosureString(d string) (sdtoken.DecodedDisclosure, error) {
	raw, err := base64.RawURLEncoding.DecodeString(d)
	if err != nil {
		return sdtoken.DecodedDisclosure{}, fmt.Errorf("%w: disclosure is not base64url", sdtoken.ErrInvalidDisclosure)
	}
	return decodeDisclosure(raw)
}

// Select implements the draft-forten section 4 client rule: pick the
// disclosures carrying the named claims, by claim name (labels
// mapped), WITHOUT parsing or inspecting the token.
func (a *holderAdapter) Select(ctx context.Context, _ string, disclosures []string, claimNames ...string) ([]string, error) {
	_ = ctx // no context-dependent work: local decoding only
	byName := make(map[string]string, len(disclosures))
	seenWire := make(map[string]struct{}, len(disclosures))
	for _, d := range disclosures {
		if _, dup := seenWire[d]; dup {
			return nil, fmt.Errorf("%w: the same disclosure was received twice", sdtoken.ErrDuplicateDisclosure)
		}
		seenWire[d] = struct{}{}

		decoded, err := decodeDisclosureString(d)
		if err != nil {
			return nil, err
		}
		if decoded.IsDecoy || decoded.ClaimKey == nil {
			continue
		}
		name := cwtClaimName(decoded.ClaimKey)
		if name == "" {
			continue
		}
		if _, exists := byName[name]; exists {
			return nil, fmt.Errorf("%w: two disclosures claim %q", sdtoken.ErrDuplicateDisclosure, name)
		}
		byName[name] = d
	}

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

// cwtClaimName maps a decoded disclosure claim key (uint64 label or
// string) back to its claim name.
func cwtClaimName(key any) string {
	if name, ok := labelToName[key]; ok {
		return name
	}
	if s, isString := key.(string); isString {
		return s
	}
	return ""
}

// KeyBind implements the draft-forten section 4 key binding in the
// CWT form: reassemble the SD-CWT with exactly the selected
// disclosures in sd_claims (the unprotected header is not signed, so
// the issuer signature stays valid) and build the KBT embedding it.
func (a *holderAdapter) KeyBind(ctx context.Context, tokenString string, selected []string, nonce, audience string, issuedAt int64) (string, error) {
	presentations, err := reassemblePresentation(tokenString, selected)
	if err != nil {
		return "", err
	}
	// cnonce: the DPoP nonce as raw bytes.
	kbt, err := a.inner.KeyBind(ctx, presentations, audience, []byte(nonce), WithIssuedAt(issuedAt))
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(kbt), nil
}

// reassemblePresentation decodes the token COSE_Sign1 and inserts the
// selected disclosures into the unprotected sd_claims header,
// re-marshaling; the returned bytes embed the presentation.
func reassemblePresentation(tokenString string, selected []string) (presentation []byte, err error) {
	tokenBytes, err := base64.RawURLEncoding.DecodeString(tokenString)
	if err != nil {
		return nil, fmt.Errorf("%w: token is not base64url", sdtoken.ErrInvalidToken)
	}

	var msg cose.Sign1Message
	if errParse := msg.UnmarshalCBOR(tokenBytes); errParse != nil {
		return nil, fmt.Errorf("%w: unable to parse cose_sign1: %w", sdtoken.ErrInvalidToken, errParse)
	}

	// Duplicate-free selection.
	seen := make(map[string]struct{}, len(selected))
	out := make([]any, 0, len(selected))
	for _, d := range selected {
		if _, dup := seen[d]; dup {
			return nil, fmt.Errorf("%w: disclosure presented twice", sdtoken.ErrDuplicateDisclosure)
		}
		seen[d] = struct{}{}

		raw, errDec := base64.RawURLEncoding.DecodeString(d)
		if errDec != nil {
			return nil, fmt.Errorf("%w: disclosure is not base64url", sdtoken.ErrInvalidDisclosure)
		}
		out = append(out, raw)
	}

	// Drop the raw captured header, swap sd_claims.
	msg.Headers.RawUnprotected = nil
	msg.Headers.Unprotected = cose.UnprotectedHeader{
		HeaderLabelSdClaims: out,
	}
	presentation, err = msg.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("unable to marshal presentation: %w", err)
	}
	return presentation, nil
}

// -----------------------------------------------------------------------------
// Verifier.

type verifierAdapter struct {
	profile sdtoken.Profile
	keys    jwk.KeySetProviderFunc
	cfg     *sdtoken.VerifySettings
}

// NewAccessTokenVerifier returns the draft-forten SD-CWT
// AccessTokenVerifier of the given profile. Role-required dependencies
// are validated at construction.
func NewAccessTokenVerifier(profile sdtoken.Profile, deps Deps, opts ...sdtoken.AccessTokenVerifierOption) (sdtoken.AccessTokenVerifier, error) {
	if deps.IssuerKeys == nil {
		return nil, fmt.Errorf("unable to build the SD-CWT verifier: IssuerKeys is required")
	}
	return &verifierAdapter{
		profile: profile,
		keys:    deps.IssuerKeys,
		cfg:     sdtoken.NewVerifySettings(opts...),
	}, nil
}

// Verify implements the draft-forten section 5 processing in the CWT
// form:
//
//  1. decode the COSE_Sign1, insert the presented disclosures into the
//     unprotected sd_claims header, re-marshal (unprotected headers are
//     not signature-covered; integrity comes from the digests in
//     redacted_claim_keys);
//  2. embed the presentation in the KBT (kcwt) and verify the KBT
//     signature with the DPoP proof key (draft section 5.3 divergence:
//     the binding key is the DPoP key, not cnf.cose_key);
//  3. run the SD-CWT structural checks and disclosure processing on the
//     embedded presentation, enforce audience / cnonce / leeway;
//  4. enforce the section 5.3 thumbprint equality (DPoP key thumbprint
//     == cnf.jkt) when a KBT is present.
//
//nolint:gocyclo,funlen // linear draft-forten section 5 verification chain
func (a *verifierAdapter) Verify(ctx context.Context, tokenString string, disclosures []string, keyBinding string, dpopProofJWK jwk.Key) (map[string]any, error) {
	if a.keys == nil {
		return nil, fmt.Errorf("%w: no issuer keys configured", sdtoken.ErrInvalidToken)
	}

	// Policy: key binding required by default.
	if keyBinding == "" && a.cfg.RequiredKeyBinding {
		return nil, fmt.Errorf("%w: no key binding presented", sdtoken.ErrInvalidKeyBinding)
	}

	// Reassemble token + presented disclosures into the presentation.
	presentation, err := reassemblePresentation(tokenString, disclosures)
	if err != nil {
		return nil, err
	}

	var processedClaims map[any]any

	if keyBinding != "" {
		// Decode the KBT.
		kbtBytes, errB64 := base64.RawURLEncoding.DecodeString(keyBinding)
		if errB64 != nil {
			return nil, fmt.Errorf("%w: key binding is not base64url", sdtoken.ErrInvalidKeyBinding)
		}

		// Structural + header checks; kcwt must embed the exact
		// presentation bytes.
		kbtMsg, embedded, errKBT := parseKBT(kbtBytes)
		if errKBT != nil {
			return nil, fmt.Errorf("%w: %w", sdtoken.ErrInvalidKeyBinding, errKBT)
		}
		if !bytes.Equal(embedded, presentation) {
			return nil, fmt.Errorf("%w: kbt kcwt does not embed the presented sd-cwt", sdtoken.ErrInvalidKeyBinding)
		}

		// KBT signature with the DPoP proof key (draft section 5.3:
		// the binding key is the DPoP key). The alg comes from the KBT
		// header; the key from the request's DPoP proof.
		if dpopProofJWK == nil {
			return nil, fmt.Errorf("%w: no dpop proof key available", sdtoken.ErrInvalidKeyBinding)
		}
		kbtAlg, errAlg := kbtMsg.Headers.Protected.Algorithm()
		if errAlg != nil {
			return nil, fmt.Errorf("%w: kbt carries no algorithm header", sdtoken.ErrInvalidKeyBinding)
		}
		dpopPub, errPub := materializePublicKey(dpopProofJWK)
		if errPub != nil {
			return nil, fmt.Errorf("%w: unable to materialize dpop key: %w", sdtoken.ErrInvalidKeyBinding, errPub)
		}
		kbtVerifier, errVerifier := cose.NewVerifier(kbtAlg, dpopPub)
		if errVerifier != nil {
			return nil, fmt.Errorf("%w: unable to initialize kbt verifier: %w", sdtoken.ErrInvalidKeyBinding, errVerifier)
		}
		if errKBT := kbtMsg.Verify(nil, kbtVerifier); errKBT != nil {
			return nil, fmt.Errorf("%w: kbt signature verification failed: %w", sdtoken.ErrInvalidKeyBinding, errKBT)
		}

		// KBT payload constraints (aud / cnonce / iat; iss and sub
		// forbidden), then audience / cnonce / temporal checks.
		kbtClaims, errClaims := decodeKBTClaims(kbtMsg.Payload, sdtoken.ErrInvalidKeyBinding)
		if errClaims != nil {
			return nil, errClaims
		}

		// Audience (mandatory, fail closed: an unconfigured audience
		// rejects the KBT — mirroring the sdjwt posture, an insecure
		// configuration is not offered as an option).
		if a.cfg.Audience == "" {
			return nil, fmt.Errorf("%w: no audience configured", sdtoken.ErrInvalidKeyBinding)
		}
		audAny, hasAud := kbtClaims[uint64(ClaimKeyAud)]
		if !hasAud {
			return nil, fmt.Errorf("%w: kbt carries no aud claim", sdtoken.ErrInvalidKeyBinding)
		}
		aud, ok := audAny.(string)
		if !ok || aud != a.cfg.Audience {
			return nil, fmt.Errorf("%w: kbt audience mismatch", sdtoken.ErrInvalidKeyBinding)
		}

		// cnonce: the DPoP nonce, mandatory one-shot validation (fail
		// closed: no validator configured rejects the KBT).
		if a.cfg.NonceValidator == nil {
			return nil, fmt.Errorf("%w: no nonce validator configured", sdtoken.ErrInvalidKeyBinding)
		}
		cnonceAny, hasCnonce := kbtClaims[uint64(ClaimKeyCnonce)]
		if !hasCnonce {
			return nil, fmt.Errorf("%w: kbt carries no cnonce claim", sdtoken.ErrInvalidKeyBinding)
		}
		cnonce, ok := cnonceAny.([]byte)
		if !ok {
			return nil, fmt.Errorf("%w: kbt cnonce is not a bstr", sdtoken.ErrInvalidKeyBinding)
		}
		if errNonce := a.cfg.NonceValidator(string(cnonce)); errNonce != nil {
			return nil, fmt.Errorf("%w: cnonce rejected: %w", sdtoken.ErrInvalidKeyBinding, errNonce)
		}

		// iat freshness with the verifier leeway.
		iatAny, hasIat := kbtClaims[uint64(ClaimKeyIat)]
		if !hasIat {
			return nil, fmt.Errorf("%w: kbt carries no iat claim", sdtoken.ErrInvalidKeyBinding)
		}
		iat, ok := numericClaim(iatAny)
		if !ok {
			return nil, fmt.Errorf("%w: kbt iat is not numeric", sdtoken.ErrInvalidKeyBinding)
		}
		now := timeNowUnix()
		if age := now - iat; age < -a.cfg.Leeway || age > 5*60+a.cfg.Leeway {
			return nil, fmt.Errorf("%w: kbt iat outside the freshness window", sdtoken.ErrInvalidKeyBinding)
		}

		// Process the embedded presentation disclosures with the
		// issuer-key verification. The draft-forten section 5.1 zero-
		// Disclosure presentation is valid: an empty presented set
		// processes without any disclosure (every site stays redacted).
		processedClaims, err = a.processPresentation(presentation)
		if err != nil {
			return nil, err
		}

		// Draft section 5.3 thumbprint equality: DPoP key thumbprint
		// == cnf (label 102) jkt.
		if errThumbprint := checkDPoPThumbprintCWT(processedClaims, dpopProofJWK); errThumbprint != nil {
			return nil, errThumbprint
		}
	} else {
		// No KBT: verify the presentation directly (structural checks
		// + signature + disclosures), audience enforced when
		// configured.
		processedClaims, err = a.processPresentation(presentation)
		if err != nil {
			return nil, err
		}
	}

	// Token audience when configured.
	if a.cfg.Audience != "" {
		audClaim := lookupClaim(processedClaims, ClaimKeyAud)
		aud, ok := audClaim.(string)
		if !ok || aud == "" {
			return nil, fmt.Errorf("%w: token carries no aud claim", sdtoken.ErrInvalidToken)
		}
		if aud != a.cfg.Audience {
			return nil, fmt.Errorf("%w: token audience mismatch", sdtoken.ErrInvalidToken)
		}
	}

	// Temporal claims of the processed payload.
	if err := checkTemporalClaims(processedClaims, a.cfg.Leeway); err != nil {
		return nil, err
	}

	// Map labels back to names for the verifier surface.
	return fromCWTClaims(processedClaims), nil
}

// processPresentation verifies the presentation signature against the
// issuer keys (with the profile typ) and processes its disclosures. The
// draft-forten section 5.1 zero-Disclosure presentation is valid: an
// empty sd_claims array processes with no disclosures (every redaction
// site stays redacted), diverging from the credential verifier which
// requires at least one.
func (a *verifierAdapter) processPresentation(presentation []byte) (map[any]any, error) {
	sdMsg, sdClaims, err := verifySDCWTWithType(presentation, a.keys, checkProfileTyp(a.profile))
	if err != nil {
		return nil, err
	}
	return processSDCWTDisclosuresOpt(sdMsg, sdClaims, true)
}

// checkDPoPThumbprintCWT enforces the draft-forten section 5.3
// equality on a label-keyed claims map: base64url(SHA-256 RFC 7638
// thumbprint of the DPoP proof JWK) == cnf.jkt.
func checkDPoPThumbprintCWT(processedClaims map[any]any, dpopProofJWK jwk.Key) error {
	if dpopProofJWK == nil {
		return fmt.Errorf("%w: no dpop proof key available for the key binding check", sdtoken.ErrInvalidKeyBinding)
	}
	// The profile encodes cnf under its access-token CWT label (102,
	// mirroring the sdk/token claim struct tags), not the RFC 8747
	// label 8 the credential engine uses.
	cnf := lookupClaim(processedClaims, claimNameToLabel["cnf"])
	if cnf == nil {
		return fmt.Errorf("%w: token carries no cnf claim", sdtoken.ErrInvalidKeyBinding)
	}
	cnfMap, ok := cnf.(map[any]any)
	if !ok {
		return fmt.Errorf("%w: cnf claim is not a map", sdtoken.ErrInvalidKeyBinding)
	}
	jktAny, has := cnfMap["jkt"]
	if !has {
		return fmt.Errorf("%w: cnf carries no jkt member", sdtoken.ErrInvalidKeyBinding)
	}
	jkt, ok := jktAny.(string)
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

// checkTemporalClaims validates exp / nbf of the processed CWT claims
// with the given leeway (seconds).
func checkTemporalClaims(claims map[any]any, leeway int64) error {
	now := timeNowUnix()
	if expAny := lookupClaim(claims, 4); expAny != nil {
		if exp, ok := numericClaim(expAny); ok && now > exp+leeway {
			return fmt.Errorf("%w: token is expired", sdtoken.ErrInvalidToken)
		}
	}
	if nbfAny := lookupClaim(claims, 5); nbfAny != nil {
		if nbf, ok := numericClaim(nbfAny); ok && now < nbf-leeway {
			return fmt.Errorf("%w: token is not yet valid", sdtoken.ErrInvalidToken)
		}
	}
	return nil
}

// timeNowUnix returns the current Unix time (seam for tests).
var timeNowUnix = func() int64 { return time.Now().Unix() }
