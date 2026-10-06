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

package sdtoken

import (
	"context"

	"zntr.io/solid/sdk/jwk"
)

// -----------------------------------------------------------------------------
// draft-forten-oauth-sd-jwt-access-token-00 role contracts.
//
// The access token is the primary draft instance; the Profile parameter
// carries the token-class generalization (the same roles issue and
// verify SD access tokens and SD ID tokens). The interfaces are
// string-surfaced so both serialization kinds meet the same boundary:
// the CWT adapters base64url-encode their bstr disclosures here and map
// claim names to CWT labels at this seam.

// AccessTokenIssuer creates selectively disclosable tokens
// (draft-forten section 3): the token carries only digests; the
// disclosure strings travel out of band (token response disclosures
// parameter).
type AccessTokenIssuer interface {
	// Issue creates a token for the given claims: claim-name keyed
	// (iss, sub, ..., email, name); markers via Disclosable /
	// DisclosableElement at the TOP LEVEL only (the profile rules
	// reject protected and nested markers before any encoding work).
	Issue(ctx context.Context, claims map[string]any) (token string, disclosures []string, err error)
}

// AccessTokenHolder consumes an issued SD token and builds the
// per-request presentation (draft-forten section 4).
type AccessTokenHolder interface {
	// Select picks the disclosures carrying the named claims from the
	// set received with the token. The client selects by claim name; it
	// MUST NOT parse or inspect the token (draft-forten section 4) —
	// only the disclosure contents are decoded.
	Select(ctx context.Context, token string, disclosures []string, claimNames ...string) (selected []string, err error)
	// KeyBind produces the key binding over the presentation carrying
	// exactly the selected disclosures (JWT kind: sd_hash over
	// token~D~...~D~; CWT kind: a KBT embedding the reassembled
	// SD-CWT).
	KeyBind(ctx context.Context, token string, selected []string, nonce, audience string, issuedAt int64) (keyBinding string, err error)
}

// AccessTokenVerifier processes SD token presentations (draft-forten
// section 5): token + presented Disclosures + optional key binding.
type AccessTokenVerifier interface {
	// Verify validates the token, the presented disclosures and the
	// key binding, and returns the Processed SD Payload. dpopProofJWK
	// is the JWK from the DPoP proof header: its SHA-256 thumbprint
	// MUST equal cnf.jkt whenever a key binding is present
	// (draft-forten section 5.3 — the DPoP key is the binding key,
	// diverging from RFC 9901's cnf.jwk).
	Verify(ctx context.Context, token string, disclosures []string, keyBinding string, dpopProofJWK jwk.Key) (claims map[string]any, err error)
}

// -----------------------------------------------------------------------------
// options.

// AccessTokenIssuerOption configures AccessTokenIssuer construction. The
// root defines the surface; each serialization adapter translates the
// options to its internal configuration.
type AccessTokenIssuerOption interface {
	applyIssue(*IssueSettings)
}

// IssueSettings carries the issuer configuration resolved from the
// option list.
type IssueSettings struct {
	SaltFactory          func() ([]byte, error)
	DecoyDigests         uint
	RequiredConfirmation bool
}

type issueOptionFunc func(*IssueSettings)

func (f issueOptionFunc) applyIssue(c *IssueSettings) { f(c) }

// WithSaltFactory overrides the disclosure salt source (default:
// NewSalt — 128 bits of crypto/rand per disclosure).
func WithSaltFactory(factory func() ([]byte, error)) AccessTokenIssuerOption {
	return issueOptionFunc(func(c *IssueSettings) { c.SaltFactory = factory })
}

// WithDecoyDigests adds n decoy digests per digest array.
func WithDecoyDigests(n uint) AccessTokenIssuerOption {
	return issueOptionFunc(func(c *IssueSettings) { c.DecoyDigests = n })
}

// WithRequiredConfirmation enforces the draft-forten section 6 mandate
// at issuance: SD access tokens MUST be DPoP-bound, so Issue rejects a
// claims map without a cnf confirmation (ErrConfirmationRequired). Do
// NOT set it for the ID-token profile: OIDC does not sender-constrain
// ID tokens.
func WithRequiredConfirmation() AccessTokenIssuerOption {
	return issueOptionFunc(func(c *IssueSettings) { c.RequiredConfirmation = true })
}

// ResolveIssueSettings resolves the issuer settings from the option
// list (zero-value defaults: salt source NewSalt at the adapter, no
// decoys, no confirmation requirement). Serialization adapters use it
// to translate the root option surface to their internal
// configuration.
func ResolveIssueSettings(opts ...AccessTokenIssuerOption) *IssueSettings {
	cfg := &IssueSettings{}
	for _, opt := range opts {
		if opt != nil {
			opt.applyIssue(cfg)
		}
	}
	return cfg
}

// AccessTokenHolderOption configures AccessTokenHolder construction.
type AccessTokenHolderOption interface {
	applyHolder(*HolderSettings)
}

// HolderSettings carries the holder configuration.
type HolderSettings struct{}

// ResolveHolderSettings resolves the holder settings from the option
// list. Serialization adapters use it to honor the root option
// surface; no holder setting exists yet, the walk reserves the seam.
func ResolveHolderSettings(opts ...AccessTokenHolderOption) *HolderSettings {
	cfg := &HolderSettings{}
	for _, opt := range opts {
		opt.applyHolder(cfg)
	}
	return cfg
}

// AccessTokenVerifierOption configures AccessTokenVerifier
// construction.
type AccessTokenVerifierOption interface {
	applyVerifier(*VerifySettings)
}

// VerifySettings carries the verifier configuration. Defaults are the
// defensive posture: key binding required (draft-forten section 6 read
// at the resource server), 60-second leeway.
type VerifySettings struct {
	Audience           string
	NonceValidator     func(string) error
	Leeway             int64
	RequiredKeyBinding bool
}

type verifierOptionFunc func(*VerifySettings)

func (f verifierOptionFunc) applyVerifier(c *VerifySettings) { f(c) }

// NewVerifySettings resolves the default verifier settings.
func NewVerifySettings(opts ...AccessTokenVerifierOption) *VerifySettings {
	cfg := &VerifySettings{RequiredKeyBinding: true, Leeway: 60}
	for _, opt := range opts {
		opt.applyVerifier(cfg)
	}
	return cfg
}

// WithAudience sets the required audience of the token (and of the key
// binding when present).
func WithAudience(audience string) AccessTokenVerifierOption {
	return verifierOptionFunc(func(c *VerifySettings) { c.Audience = audience })
}

// WithNonceValidator sets the key binding nonce validator (replay
// defense): a non-nil error rejects the nonce.
func WithNonceValidator(validator func(string) error) AccessTokenVerifierOption {
	return verifierOptionFunc(func(c *VerifySettings) { c.NonceValidator = validator })
}

// WithLeeway sets the temporal claim leeway in seconds (default 60).
func WithLeeway(leewaySeconds int64) AccessTokenVerifierOption {
	return verifierOptionFunc(func(c *VerifySettings) { c.Leeway = leewaySeconds })
}

// WithKeyBindingRequired restores the default key-binding-required
// verifier posture.
func WithKeyBindingRequired() AccessTokenVerifierOption {
	return verifierOptionFunc(func(c *VerifySettings) { c.RequiredKeyBinding = true })
}

// WithOptionalKeyBinding relaxes the default key-binding-required
// policy (draft-forten leaves resource-server KB policy to the
// deployment; the default here requires it).
func WithOptionalKeyBinding() AccessTokenVerifierOption {
	return verifierOptionFunc(func(c *VerifySettings) { c.RequiredKeyBinding = false })
}
