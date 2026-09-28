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
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token"
	"zntr.io/solid/sdk/types"
)

// ErrInvalidGrant signals a profile-invalid ID-JAG: the Resource
// Authorization Server maps this to invalid_grant (draft section 4.4.1).
var ErrInvalidGrant = errors.New("invalid ID-JAG")

// DefaultVerifier builds an ID-JAG verifier for a Resource Authorization
// Server with the given local issuer identifier, trusted-issuer resolver
// and token verifier (token.Verifier). The injected verifier carries the
// serialization format and the signature algorithm allowlist: it MUST
// contain elliptic-curve and/or ML-DSA identifiers only (assemblies
// enforce this); a token signed with any other algorithm fails closed at
// parse time.
func DefaultVerifier(localIssuer string, issuerResolver IssuerResolver, verifier token.Verifier) Verifier {
	return &defaultVerifier{
		localIssuer:    localIssuer,
		issuerResolver: issuerResolver,
		verifier:       verifier,
		now:            time.Now,
	}
}

type defaultVerifier struct {
	localIssuer    string
	issuerResolver IssuerResolver
	verifier       token.Verifier
	now            func() time.Time
}

// Verify applies the draft section 4.4.1 processing rules to a raw ID-JAG
// and returns its decoded claim set.
//
//nolint:gocyclo // linear RFC-ordered validation chain; each guard is a protocol requirement
func (v *defaultVerifier) Verify(ctx context.Context, raw string) (*tokenv1.IdentityAssertionJWTAuthorizationGrant, error) {
	// Syntactic parse without verification; the algorithm allowlist is
	// enforced by the injected verifier at parse time.
	t, err := v.verifier.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: unable to parse ID-JAG: %w", ErrInvalidGrant, err)
	}

	// draft section 3.1 / RFC 8725 section 3.11: the typ header MUST be
	// the ID-JAG type qualified with the verifier's serialization
	// format (e.g. "oauth-id-jag+jwt").
	typ, err := t.Type()
	if err != nil || typ != token.HeaderType(token.TypeIDJAG, v.verifier.ContentType()) {
		return nil, fmt.Errorf("%w: typ header is not %q", ErrInvalidGrant, token.HeaderType(token.TypeIDJAG, v.verifier.ContentType()))
	}

	// Pre-decode the untrusted claim map to route issuer resolution. The
	// values are attacker-controlled until the signature verifies below;
	// only iss is consulted here. aud may be a string or an array, which
	// the proto claim set cannot represent.
	var rawClaims map[string]any
	if errJSON := t.UnverifiedClaims(&rawClaims); errJSON != nil {
		return nil, fmt.Errorf("%w: unable to decode claims: %w", ErrInvalidGrant, errJSON)
	}
	iss, _ := rawClaims["iss"].(string)

	// draft section 9.3: an AS must not honor an ID-JAG issued by itself
	// (no trust-domain crossing).
	if iss == v.localIssuer {
		return nil, fmt.Errorf("%w: ID-JAG issuer is the local issuer", ErrInvalidGrant)
	}

	// Resolve trusted issuer JWKS. An unknown issuer is not trusted:
	// fail closed.
	jwks, err := v.issuerResolver.Resolve(ctx, iss)
	if err != nil {
		return nil, fmt.Errorf("%w: issuer %q is not trusted: %w", ErrInvalidGrant, iss, err)
	}

	// Cryptographic verification against the issuer key set, honoring
	// kid when present. verifiedClaims is decoded by the same call, so
	// it is signature-verified content.
	verifiedClaims, errSig := v.verifySignature(t, jwks)
	if errSig != nil {
		return nil, errSig
	}

	// draft section 4.4.1: aud MUST be the local issuer identifier, as a
	// string or a single-element array.
	if !audienceMatchesRaw(verifiedClaims, v.localIssuer) {
		return nil, fmt.Errorf("%w: aud claim is not the local issuer identifier", ErrInvalidGrant)
	}

	// REQUIRED claims present in the verified claim set. protojson
	// encodes 64-bit integers as strings, so both forms are accepted.
	if s, _ := verifiedClaims["jti"].(string); s == "" {
		return nil, fmt.Errorf("%w: jti claim is missing", ErrInvalidGrant)
	}
	if s, _ := verifiedClaims["sub"].(string); s == "" {
		return nil, fmt.Errorf("%w: sub claim is missing", ErrInvalidGrant)
	}
	if s, _ := verifiedClaims["client_id"].(string); s == "" {
		return nil, fmt.Errorf("%w: client_id claim is missing", ErrInvalidGrant)
	}
	exp, err := numericClaim(verifiedClaims, "exp")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidGrant, err)
	}
	if _, errIat := numericClaim(verifiedClaims, "iat"); errIat != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidGrant, errIat)
	}

	// Temporal validity: RFC 7523 section 3.
	if errTemporal := validateTemporal(verifiedClaims, exp, v.now().Unix()); errTemporal != nil {
		return nil, errTemporal
	}

	// Every profile rule passed: normalize a single-element aud array to
	// its string form, then decode the typed claim set.
	if aud, ok := verifiedClaims["aud"].([]any); ok && len(aud) == 1 {
		if s, isStr := aud[0].(string); isStr {
			verifiedClaims["aud"] = s
		}
	}
	normalized, err := json.Marshal(verifiedClaims)
	if err != nil {
		return nil, fmt.Errorf("%w: unable to normalize claims: %w", ErrInvalidGrant, err)
	}
	var claims tokenv1.IdentityAssertionJWTAuthorizationGrant
	if err := json.Unmarshal(normalized, &claims); err != nil {
		return nil, fmt.Errorf("%w: unable to decode claims: %w", ErrInvalidGrant, err)
	}

	return &claims, nil
}

// numericClaim extracts a numeric claim that may be encoded as a JSON
// number or (protojson) as a string.
func numericClaim(rawClaims map[string]any, name string) (float64, error) {
	switch v := rawClaims[name].(type) {
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return 0, fmt.Errorf("%s claim is not a finite number", name)
		}
		return v, nil
	case string:
		// protojson encodes 64-bit integers as strings; accept only a
		// strict full numeric form. ParseFloat rejects NaN/Inf text
		// but accepts "NaN" via Sscanf, and partial parses ("123abc")
		// must fail closed.
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, fmt.Errorf("%s claim is not a finite number", name)
		}
		return f, nil
	default:
		return 0, fmt.Errorf("%s claim is missing", name)
	}
}

// verifySignature cryptographically verifies the parsed token against the
// issuer JWKS, trying the kid-matched key first, then every signing key,
// and decodes the verified claim set from the first key that verifies.
func (v *defaultVerifier) verifySignature(t token.Token, jwks jwk.Set) (map[string]any, error) {
	// Materialize candidate keys: kid match when present, all sig keys
	// otherwise.
	kid, kidErr := t.KeyID()
	var candidates []jwk.Key
	for i := 0; i < jwks.Len(); i++ {
		k, ok := jwks.Key(i)
		if !ok {
			continue
		}
		if use, hasUse := k.KeyUsage(); hasUse && use == "enc" {
			continue
		}
		if kidErr == nil {
			if kID, hasID := k.KeyID(); hasID && kID == kid {
				candidates = []jwk.Key{k}
				break
			}
			continue
		}
		candidates = append(candidates, k)
	}
	if len(candidates) == 0 {
		if kidErr == nil {
			return nil, fmt.Errorf("%w: no issuer key matches kid", ErrInvalidGrant)
		}
		return nil, fmt.Errorf("%w: issuer has no usable signing key", ErrInvalidGrant)
	}

	// Try each candidate key until one verifies; Claims both verifies
	// the signature and decodes the claim set.
	for _, k := range candidates {
		var claims map[string]any
		if err := t.Claims(k, &claims); err == nil {
			return claims, nil
		}
	}
	return nil, fmt.Errorf("%w: %w", ErrInvalidGrant, token.ErrInvalidTokenSignature)
}

// audienceMatchesRaw reports whether the raw aud claim is exactly the
// local issuer, as a string or a single-element array.
func audienceMatchesRaw(rawClaims map[string]any, localIssuer string) bool {
	switch aud := rawClaims["aud"].(type) {
	case string:
		return types.SecureCompareString(aud, localIssuer)
	case []any:
		if len(aud) != 1 {
			return false
		}
		s, ok := aud[0].(string)
		return ok && types.SecureCompareString(s, localIssuer)
	default:
		return false
	}
}

// validateTemporal enforces the RFC 7523 section 3 temporal rules: exp
// MUST be in the future, and nbf, when present, MUST be in the past.
func validateTemporal(rawClaims map[string]any, exp float64, now int64) error {
	if exp < float64(now) {
		return fmt.Errorf("%w: ID-JAG is expired", ErrInvalidGrant)
	}
	if _, hasNbf := rawClaims["nbf"]; hasNbf {
		nbf, err := numericClaim(rawClaims, "nbf")
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidGrant, err)
		}
		if nbf > float64(now) {
			return fmt.Errorf("%w: ID-JAG is not yet valid (nbf)", ErrInvalidGrant)
		}
	}
	return nil
}
