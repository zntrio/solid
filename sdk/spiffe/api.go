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

// Package spiffe implements the SPIFFE trust-bundle key distribution of
// draft-ietf-oauth-spiffe-client-auth-02 section 6: bundles of trust-domain
// signing keys (JWKS, RFC 7517) keyed by trust domain identifier, obtained
// either statically (pre-configured) or dynamically (SPIFFE bundle
// endpoints with refresh-hint polling).
package spiffe

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"

	"zntr.io/solid/sdk/jwk"
)

// -----------------------------------------------------------------------------

// BundleSource resolves the SPIFFE trust bundle (JWKS) of a trust domain.
// Bundles MUST be keyed by trust domain identifier (draft section 6), never
// derived from an SVID: keys come only from explicitly configured or
// pre-established sources, structurally satisfying the section 8.1
// prohibition on issuer-claim key discovery.
//
//go:generate mockgen -destination mock/bundlesource.gen.go -package mock zntr.io/solid/sdk/spiffe BundleSource

type BundleSource interface {
	Get(ctx context.Context, trustDomain string) (jwk.Set, error)
}

// Key uses recognized by the SPIFFE bundle format (draft section 6.1.1):
// the credential format the key is intended for.
const (
	// KeyUseJWTSVID marks keys used to sign JWT-SVIDs.
	KeyUseJWTSVID = "jwt-svid"
	// KeyUseWITSVID marks keys used to sign WIT-SVIDs.
	KeyUseWITSVID = "wit-svid"
	// KeyUseX509SVID marks keys used to sign X.509-SVIDs; the signing
	// certificate is carried in x5c.
	KeyUseX509SVID = "x509-svid"
)

// TrustDomainFromSPIFFEID parses a SPIFFE ID of the form
// spiffe://<trust-domain>[/path] and returns the trust domain (host part).
// SPIFFE IDs with a non-spiffe scheme or an empty host are rejected.
func TrustDomainFromSPIFFEID(id string) (string, error) {
	u, err := url.Parse(id)
	if err != nil {
		return "", fmt.Errorf("spiffe: invalid spiffe id %q: %w", id, err)
	}
	if u.Scheme != "spiffe" {
		return "", fmt.Errorf("spiffe: %q is not a spiffe id (scheme must be spiffe)", id)
	}
	if u.Host == "" {
		return "", fmt.Errorf("spiffe: %q has no trust domain", id)
	}
	return u.Host, nil
}

// MatchSPIFFEID reports whether a client's registered SPIFFE ID pattern
// matches the presented SPIFFE ID, implementing the wildcard semantics of
// draft section 5.1: a pattern ending with "/*" matches any SPIFFE ID whose
// prefix up to and including the final "/" is identical — i.e. wildcard
// expansion aligns with complete path segments
// (spiffe://example.org/client/* matches spiffe://example.org/client/123 but
// not spiffe://example.org/client123). Any other pattern requires an exact
// string match.
func MatchSPIFFEID(pattern, id string) bool {
	if pattern == "" || id == "" {
		return false
	}
	if !strings.HasSuffix(pattern, "/*") {
		return pattern == id
	}
	// Wildcard: prefix match up to and including the final "/" of the pattern.
	prefix := strings.TrimSuffix(pattern, "*") // keeps the trailing "/"
	if len(id) < len(prefix)-1 {
		return false
	}
	if !strings.HasPrefix(id, prefix) {
		return false
	}
	// Either the id ends exactly at the prefix boundary (id == pattern minus
	// the "*"), or the next character continues the path after the "/".
	return len(id) == len(prefix)-1 || id[len(prefix)-1] == '/'
}

// TrustDomainFromX509SVID extracts the SPIFFE ID from the URI SANs of an
// X.509-SVID certificate. A valid SVID carries exactly one URI SAN with the
// spiffe scheme (draft section 3.2, rule 2); anything else is rejected.
func TrustDomainFromX509SVID(cert *x509.Certificate) (spiffeID string, ok bool) {
	if cert == nil || len(cert.URIs) == 0 {
		return "", false
	}
	var found string
	count := 0
	for _, u := range cert.URIs {
		if u.Scheme == "spiffe" {
			found = u.String()
			count++
		}
	}
	if count != 1 {
		return "", false
	}
	return found, true
}

// KeysByUse filters a SPIFFE bundle down to the keys intended for the given
// credential format use (jwt-svid, wit-svid, x509-svid). Keys without a use
// are excluded: the bundle format (draft section 6.1.1) ties every key to a
// credential format, so an untagged key has no defined purpose.
func KeysByUse(set jwk.Set, use string) (jwk.Set, error) {
	if set == nil {
		return nil, fmt.Errorf("spiffe: nil keyset")
	}
	var keys []jwk.Key
	for i := 0; i < set.Len(); i++ {
		k, ok := set.Key(i)
		if !ok {
			continue
		}
		if ku, ok := k.KeyUsage(); ok && ku == use {
			keys = append(keys, k)
		}
	}
	filtered := jwk.NewSet()
	if err := filtered.Set("keys", keys); err != nil {
		return nil, fmt.Errorf("spiffe: unable to filter keyset: %w", err)
	}
	return filtered, nil
}
