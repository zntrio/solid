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

package resourcemetadata

import (
	"fmt"
	"net/url"
	"strings"

	discoveryv1 "zntr.io/solid/api/oidc/discovery/v1"
)

// DecodeProtectedResourceMetadata parses a raw Protected Resource Metadata
// JSON body (RFC 9728 section 2) and applies the defensive validation
// posture:
//
//   - the `resource` member is REQUIRED and MUST be a valid https URL
//     without a fragment component (sections 1.2 and 2)
//   - `jwks_uri`, when present, MUST use the https scheme (section 2)
//   - `resource_signing_alg_values_supported` MUST NOT contain `none`
//     (section 2: unsigned metadata MUST NOT be offered)
//
// Unknown members are ignored (section 3.2: parameters that are not
// understood MUST be ignored). signed_metadata is not validated here; it is
// the resolver's concern, through the configured SignedMetadataVerifier.
func DecodeProtectedResourceMetadata(b []byte) (*discoveryv1.ProtectedResourceMetadata, error) {
	md := new(discoveryv1.ProtectedResourceMetadata)
	if err := md.UnmarshalJSON(b); err != nil {
		return nil, fmt.Errorf("resourcemetadata: unable to decode document: %w", err)
	}

	// REQUIRED `resource` member, https and fragment-free (section 1.2).
	if md.GetResource() == "" {
		return nil, fmt.Errorf("resourcemetadata: document is missing the required %q member", "resource")
	}
	u, err := url.Parse(md.GetResource())
	if err != nil {
		return nil, fmt.Errorf("resourcemetadata: resource %q is not a valid url: %w", md.GetResource(), err)
	}
	if u.Scheme != httpsScheme {
		return nil, fmt.Errorf("resourcemetadata: resource %q must use the https scheme", md.GetResource())
	}
	if u.Fragment != "" || strings.Contains(md.GetResource(), "#") {
		return nil, fmt.Errorf("resourcemetadata: resource %q must not contain a fragment component", md.GetResource())
	}

	// OPTIONAL `jwks_uri` member MUST use https (section 2).
	if v := md.GetJwksUri(); v != "" {
		ju, err := url.Parse(v)
		if err != nil {
			return nil, fmt.Errorf("resourcemetadata: jwks_uri %q is not a valid url: %w", v, err)
		}
		if ju.Scheme != httpsScheme {
			return nil, fmt.Errorf("resourcemetadata: jwks_uri %q must use the https scheme", v)
		}
	}

	// `none` MUST NOT be advertised for signed content (section 2).
	for _, alg := range md.GetResourceSigningAlgValuesSupported() {
		if strings.EqualFold(alg, "none") {
			return nil, fmt.Errorf("resourcemetadata: resource_signing_alg_values_supported must not contain %q", "none")
		}
	}

	return md, nil
}
