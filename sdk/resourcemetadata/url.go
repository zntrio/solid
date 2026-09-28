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
)

// httpsScheme is the only scheme a resource identifier and metadata URL
// members may use (RFC 9728 section 1.2).
const httpsScheme = "https"

// WellKnownSuffix is the default well-known URI path suffix for Protected
// Resource Metadata (RFC 9728 section 3).
const WellKnownSuffix = "oauth-protected-resource"

// WellKnownURL inserts /.well-known/<suffix> into the resource identifier
// between the host component and the path/query components (RFC 9728
// section 3, building on RFC 8615 section 2). A bare https://host/ maps to
// /.well-known/oauth-protected-resource, and
// /.well-known/oauth-protected-resource/resource1.
//
// The identifier MUST use the https scheme and MUST NOT carry a fragment
// (RFC 9728 section 1.2). A query component is allowed and carried through
// after the path. A terminating slash following the host component is
// removed before insertion. An empty suffix selects WellKnownSuffix; a
// suffix containing "/" is rejected (registry values are a single path
// segment, RFC 8615).
func WellKnownURL(resourceIdentifier, suffix string) (string, error) {
	if suffix == "" {
		suffix = WellKnownSuffix
	}
	if strings.Contains(suffix, "/") {
		return "", fmt.Errorf("resourcemetadata: well-known suffix %q must not contain %q", suffix, "/")
	}
	u, err := url.Parse(resourceIdentifier)
	if err != nil {
		return "", fmt.Errorf("resourcemetadata: unable to parse resource identifier %q: %w", resourceIdentifier, err)
	}
	if u.Scheme != httpsScheme {
		return "", fmt.Errorf("resourcemetadata: resource identifier %q must use the https scheme, got %q", resourceIdentifier, u.Scheme)
	}
	if u.Fragment != "" || strings.Contains(resourceIdentifier, "#") {
		return "", fmt.Errorf("resourcemetadata: resource identifier %q must not contain a fragment component", resourceIdentifier)
	}

	// Strip the terminating slash following the host component before
	// inserting the well-known path (RFC 9728 section 3.1).
	path := strings.TrimPrefix(u.Path, "/")

	// Insert /.well-known/<suffix> between the host and the path components
	// (RFC 9728 section 3.1): the original path is replaced, not appended to.
	wk := u
	wk.Path = "/.well-known/" + suffix
	if path != "" {
		wk.Path += "/" + path
	}
	wk.RawPath = ""
	wk.Fragment = ""
	wk.RawFragment = ""

	return wk.String(), nil
}
