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

// Package cimd implements the OAuth Client ID Metadata Document mechanism
// (draft-ietf-oauth-client-id-metadata-document), a wire-agnostic building
// block for resolving URL-shaped client identifiers into client metadata
// without prior registration.
package cimd

import (
	"net/url"
	"strings"
)

// IsClientIdentifierURL reports whether id is a valid Client Identifier URL
// as defined by draft-ietf-oauth-client-id-metadata-document, section 3:
//
//   - MUST use the https URL scheme
//   - MUST NOT contain a userinfo component
//   - MAY contain a port
//   - MUST contain a path component
//   - MUST NOT contain single-dot or double-dot path components
//   - SHOULD NOT contain a query component (accepted, not rejected)
//   - MUST NOT contain a fragment component
//
// Client Identifier URLs are compared with simple string comparison by the
// caller; this function performs no normalization on purpose.
func IsClientIdentifierURL(id string) bool {
	u, err := url.Parse(id)
	if err != nil {
		return false
	}
	if u.Scheme != "https" {
		return false
	}
	if u.User != nil {
		return false
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return false
	}
	path := u.EscapedPath()
	if path == "" {
		return false
	}
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		// Path is only slashes; still a path component, but no segments to
		// check for dots.
		return true
	}
	for _, seg := range strings.Split(trimmed, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}
