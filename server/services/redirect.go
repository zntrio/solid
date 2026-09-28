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

package services

import (
	"net"
	"net/url"
)

// RedirectURIMatchesRegistered reports whether the requested redirect URI is
// valid for the given client registration.
//
// Two rules apply (draft-ietf-oauth-v2-1-16 §4.1.1 and §8.4.2):
//   - the default comparison is a simple exact string match (RFC 3986
//     §6.2.1), the standard rule for redirect URI matching;
//   - the loopback interface exception: for native applications using an
//     http (not https) redirect URI whose host is the IP loopback interface
//     literal (127.0.0.1 or ::1), the port MAY vary between the registered
//     URI and the requested one — any other component MUST be identical.
func RedirectURIMatchesRegistered(registered []string, requested string) bool {
	for _, registeredURI := range registered {
		if registeredURI == requested {
			return true
		}
		if loopbackPortVaries(registeredURI, requested) {
			return true
		}
	}
	return false
}

// loopbackPortVaries reports whether requested equals candidate with only the
// port differing, both being http URIs on an IP loopback host literal.
func loopbackPortVaries(candidate, requested string) bool {
	candidateURL, errCandidate := url.ParseRequestURI(candidate)
	if errCandidate != nil {
		return false
	}
	requestedURL, errRequested := url.ParseRequestURI(requested)
	if errRequested != nil {
		return false
	}

	// Loopback exception applies to the http scheme only, with an IP
	// loopback literal host (draft-ietf-oauth-v2-1-16 §8.4.2).
	if candidateURL.Scheme != "http" || requestedURL.Scheme != "http" {
		return false
	}
	if !isIPLoopbackHost(candidateURL) || !isIPLoopbackHost(requestedURL) {
		return false
	}

	// Every component except the port MUST be identical.
	if candidateURL.Path != requestedURL.Path ||
		candidateURL.RawQuery != requestedURL.RawQuery ||
		candidateURL.Fragment != requestedURL.Fragment ||
		candidateURL.User != nil || requestedURL.User != nil {
		return false
	}

	// Compare hostnames: both must be loopback literals, but they must also
	// designate the same literal (127.0.0.1 vs ::1 do not match each other).
	if candidateURL.Hostname() != requestedURL.Hostname() {
		return false
	}

	return candidateURL.Port() != requestedURL.Port()
}

// isIPLoopbackHost reports whether the URL host is an IP loopback literal
// (IPv4 127.0.0.1 or IPv6 ::1).
func isIPLoopbackHost(u *url.URL) bool {
	ip := net.ParseIP(u.Hostname())
	return ip != nil && ip.IsLoopback()
}
