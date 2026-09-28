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

// Package resourcemetadata implements the client side of RFC 9728,
// OAuth 2.0 Protected Resource Metadata: resolving a protected resource
// identifier into a validated ProtectedResourceMetadata document.
//
// The mechanism is transport-agnostic: document retrieval is behind the
// Fetcher interface, satisfied structurally by sdk/httpfetch (the hardened
// HTTPS adapter). Validation follows the RFC with the project's defensive
// posture: https-only identifiers (section 1.2), no unsigned `none` signing
// algorithms (section 2), and the section 3.3 impersonation check (the
// `resource` member MUST match the identifier the well-known URL was derived
// from).
//
// Scope boundaries, deliberately:
//   - authorization_servers entries are issuer identifiers passed through
//     as-is; cross-checking them against AS metadata (RFC 9728 section 4)
//     is an application concern.
//   - language-tagged members (e.g. `resource_name#fr`, section 2.1) are
//     ignored via DiscardUnknown; multi-language metadata is not modeled.
//   - signed_metadata is accepted only through a caller-supplied
//     SignedMetadataVerifier; with no verifier configured, documents
//     carrying signed_metadata are rejected (fail-closed, section 2.2).
//     When verified, the plain document is returned as-is: merging signed
//     claims over plain values is consumer policy (section 2.2 precedence).
package resourcemetadata
