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

// Package idjag implements the Identity Assertion JWT Authorization Grant
// (ID-JAG) mechanism defined by
// draft-ietf-oauth-identity-assertion-authz-grant-04 (Cross-App Access).
//
// An ID-JAG is a typed token (base typ "oauth-id-jag" qualified with the
// serializer media-type suffix, e.g. "oauth-id-jag+jwt") issued by an IdP
// Authorization Server and redeemed by a Resource Authorization Server
// via the JWT Bearer grant. The mechanism is serialization-format
// agnostic: minting and verification delegate to the assembly-provided
// token.Serializer / token.Verifier (JWT, CWT or PASETO); token-endpoint
// handling, subject resolution and trust configuration live in
// server/services/token and in assemblies.
package idjag
