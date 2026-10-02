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

// Package ace implements the CBOR wire codec for the Authentication and
// Authorization for Constrained Environments (ACE) OAuth 2.0 profile,
// RFC 9200, plus its companion profiles RFC 9201 (COSE ProfilE) and
// RFC 9202 (DTLS Profile for ACE).
//
// The package is presentation-agnostic: it only encodes and decodes
// application/ace+cbor payloads (CoAP Content-Format 19) as defined by
// RFC 9200 section 5 (token endpoint, introspection) and section 5.10
// (authz-info / AS Request Creation Hints). It does not depend on any
// transport (CoAP, HTTP, gRPC) and carries no server-side logic.
//
// Integer keys, grant/token/profile abbreviations and error codes are the
// registered values from RFC 9200 Tables 1, 3, 4, 5, 6 and section 8.
package ace
