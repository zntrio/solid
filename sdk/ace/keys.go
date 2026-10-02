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

package ace

// ContentFormatACECBOR is the CoAP Content-Format ID for the
// "application/ace+cbor" media type (RFC 9200 section 8.16).
const ContentFormatACECBOR = 19

// Parameter CBOR keys from RFC 9200 Table 5 (token request / response).
const (
	KeyAccessToken      = 1  // byte string
	KeyExpiresIn        = 2  // unsigned integer
	KeyAudience         = 5  // text string
	KeyReqCnf           = 4  // map
	KeyScope            = 9  // text string
	KeyCnf              = 8  // map
	KeyRsCnf            = 41 // map
	KeyClientId         = 24 // text string
	KeyError            = 30 // integer
	KeyErrorDescription = 31 // text string
	KeyErrorUri         = 32 // text string
	KeyGrantType        = 33 // unsigned integer
	KeyTokenType        = 34 // unsigned integer
	KeyRefreshToken     = 37 // byte string
	KeyAceProfile       = 38 // integer
	KeyCnonce           = 39 // byte string
)

// Introspection timestamps (RFC 9200 Table 6): nbf, exp, iat.
const (
	KeyExp = 4 // unsigned integer
	KeyNbf = 5 // unsigned integer
	KeyIat = 6 // unsigned integer
)

// Additional CBOR keys: RFC 9200 Table 6 (introspection response) and
// Table 1 (AS Request Creation Hints), where not already defined above.
const (
	KeyActive        = 10 // boolean (introspection)
	KeyToken         = 11 // byte string (introspection request payload)
	KeyTokenTypeHint = 33 // unsigned integer (introspection request)
)

// Error code abbreviations from RFC 9200 Table 3.
const (
	ErrInvalidRequest         = 1
	ErrInvalidClient          = 2
	ErrInvalidGrant           = 3
	ErrUnauthorizedClient     = 4
	ErrUnsupportedGrantType   = 5
	ErrInvalidScope           = 6
	ErrUnsupportedPopKey      = 7
	ErrIncompatibleAceProfile = 8
)

// Grant type abbreviations from RFC 9200 Table 4.
const (
	GrantTypeClientCredentials = 2
)

// Token type abbreviations from RFC 9200 section 8.7.
const (
	TokenTypeBearer = 1
	TokenTypePoP    = 2
)

// ACE profile abbreviations; coap_dtls is defined in RFC 9202 section 9.
const (
	AceProfileCoapDTLS = 1
)
