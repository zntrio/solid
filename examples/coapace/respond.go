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

package main

import (
	"bytes"

	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"
	"github.com/plgd-dev/go-coap/v3/mux"

	"zntr.io/solid/sdk/ace"
)

// errInvalidRequest is the RFC 6749 error code fallback when a service
// rejection carries no typed error envelope.
const errInvalidRequest = "invalid_request"

// writeACEError responds with an RFC 9200 section 5.8.3 error payload
// (application/ace+cbor, abbreviated error code per Table 3).
func writeACEError(w mux.ResponseWriter, code codes.Code, errCode uint64, description string) {
	if err := w.SetResponse(code, message.MediaType(ace.ContentFormatACECBOR), bytes.NewReader(ace.EncodeError(errCode, description))); err != nil {
		printf("cannot write error response: %v", err)
	}
}

// coapCodeFor maps a service error code string to the CoAP response
// code (RFC 9200 section 5.8.3): invalid_client → 4.01, everything
// else defaults to 4.00.
func coapCodeFor(errCode string) codes.Code {
	switch errCode {
	case "invalid_client":
		return codes.Unauthorized
	case "invalid_scope", "unauthorized_client", "access_denied":
		return codes.Forbidden
	default:
		return codes.BadRequest
	}
}

// errorAbbrev maps a service error code string to its RFC 9200 Table 3
// integer abbreviation; unknown codes fall back to invalid_request (1)
// with the original description carried along.
func errorAbbrev(errCode string) uint64 {
	switch errCode {
	case errInvalidRequest:
		return ace.ErrInvalidRequest
	case "invalid_client":
		return ace.ErrInvalidClient
	case "invalid_grant":
		return ace.ErrInvalidGrant
	case "unauthorized_client":
		return ace.ErrUnauthorizedClient
	case "unsupported_grant_type":
		return ace.ErrUnsupportedGrantType
	case "invalid_scope":
		return ace.ErrInvalidScope
	default:
		return ace.ErrInvalidRequest
	}
}
