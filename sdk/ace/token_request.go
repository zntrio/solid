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

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/fxamacker/cbor/v2"
)

// TokenRequest is the decoded ACE token request (RFC 9200 section 5.8.1).
type TokenRequest struct {
	ClientID string
	Audience string
	Scope    string
	// GrantType is the raw integer abbreviation; 0 means absent (the
	// RFC 9200 section 5.8.1 default is client_credentials).
	GrantType uint64
	// ReqCnf is the optional PoP key the client asks the AS to bind to
	// the token (req_cnf, RFC 9200 section 5.8.1): a CWT-based DPoP
	// public key carried by value per RFC 8747 section 3.2.
	ReqCnf *Confirmation
}

// EncodeTokenRequest encodes a client_credentials token request as an
// application/ace+cbor map (RFC 9200 section 5.8.1, Table 5).
//
// The grant_type is always emitted explicitly (grant client_credentials,
// abbreviation 2 from Table 4) to avoid ambiguity, even though the RFC
// defaults to client_credentials. audience and scope are only present when
// non-empty.
func EncodeTokenRequest(clientID, audience, scope string) []byte {
	return EncodeTokenRequestWithOptions(clientID, audience, scope, nil)
}

// EncodeTokenRequestWithOptions encodes a client_credentials token
// request with an optional req_cnf confirmation (RFC 9200 section
// 5.8.1, key 4): the CWT-based DPoP public key the client asks the AS
// to bind to the issued token (RFC 8747 section 3.2).
func EncodeTokenRequestWithOptions(clientID, audience, scope string, reqCnf *Confirmation) []byte {
	req := map[int]any{
		KeyGrantType: GrantTypeClientCredentials,
		KeyClientId:  clientID,
	}
	if audience != "" {
		req[KeyAudience] = audience
	}
	if scope != "" {
		req[KeyScope] = scope
	}
	if reqCnf != nil {
		req[KeyReqCnf] = reqCnf.encode()
	}
	return encodeMap(req)
}

// canonical is the deterministic encoding mode used for every application/ace+cbor
// payload: length-first map key sorting as suggested by RFC 9200 appendix A.2.
var canonical cbor.EncMode

func init() {
	var err error
	canonical, err = cbor.EncOptions{Sort: cbor.SortLengthFirst}.EncMode()
	if err != nil {
		panic("ace: unable to initialize CBOR encoding mode: " + err.Error())
	}
}

// encodeMap deterministically marshals an application/ace+cbor map.
func encodeMap(v map[int]any) []byte {
	payload, err := canonical.Marshal(v)
	if err != nil {
		// map[int]any with []byte/string/uint/map values cannot fail to encode.
		panic(fmt.Sprintf("ace: unable to encode CBOR map: %v", err))
	}
	return payload
}

// decoder is the decoding mode for every application/ace+cbor payload:
// untyped maps decode to map[int]any at any nesting depth, so ACE integer
// keys are directly usable without shape normalization.
var decoder cbor.DecMode

func init() {
	var err error
	decoder, err = cbor.DecOptions{
		DefaultMapType: reflect.TypeOf(map[int]any{}),
	}.DecMode()
	if err != nil {
		panic("ace: unable to initialize CBOR decoding mode: " + err.Error())
	}
}

// DecodeTokenRequest decodes an application/ace+cbor token request payload
// (RFC 9200 section 5.8.1). Unknown integer keys are ignored, per the
// extensibility rule in the last paragraph of section 5.8.4.
//
// It returns an error when: the payload is not a CBOR map, a known key
// carries a value of the wrong CBOR type, or client_id is absent/empty.
func DecodeTokenRequest(payload []byte) (*TokenRequest, error) {
	var raw map[int]any
	if err := decoder.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("ace: malformed token request payload: %w", err)
	}
	if raw == nil {
		return nil, errors.New("ace: token request payload is not a CBOR map")
	}

	req := &TokenRequest{}
	for k, v := range raw {
		switch k {
		case KeyClientId:
			s, ok := v.(string)
			if !ok {
				return nil, errors.New("ace: client_id must be a text string")
			}
			req.ClientID = s
		case KeyAudience:
			s, ok := v.(string)
			if !ok {
				return nil, errors.New("ace: audience must be a text string")
			}
			req.Audience = s
		case KeyScope:
			s, ok := v.(string)
			if !ok {
				return nil, errors.New("ace: scope must be a text string")
			}
			req.Scope = s
		case KeyGrantType:
			n, err := asUint(v)
			if err != nil {
				return nil, errors.New("ace: grant_type must be an unsigned integer")
			}
			req.GrantType = n
		case KeyReqCnf:
			cnf, ok := decodeConfirmation(v)
			if !ok {
				return nil, errors.New("ace: req_cnf must be a COSE_Key or kid confirmation map")
			}
			req.ReqCnf = cnf
		default:
			// Unknown key: ignore (RFC 9200 section 5.8.4 extensibility).
		}
	}
	if req.ClientID == "" {
		return nil, errors.New("ace: client_id is required")
	}
	return req, nil
}

// asUint normalizes the numeric types fxamacker/cbor may decode into
// (uint64, uint32, uint16, uint8, int64, int32, ...) to uint64.
func asUint(v any) (uint64, error) {
	switch n := v.(type) {
	case uint64:
		return n, nil
	case uint32:
		return uint64(n), nil
	case uint16:
		return uint64(n), nil
	case uint8:
		return uint64(n), nil
	case int64:
		if n < 0 {
			return 0, errors.New("negative integer")
		}
		return uint64(n), nil
	case int32:
		if n < 0 {
			return 0, errors.New("negative integer")
		}
		return uint64(n), nil
	case int:
		if n < 0 {
			return 0, errors.New("negative integer")
		}
		return uint64(n), nil
	default:
		return 0, errors.New("not an integer")
	}
}
