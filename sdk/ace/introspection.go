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
)

// EncodeIntrospectionRequest encodes a CoAP token introspection request
// (RFC 9200 section 5.9.1, Table 6): the token as byte string (key 11)
// plus an optional token_type_hint abbreviation (key 33); hint == 0
// omits the member.
func EncodeIntrospectionRequest(token []byte, hint uint64) []byte {
	req := map[int]any{
		KeyToken: token,
	}
	if hint != 0 {
		req[KeyTokenTypeHint] = hint
	}
	return encodeMap(req)
}

// DecodeIntrospectionRequest extracts the token (key 11) and the optional
// token_type_hint abbreviation (key 33; 0 when absent). It returns an
// error when the payload is not a CBOR map, the token member is absent,
// empty, or not a byte string, or a known member has the wrong CBOR type.
// Unknown integer keys are ignored.
func DecodeIntrospectionRequest(payload []byte) (token []byte, hint uint64, err error) {
	var raw map[int]any
	if err := decoder.Unmarshal(payload, &raw); err != nil {
		return nil, 0, fmt.Errorf("ace: malformed introspection request payload: %w", err)
	}
	if raw == nil {
		return nil, 0, errors.New("ace: introspection request payload is not a CBOR map")
	}

	for k, v := range raw {
		switch k {
		case KeyToken:
			b, ok := v.([]byte)
			if !ok {
				return nil, 0, errors.New("ace: token must be a byte string")
			}
			token = b
		case KeyTokenTypeHint:
			n, err := asUint(v)
			if err != nil {
				return nil, 0, errors.New("ace: token_type_hint must be an unsigned integer")
			}
			hint = n
		default:
			// Unknown key: ignore (RFC 9200 section 5.8.4 extensibility).
		}
	}
	if len(token) == 0 {
		return nil, 0, errors.New("ace: token is required")
	}
	return token, hint, nil
}

// EncodeIntrospectionResponse encodes a CoAP introspection response
// (RFC 9200 section 5.9.2, Table 6). Empty scope/clientID omit the
// corresponding members; cnf may be nil. Timestamps are absolute Unix
// times; zero omits the member.
func EncodeIntrospectionResponse(active bool, scope, clientID string, exp, iat, nbf uint64, cnf *Confirmation) []byte {
	res := map[int]any{
		KeyActive: active,
	}
	if scope != "" {
		res[KeyScope] = scope
	}
	if clientID != "" {
		res[KeyClientId] = clientID
	}
	if exp != 0 {
		res[KeyExp] = exp
	}
	if iat != 0 {
		res[KeyIat] = iat
	}
	if nbf != 0 {
		res[KeyNbf] = nbf
	}
	if cnf != nil {
		res[KeyCnf] = cnf.encode()
	}
	return encodeMap(res)
}

// IntrospectionResponse is a decoded RFC 9200 section 5.9.2 payload.
type IntrospectionResponse struct {
	Active   bool
	Scope    string
	ClientID string
	Exp      uint64
	Iat      uint64
	Nbf      uint64
	Cnf      *Confirmation
}

// DecodeIntrospectionResponse parses an introspection response payload.
// Unknown integer keys are ignored; known keys with wrong CBOR types
// produce an error.
//
//nolint:gocyclo // linear RFC-ordered member validation; each guard is a protocol requirement
func DecodeIntrospectionResponse(payload []byte) (*IntrospectionResponse, error) {
	var raw map[int]any
	if err := decoder.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("ace: malformed introspection response payload: %w", err)
	}
	if raw == nil {
		return nil, errors.New("ace: introspection response payload is not a CBOR map")
	}

	res := &IntrospectionResponse{}
	for k, v := range raw {
		switch k {
		case KeyActive:
			b, ok := v.(bool)
			if !ok {
				return nil, errors.New("ace: active must be a boolean")
			}
			res.Active = b
		case KeyScope:
			s, ok := v.(string)
			if !ok {
				return nil, errors.New("ace: scope must be a text string")
			}
			res.Scope = s
		case KeyClientId:
			s, ok := v.(string)
			if !ok {
				return nil, errors.New("ace: client_id must be a text string")
			}
			res.ClientID = s
		case KeyExp:
			n, err := asUint(v)
			if err != nil {
				return nil, errors.New("ace: exp must be an unsigned integer")
			}
			res.Exp = n
		case KeyIat:
			n, err := asUint(v)
			if err != nil {
				return nil, errors.New("ace: iat must be an unsigned integer")
			}
			res.Iat = n
		case KeyNbf:
			n, err := asUint(v)
			if err != nil {
				return nil, errors.New("ace: nbf must be an unsigned integer")
			}
			res.Nbf = n
		case KeyCnf:
			cnf, ok := decodeConfirmation(v)
			if !ok {
				return nil, errors.New("ace: cnf must be a COSE_Key confirmation map")
			}
			res.Cnf = cnf
		default:
			// Unknown key: ignore (RFC 9200 section 5.8.4 extensibility).
		}
	}
	return res, nil
}
