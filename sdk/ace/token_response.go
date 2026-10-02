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

// TokenResponse is a decoded AS-to-client token response (RFC 9200
// section 5.8.2 Access Information, or section 5.8.3 error).
type TokenResponse struct {
	AccessToken []byte
	ExpiresIn   uint64
	TokenType   uint64
	AceProfile  uint64
	Cnf         *Confirmation
	Error       *Error
}

// Error is an RFC 9200 section 5.8.3 error payload.
type Error struct {
	Code        uint64
	Description string
	URI         string
}

// EncodeTokenResponse encodes Access Information (RFC 9200 section 5.8.2)
// as an application/ace+cbor map, the payload of a 2.01 (Created) CoAP
// response. cnf may be nil to omit the confirmation member.
func EncodeTokenResponse(accessToken []byte, expiresIn, tokenType uint64, cnf *Confirmation, aceProfile uint64) []byte {
	resp := map[int]any{
		KeyAccessToken: accessToken,
		KeyExpiresIn:   expiresIn,
		KeyTokenType:   tokenType,
	}
	if cnf != nil {
		resp[KeyCnf] = cnf.encode()
	}
	if aceProfile != 0 {
		resp[KeyAceProfile] = aceProfile
	}

	return encodeMap(resp)
}

// DecodeTokenResponse parses an AS token endpoint response payload. When
// the error key (30) is present, res.Error is set and the access-token
// members remain empty; unknown integer keys are ignored.
//
//nolint:funlen,gocyclo // linear RFC-ordered member validation; each guard is a protocol requirement
func DecodeTokenResponse(payload []byte) (*TokenResponse, error) {
	var raw map[int]any
	if err := decoder.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("ace: malformed token response payload: %w", err)
	}
	if raw == nil {
		return nil, errors.New("ace: token response payload is not a CBOR map")
	}

	res := &TokenResponse{}
	for k, v := range raw {
		switch k {
		case KeyError:
			n, err := asUint(v)
			if err != nil {
				return nil, errors.New("ace: error must be an integer")
			}
			res.Error = &Error{Code: n}
		case KeyErrorDescription:
			s, ok := v.(string)
			if !ok {
				return nil, errors.New("ace: error_description must be a text string")
			}
			if res.Error != nil {
				res.Error.Description = s
			}
		case KeyErrorUri:
			s, ok := v.(string)
			if !ok {
				return nil, errors.New("ace: error_uri must be a text string")
			}
			if res.Error != nil {
				res.Error.URI = s
			}
		case KeyAccessToken:
			b, ok := v.([]byte)
			if !ok {
				return nil, errors.New("ace: access_token must be a byte string")
			}
			res.AccessToken = b
		case KeyExpiresIn:
			n, err := asUint(v)
			if err != nil {
				return nil, errors.New("ace: expires_in must be an unsigned integer")
			}
			res.ExpiresIn = n
		case KeyTokenType:
			n, err := asUint(v)
			if err != nil {
				return nil, errors.New("ace: token_type must be an unsigned integer")
			}
			res.TokenType = n
		case KeyAceProfile:
			n, err := asUint(v)
			if err != nil {
				return nil, errors.New("ace: ace_profile must be an integer")
			}
			res.AceProfile = n
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

// EncodeError encodes an RFC 9200 section 5.8.3 error payload with the
// abbreviated error code (Table 3) and an optional human-readable
// description (omitted when empty).
func EncodeError(errorCode uint64, description string) []byte {
	err := map[int]any{
		KeyError: errorCode,
	}
	if description != "" {
		err[KeyErrorDescription] = description
	}
	return encodeMap(err)
}
