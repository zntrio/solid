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

package token

import (
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
)

// X5tS256ConfirmationKey is the RFC 8705 section 3.1 confirmation
// method member name, carrying the base64url SHA-256 thumbprint of the
// client certificate DER encoding.
const X5tS256ConfirmationKey = "x5t#S256"

// JSONConfirmation re-marshals a TokenConfirmation with the RFC-mandated
// member names: "x5t#S256" per RFC 8705 section 3.1; "jkt" keeps its
// proto name (RFC 9449). The generated protojson MarshalJSON uses
// UseProtoNames, which would emit the proto field name "x5t_s256"
// instead of the wire-mandated member name; this adapter restores the
// correct wire format for the JWT "cnf" claim and the introspection
// "cnf" member.
type JSONConfirmation struct {
	Jkt     string `json:"jkt,omitempty"`
	X5tS256 string `json:"x5t#S256,omitempty"`
}

// ConfirmationAsJSON converts a TokenConfirmation into its
// RFC-compliant JSON shape. It is nil-safe: a nil confirmation
// yields a nil adapter value.
func ConfirmationAsJSON(c *tokenv1.TokenConfirmation) *JSONConfirmation {
	if c == nil {
		return nil
	}
	return &JSONConfirmation{
		Jkt:     c.Jkt,
		X5tS256: c.X5TS256,
	}
}
