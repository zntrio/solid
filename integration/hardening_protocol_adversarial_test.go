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

package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"zntr.io/solid/sdk/types"
)

// TestAdversarial_JARIssMismatch pins the request-object iss validation
// (RFC 9101 section 5): the iss claim, when present, must equal the
// request's client_id — a request object signed by one client but claiming
// another's identity in iss is rejected.
func TestAdversarial_JARIssMismatch(t *testing.T) {
	// iss differing from client_id: rejected at decode.
	raw := signedRequestObject(t, jarClaims(map[string]any{
		"iss":       "https://attacker.example",
		"client_id": "confidential-client-1",
	}))
	_, err := jarDecoder().Decode(t.Context(), raw)
	require.Error(t, err, "iss != client_id must be rejected")
}

// TestAdversarial_ScopeCaseConfusion pins RFC 6749 section 3.3 at the
// entitlement layer: scope tokens are case-sensitive — a registered
// "timestamp:read" must not satisfy a requested "Timestamp:Read" (nor
// the reverse), so a case-swapped scope cannot ride an entitlement check.
func TestAdversarial_ScopeCaseConfusion(t *testing.T) {
	registered := types.StringArray{"timestamp:read", "openid"}

	assert.True(t, registered.Contains("timestamp:read"))
	assert.False(t, registered.Contains("Timestamp:Read"), "case-swapped scope must not match the registered token")
	assert.False(t, registered.Contains("TIMESTAMP:READ"), "upper-cased scope must not match the registered token")
}

// TestAdversarial_StringArrayExactMatchSemantics pins the exact-match
// comparison policy shared by every entitlement check (scopes, grant
// types, response modes, audiences): only byte-equal strings match.
func TestAdversarial_StringArrayExactMatchSemantics(t *testing.T) {
	list := types.StringArray{"client_credentials", "refresh_token"}

	assert.True(t, list.Contains("client_credentials"))
	assert.False(t, list.Contains("Client_Credentials"))
	assert.False(t, list.Contains("CLIENT_CREDENTIALS"))
	assert.False(t, list.Contains("client-credentials"))
}
