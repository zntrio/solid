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

package handlers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestParseAuthorizationDetails exercises the token-endpoint form parameter
// parser (RFC 9396 section 6): valid arrays decode into typed details;
// malformed JSON, non-array payloads, null entries and missing type fields
// are rejected.
func TestParseAuthorizationDetails(t *testing.T) {
	t.Run("valid array with extensions", func(t *testing.T) {
		raw := `[{"type":"payment_initiation","actions":["initiate"],"instructedAmount":{"currency":"EUR","amount":"123.45"}}]`
		details, err := parseAuthorizationDetails(raw)
		require.NoError(t, err)
		require.Len(t, details, 1)
		require.Equal(t, "payment_initiation", details[0].Type)
		require.Equal(t, []string{"initiate"}, details[0].Actions)
		require.NotNil(t, details[0].Extensions["instructedAmount"])
	})

	t.Run("malformed json", func(t *testing.T) {
		_, err := parseAuthorizationDetails(`[{"type":`)
		require.Error(t, err)
	})

	t.Run("not an array", func(t *testing.T) {
		_, err := parseAuthorizationDetails(`{"type":"payment_initiation"}`)
		require.Error(t, err)
	})

	t.Run("null entry", func(t *testing.T) {
		_, err := parseAuthorizationDetails(`[null]`)
		require.Error(t, err)
	})

	t.Run("missing type", func(t *testing.T) {
		_, err := parseAuthorizationDetails(`[{"actions":["initiate"]}]`)
		require.Error(t, err)
		require.Contains(t, err.Error(), "type")
	})
}
