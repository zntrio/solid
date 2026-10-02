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

// RFC 9200 (ACE-OAuth) adversarial coverage of the application/ace+cbor
// wire codec (sdk/ace): attacker-controlled payloads against every
// decoder surface. The attack vectors mirror the RFC 9700 A5 token
// attacker posture applied to the CoAP presentation: malformed CBOR,
// type-confused members, forged confirmations, truncated payloads and
// ambiguity attacks on the token-request/response maps.
package integration

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"zntr.io/solid/sdk/ace"
)

// rawCBOR builds a CBOR payload from an arbitrary Go value with the
// plain library encoder (attacker tooling: no canonical options).
func rawCBOR(t *testing.T, v any) []byte {
	t.Helper()
	b, err := cbor.Marshal(v)
	require.NoError(t, err)
	return b
}

func TestACEAdversarialCodecTokenRequest(t *testing.T) {
	t.Run("not a map", func(t *testing.T) {
		for _, payload := range [][]byte{
			{0x82, 0x01, 0x02}, // array [1, 2]
			{0x01},             // integer
			{0x40},             // empty byte string
			{0xf6},             // null
			{0x00, 0x00, 0x00}, // truncated indefinite map header
			{},                 // empty payload
		} {
			_, err := ace.DecodeTokenRequest(payload)
			require.Error(t, err, "payload %x accepted", payload)
		}
	})

	t.Run("type confusion on known members", func(t *testing.T) {
		vectors := map[string][]byte{
			// {24: 2} — client_id as integer
			"integer client_id": rawCBOR(t, map[int]any{24: 2}),
			// {24: "c", 5: 2} — audience as integer
			"integer audience": rawCBOR(t, map[int]any{24: "c", 5: 2}),
			// {24: "c", 9: true} — scope as boolean
			"boolean scope": rawCBOR(t, map[int]any{24: "c", 9: true}),
			// {24: "c", 33: "client_credentials"} — grant_type as text
			"text grant_type": rawCBOR(t, map[int]any{24: "c", 33: "client_credentials"}),
			// {24: "c", 4: " forged "} — req_cnf as text string, not a map
			"text req_cnf": rawCBOR(t, map[int]any{24: "c", 4: "forged"}),
		}
		for name, payload := range vectors {
			_, err := ace.DecodeTokenRequest(payload)
			require.Error(t, err, "%s accepted", name)
		}
	})

	t.Run("client id absent or empty", func(t *testing.T) {
		for _, payload := range [][]byte{
			rawCBOR(t, map[int]any{33: 2}),         // no client_id
			rawCBOR(t, map[int]any{24: "", 33: 2}), // empty client_id
			rawCBOR(t, map[int]any{}),              // empty map
		} {
			_, err := ace.DecodeTokenRequest(payload)
			require.Error(t, err, "payload %x accepted", payload)
		}
	})

	t.Run("unknown members ignored not fatal", func(t *testing.T) {
		// Attacker appends unknown keys (99, -1) with arbitrary values;
		// RFC 9200 section 5.8.4 extensibility: decoders ignore them
		// without changing the recognized members.
		payload := rawCBOR(t, map[int]any{24: "c", 5: "a", 9: "s", 99: []byte{0x00, 0x01}, -1: true})
		req, err := ace.DecodeTokenRequest(payload)
		require.NoError(t, err)
		assert.Equal(t, "c", req.ClientID)
		assert.Equal(t, "a", req.Audience)
		assert.Equal(t, "s", req.Scope)
	})

	t.Run("trailing garbage rejected", func(t *testing.T) {
		payload := append(rawCBOR(t, map[int]any{24: "c"}), 0x00, 0x00, 0x00)
		_, err := ace.DecodeTokenRequest(payload)
		require.Error(t, err)
	})

	t.Run("req_cnf kid forgery decodes but carries only a reference", func(t *testing.T) {
		// An attacker crafts req_cnf with a kid-only reference to a key
		// they do not own: the codec must faithfully surface the
		// reference; the AS (not the codec) is the trust boundary.
		payload := rawCBOR(t, map[int]any{
			24: "c",
			4:  map[int]any{3: []byte("someone-elses-key")},
		})
		req, err := ace.DecodeTokenRequest(payload)
		require.NoError(t, err)
		require.NotNil(t, req.ReqCnf)
		assert.Equal(t, []byte("someone-elses-key"), req.ReqCnf.KID)
		assert.Nil(t, req.ReqCnf.COSEKey, "kid and COSE_Key are mutually exclusive")
	})

	t.Run("req_cnf coSE key with truncated coordinates", func(t *testing.T) {
		// Malformed EC2 key: missing x coordinate.
		payload := rawCBOR(t, map[int]any{
			24: "c",
			4:  map[int]any{1: map[int]any{1: 2, -1: 1, -3: []byte{0x01}}},
		})
		req, err := ace.DecodeTokenRequest(payload)
		require.NoError(t, err, "codec is permissive; the AS validates key material")
		if req.ReqCnf != nil && req.ReqCnf.COSEKey != nil {
			assert.Empty(t, req.ReqCnf.COSEKey.X, "absent x coordinate must surface as empty")
		}
	})
}

func TestACEAdversarialCodecTokenResponse(t *testing.T) {
	t.Run("malformed payloads", func(t *testing.T) {
		for _, payload := range [][]byte{
			{0x82, 0x01, 0x02}, // array
			{0xf6},             // null
			{},                 // empty
		} {
			_, err := ace.DecodeTokenResponse(payload)
			require.Error(t, err, "payload %x accepted", payload)
		}
	})

	t.Run("type confusion on known members", func(t *testing.T) {
		vectors := map[string][]byte{
			"integer access_token": rawCBOR(t, map[int]any{1: 2}),
			"text expires_in":      rawCBOR(t, map[int]any{2: "3600"}),
			"negative expires_in":  rawCBOR(t, map[int]any{2: -1}),
			"text error":           rawCBOR(t, map[int]any{30: "invalid_client"}),
			"array cnf":            rawCBOR(t, map[int]any{8: []any{1, 2}}),
			// cnf with both COSE_Key and kid: not a single-PoP-key cnf
			// (RFC 8747 section 3.1); the decoder must not error but must
			// deterministically prefer one representation.
			"ambiguous cnf": rawCBOR(t, map[int]any{8: map[int]any{
				1: map[int]any{1: 2, -1: 1, -2: []byte{1}, -3: []byte{2}},
				3: []byte("kid"),
			}}),
		}
		for name, payload := range vectors {
			res, err := ace.DecodeTokenResponse(payload)
			switch name {
			case "ambiguous cnf":
				require.NoError(t, err)
				require.NotNil(t, res.Cnf, "ambiguous cnf must still decode to one representation")
				assert.NotNil(t, res.Cnf.COSEKey, "COSE_Key wins over kid on ambiguity")
			default:
				require.Error(t, err, "%s accepted", name)
			}
		}
	})

	t.Run("error payload only carries the error envelope", func(t *testing.T) {
		// {30: 2} — invalid_client
		res, err := ace.DecodeTokenResponse([]byte{0xa1, 0x18, 0x1e, 0x02})
		require.NoError(t, err)
		require.NotNil(t, res.Error)
		assert.Equal(t, uint64(ace.ErrInvalidClient), res.Error.Code)
		assert.Empty(t, res.AccessToken, "no token leaks in an error payload")
	})
}

func TestACEAdversarialCodecIntrospection(t *testing.T) {
	t.Run("request vectors", func(t *testing.T) {
		vectors := map[string][]byte{
			"not a map":     {0x82, 0x01, 0x02},
			"missing token": rawCBOR(t, map[int]any{}),
			"empty token":   rawCBOR(t, map[int]any{11: []byte{}}),
			"text token":    rawCBOR(t, map[int]any{11: "token-value"}),
			"text hint":     rawCBOR(t, map[int]any{11: []byte("t"), 33: "access_token"}),
		}
		for name, payload := range vectors {
			_, _, err := ace.DecodeIntrospectionRequest(payload)
			require.Error(t, err, "%s accepted", name)
		}
	})

	t.Run("response vectors", func(t *testing.T) {
		vectors := map[string][]byte{
			"integer active": rawCBOR(t, map[int]any{10: 1}),
			"integer scope":  rawCBOR(t, map[int]any{10: true, 9: 7}),
			"text exp":       rawCBOR(t, map[int]any{10: true, 4: "later"}),
			"array cnf":      rawCBOR(t, map[int]any{10: true, 8: []any{}}),
		}
		for name, payload := range vectors {
			_, err := ace.DecodeIntrospectionResponse(payload)
			require.Error(t, err, "%s accepted", name)
		}
	})

	t.Run("inactive response leaks no claims", func(t *testing.T) {
		// The AS renders unknown/inactive tokens as the bare inactive
		// envelope; the codec must round-trip that shape without
		// inventing claims.
		payload := ace.EncodeIntrospectionResponse(false, "", "", 0, 0, 0, nil)
		res, err := ace.DecodeIntrospectionResponse(payload)
		require.NoError(t, err)
		assert.False(t, res.Active)
		assert.Empty(t, res.Scope)
		assert.Empty(t, res.ClientID)
		assert.Nil(t, res.Cnf)
	})
}

func TestACEAdversarialCodecHints(t *testing.T) {
	// The hints payload is rendered by the RS; malformed inputs are not
	// decoded by the codec (write-only surface), but the encoder must
	// never emit an empty map for a fully-specified hint set.
	got := ace.EncodeASRequestCreationHints("coaps://as/token", "coaps://rs", "temperature:read")
	require.NotEmpty(t, got)
	// Wire shape: exactly the three members (16, 5, 9).
	decoded := map[int]any{}
	err := cbor.Unmarshal(got, &decoded)
	require.NoError(t, err)
	for _, k := range []int{16, 5, 9} {
		_, ok := decoded[k]
		assert.True(t, ok, "hints payload missing member %d", k)
	}
}

func TestACEAdversarialGoldenHex(t *testing.T) {
	// Known-goods must decode deterministically (guards a malicious or
	// accidental codec drift between versions).
	tokenReq, err := hex.DecodeString("a3056773656e736f72731818686d79636c69656e74182102")
	require.NoError(t, err)
	req, err := ace.DecodeTokenRequest(tokenReq)
	require.NoError(t, err)
	assert.Equal(t, "myclient", req.ClientID)
	assert.Equal(t, "sensors", req.Audience)
	assert.Equal(t, uint64(ace.GrantTypeClientCredentials), req.GrantType)
}

func TestACEAdversarialKeyConstantDrift(t *testing.T) {
	// RFC 9200/8747 registered values: a drifted constant silently
	// breaks wire compatibility; assert the registry truth.
	assert.Equal(t, 19, ace.ContentFormatACECBOR)
	for k, want := range map[string]struct {
		got  int
		want int
	}{
		"access_token": {ace.KeyAccessToken, 1},
		"expires_in":   {ace.KeyExpiresIn, 2},
		"req_cnf":      {ace.KeyReqCnf, 4},
		"audience":     {ace.KeyAudience, 5},
		"cnf":          {ace.KeyCnf, 8},
		"scope":        {ace.KeyScope, 9},
		"active":       {ace.KeyActive, 10},
		"token":        {ace.KeyToken, 11},
		"client_id":    {ace.KeyClientId, 24},
		"error":        {ace.KeyError, 30},
		"error_desc":   {ace.KeyErrorDescription, 31},
		"grant_type":   {ace.KeyGrantType, 33},
		"token_type":   {ace.KeyTokenType, 34},
		"ace_profile":  {ace.KeyAceProfile, 38},
		"rs_cnf":       {ace.KeyRsCnf, 41},
		"cose_key":     {ace.CnfCoseKey, 1},
		"cnf kid":      {ace.CnfKid, 3},
		"as hints":     {ace.KeyAS, 16},
	} {
		assert.Equal(t, want.want, want.got, "%s constant drifted", k)
	}
	for k, want := range map[string]struct {
		got  uint64
		want uint64
	}{
		"invalid_request":          {ace.ErrInvalidRequest, 1},
		"invalid_client":           {ace.ErrInvalidClient, 2},
		"invalid_grant":            {ace.ErrInvalidGrant, 3},
		"unauthorized_client":      {ace.ErrUnauthorizedClient, 4},
		"unsupported_grant_type":   {ace.ErrUnsupportedGrantType, 5},
		"invalid_scope":            {ace.ErrInvalidScope, 6},
		"unsupported_pop_key":      {ace.ErrUnsupportedPopKey, 7},
		"incompatible_profiles":    {ace.ErrIncompatibleAceProfile, 8},
		"grant client_credentials": {ace.GrantTypeClientCredentials, 2},
		"token bearer":             {ace.TokenTypeBearer, 1},
		"token pop":                {ace.TokenTypePoP, 2},
		"profile coap_dtls":        {ace.AceProfileCoapDTLS, 1},
	} {
		assert.Equal(t, want.want, want.got, "%s constant drifted", k)
	}
	_ = bytes.Equal // keep import parity with the harness style
}
