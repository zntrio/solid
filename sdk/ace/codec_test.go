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
	"bytes"
	"encoding/hex"
	"testing"
)

// key ordering) that fxamacker/cbor produces, matching the wire form of
// the RFC 9200 examples (Figures 2, 4, 7, 10) and RFC 9202 Figure 6.

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex: %v", err)
	}
	return b
}

func TestContentFormat(t *testing.T) {
	if ContentFormatACECBOR != 19 {
		t.Errorf("ContentFormatACECBOR = %d, want 19 (RFC 9200 section 8.16)", ContentFormatACECBOR)
	}
}

func TestEncodeTokenRequestGolden(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		audience string
		scope    string
		wantHex  string
	}{
		{
			name:     "client and audience",
			clientID: "myclient",
			audience: "sensors",
			wantHex:  "a3056773656e736f72731818686d79636c69656e74182102",
		},

		{
			name:     "full request",
			clientID: "myclient",
			audience: "coaps://127.0.0.1:5685",
			scope:    "temperature:read",
			wantHex:  "a40576636f6170733a2f2f3132372e302e302e313a35363835097074656d70657261747572653a726561641818686d79636c69656e74182102",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncodeTokenRequest(tt.clientID, tt.audience, tt.scope)
			if want := mustHex(t, tt.wantHex); !bytes.Equal(got, want) {
				t.Errorf("EncodeTokenRequest() = %x, want %x", got, want)
			}
		})
	}
}

func TestTokenRequestRoundTrip(t *testing.T) {
	payload := EncodeTokenRequest("myclient", "coaps://127.0.0.1:5685", "temperature:read")
	req, err := DecodeTokenRequest(payload)
	if err != nil {
		t.Fatalf("DecodeTokenRequest: %v", err)
	}
	if req.ClientID != "myclient" {
		t.Errorf("ClientID = %q, want myclient", req.ClientID)
	}
	if req.Audience != "coaps://127.0.0.1:5685" {
		t.Errorf("Audience = %q", req.Audience)
	}
	if req.Scope != "temperature:read" {
		t.Errorf("Scope = %q", req.Scope)
	}
	if req.GrantType != GrantTypeClientCredentials {
		t.Errorf("GrantType = %d, want %d", req.GrantType, GrantTypeClientCredentials)
	}
}

func TestDecodeTokenRequestUnknownKeyIgnored(t *testing.T) {
	// {33:2, 24:"myclient", 5:"sensors", 99:"future-extension"}
	payload := mustHex(t, "a4056773656e736f72731818686d79636c69656e741821021863706675747572652d657874656e73696f6e")
	req, err := DecodeTokenRequest(payload)
	if err != nil {
		t.Fatalf("DecodeTokenRequest with unknown key: %v", err)
	}
	if req.ClientID != "myclient" || req.Audience != "sensors" {
		t.Errorf("unexpected decode: %+v", req)
	}
}

func TestDecodeTokenRequestMalformed(t *testing.T) {
	// array, not a map
	if _, err := DecodeTokenRequest(mustHex(t, "820102")); err == nil {
		t.Error("array payload accepted")
	}
	// {24: 2} — client_id not a text string
	if _, err := DecodeTokenRequest(mustHex(t, "a1181802")); err == nil {
		t.Error("integer client_id accepted")
	}
	// {24: ""} — empty client_id
	if _, err := DecodeTokenRequest(mustHex(t, "a1181860")); err == nil {
		t.Error("empty client_id accepted")
	}
	// {33: [1,2], 24: "myclient"} — grant_type not an integer
	if _, err := DecodeTokenRequest(mustHex(t, "a21818686d79636c69656e741821820102")); err == nil {
		t.Error("array grant_type accepted")
	}
	// {33: 2} — client_id missing
	if _, err := DecodeTokenRequest(mustHex(t, "a1182102")); err == nil {
		t.Error("missing client_id accepted")
	}
}

func TestEncodeTokenResponseGolden(t *testing.T) {
	cnf := EncodeCnfKid([]byte("kidbytes"))
	got := EncodeTokenResponse([]byte("at"), 3600, TokenTypePoP, cnf, AceProfileCoapDTLS)
	want := mustHex(t, "a50142617402190e1008a103486b69646279746573182202182601")
	if !bytes.Equal(got, want) {
		t.Errorf("EncodeTokenResponse() = %x, want %x", got, want)
	}
}

func TestTokenResponseRoundTrip(t *testing.T) {
	cnf := EncodeCnfKid([]byte("thumbprint"))
	payload := EncodeTokenResponse([]byte("opaque-token"), 3600, TokenTypePoP, cnf, AceProfileCoapDTLS)
	res, err := DecodeTokenResponse(payload)
	if err != nil {
		t.Fatalf("DecodeTokenResponse: %v", err)
	}
	if !bytes.Equal(res.AccessToken, []byte("opaque-token")) {
		t.Errorf("AccessToken = %q", res.AccessToken)
	}
	if res.ExpiresIn != 3600 {
		t.Errorf("ExpiresIn = %d", res.ExpiresIn)
	}
	if res.TokenType != TokenTypePoP {
		t.Errorf("TokenType = %d, want %d", res.TokenType, TokenTypePoP)
	}
	if res.AceProfile != AceProfileCoapDTLS {
		t.Errorf("AceProfile = %d, want %d", res.AceProfile, AceProfileCoapDTLS)
	}
	if res.Error != nil {
		t.Errorf("unexpected error member: %+v", res.Error)
	}
	if res.Cnf == nil {
		t.Fatal("cnf member missing")
	}
	if !bytes.Equal(res.Cnf.KID, []byte("thumbprint")) {
		t.Errorf("cnf kid = %q, want %q", res.Cnf.KID, "thumbprint")
	}
}

func TestDecodeTokenResponseErrorPayload(t *testing.T) {
	res, err := DecodeTokenResponse(mustHex(t, "a1181e02")) // {30: 2} invalid_client
	if err != nil {
		t.Fatalf("DecodeTokenResponse: %v", err)
	}
	if res.Error == nil {
		t.Fatal("expected error member")
	}
	if res.Error.Code != ErrInvalidClient {
		t.Errorf("error code = %d, want %d", res.Error.Code, ErrInvalidClient)
	}
	if len(res.AccessToken) != 0 {
		t.Errorf("access token should be empty on error, got %q", res.AccessToken)
	}
}

func TestEncodeErrorGolden(t *testing.T) {
	got := EncodeError(ErrInvalidClient, "")
	if want := mustHex(t, "a1181e02"); !bytes.Equal(got, want) {
		t.Errorf("EncodeError() = %x, want %x", got, want)
	}
	got = EncodeError(ErrInvalidRequest, "bad request")
	if want := mustHex(t, "a2181e01181f6b6261642072657175657374"); !bytes.Equal(got, want) {
		t.Errorf("EncodeError(desc) = %x, want %x", got, want)
	}
}

func TestEncodeASRequestCreationHintsGolden(t *testing.T) {
	got := EncodeASRequestCreationHints("coaps://127.0.0.1:5684/token", "coaps://127.0.0.1:5685", "temperature:read")
	want := mustHex(t, "a30576636f6170733a2f2f3132372e302e302e313a35363835097074656d70657261747572653a7265616410781c636f6170733a2f2f3132372e302e302e313a353638342f746f6b656e")
	if !bytes.Equal(got, want) {
		t.Errorf("EncodeASRequestCreationHints() = %x, want %x", got, want)
	}
}

func TestIntrospectionRequestRoundTrip(t *testing.T) {
	payload := EncodeIntrospectionRequest([]byte("thetoken"), TokenTypePoP)
	if want := mustHex(t, "a20b48746865746f6b656e182102"); !bytes.Equal(payload, want) {
		t.Errorf("EncodeIntrospectionRequest() = %x, want %x", payload, want)
	}
	token, hint, err := DecodeIntrospectionRequest(payload)
	if err != nil {
		t.Fatalf("DecodeIntrospectionRequest: %v", err)
	}
	if !bytes.Equal(token, []byte("thetoken")) || hint != TokenTypePoP {
		t.Errorf("got token=%q hint=%d", token, hint)
	}

	// no hint member
	payload = EncodeIntrospectionRequest([]byte("thetoken"), 0)
	if _, hint, err := DecodeIntrospectionRequest(payload); err != nil || hint != 0 {
		t.Errorf("hint omitted: hint=%d err=%v", hint, err)
	}
}

func TestDecodeIntrospectionRequestMalformed(t *testing.T) {
	if _, _, err := DecodeIntrospectionRequest(mustHex(t, "820102")); err == nil {
		t.Error("non-map payload accepted")
	}
	if _, _, err := DecodeIntrospectionRequest(mustHex(t, "a10b01")); err == nil {
		// {11: 1} — token not a byte string
		t.Error("integer token accepted")
	}
	if _, _, err := DecodeIntrospectionRequest(mustHex(t, "a0")); err == nil {
		t.Error("empty map (missing token) accepted")
	}
}

func TestIntrospectionResponseRoundTrip(t *testing.T) {
	cnf := EncodeCnfKid([]byte("kidbytes"))
	payload := EncodeIntrospectionResponse(true, "temperature:read", "myclient", 2000000000, 1999996400, 0, cnf)
	want := mustHex(t, "a6041a77359400061a773585f008a103486b69646279746573097074656d70657261747572653a726561640af51818686d79636c69656e74")
	if !bytes.Equal(payload, want) {
		t.Errorf("EncodeIntrospectionResponse() = %x, want %x", payload, want)
	}
	res, err := DecodeIntrospectionResponse(payload)
	if err != nil {
		t.Fatalf("DecodeIntrospectionResponse: %v", err)
	}
	if !res.Active || res.Scope != "temperature:read" || res.ClientID != "myclient" {
		t.Errorf("unexpected decode: %+v", res)
	}
	if res.Exp != 2000000000 || res.Iat != 1999996400 || res.Nbf != 0 {
		t.Errorf("timestamps wrong: exp=%d iat=%d nbf=%d", res.Exp, res.Iat, res.Nbf)
	}
	if res.Cnf == nil {
		t.Fatal("cnf missing")
	}
}

func TestEncodeCnfKid(t *testing.T) {
	cnf := EncodeCnfKid([]byte("kidbytes"))
	// cnf renders as { kid: kidbytes } (RFC 8747 section 3.4.1 member key 3)
	encoded := cnf.encode()
	if !bytes.Equal(encoded[CnfKid].([]byte), []byte("kidbytes")) {
		t.Errorf("cnf kid member = %#v", encoded)
	}
	// Golden wire: {8: {3: b"kidbytes"}}
	if got := encodeMap(map[int]any{KeyCnf: cnf.encode()}); !bytes.Equal(got, mustHex(t, "a108a103486b69646279746573")) {
		t.Errorf("cnf golden = %x", got)
	}
}

func TestEncodeCnfCOSEKeyRoundTrip(t *testing.T) {
	// RFC 8747 section 3.2: asymmetric PoP key by value (EC2 P-256).
	key := COSEKey{X: []byte{0xd7, 0xcc, 0x07, 0x2d}, Y: []byte{0xf9, 0x5e, 0x1d, 0x4b}}
	cnf := EncodeCnfCOSEKey(&key)
	req := EncodeTokenRequestWithOptions("myclient", "coaps://rs", "", cnf)
	decoded, err := DecodeTokenRequest(req)
	if err != nil {
		t.Fatalf("DecodeTokenRequest: %v", err)
	}
	if decoded.ReqCnf == nil || decoded.ReqCnf.COSEKey == nil {
		t.Fatalf("req_cnf not decoded: %+v", decoded.ReqCnf)
	}
	if !bytes.Equal(decoded.ReqCnf.COSEKey.X, key.X) || !bytes.Equal(decoded.ReqCnf.COSEKey.Y, key.Y) {
		t.Errorf("PoP key mismatch: x=%x y=%x", decoded.ReqCnf.COSEKey.X, decoded.ReqCnf.COSEKey.Y)
	}
	// Golden wire form of the request carrying req_cnf (key 4).
	if !bytes.Equal(req, mustHex(t, "a404a101a4010220012144d7cc072d2244f95e1d4b056a636f6170733a2f2f72731818686d79636c69656e74182102")) {
		t.Errorf("req_cnf golden = %x", req)
	}
}
