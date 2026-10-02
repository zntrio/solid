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

// Confirmation method member keys inside a cnf map (RFC 8747 Table 1,
// aligned with RFC 9201 section 2). At most one key-representation
// member may be present; this codec carries exactly one.
const (
	CnfCoseKey          = 1 // COSE_Key (asymmetric PoP key, RFC 8747 section 3.2)
	CnfEncryptedCoseKey = 2 // Encrypted_COSE_Key (symmetric PoP key, RFC 8747 section 3.3)
	CnfKid              = 3 // kid (key reference, RFC 8747 section 3.4.1)
)

// COSE_Key common members (RFC 9050); negative labels are the key-type
// specific parameters. Values below are the EC2 elliptic curve members
// used by the P-256 profile of this SDK.
const (
	CoseKeyKty = 1 // key type
	CoseKeyKid = 2 // key identifier (byte string)
	CoseKeyAlg = 3 // algorithm
	CoseKeyOps = 4 // key operations

	CoseEC2Crv = -1 // curve (1 = P-256, RFC 9050 section 13.1)
	CoseEC2X   = -2 // x coordinate (byte string)
	CoseEC2Y   = -3 // y coordinate (byte string)

	CoseCrvP256 = 1 // P-256 (secp256r1)
)

// KtyEC2 is the COSE key type for EC2 elliptic curve keys.
const KtyEC2 = 2

// Confirmation is a decoded cnf member carrying the PoP key bound to a
// token, per RFC 8747 (Proof-of-Possession Key Semantics for CWTs).
// Exactly one representation is populated:
//   - COSEKey: an asymmetric EC2 P-256 public key (section 3.2)
//   - KID: a key-reference byte string (section 3.4.1); in the
//     certificate-bound coap_dtls profile it carries the RFC 8705
//     x5t#S256 thumbprint value as the binding reference
//
// Encrypted_COSE_Key (section 3.3) is deliberately not carried: the SDK
// only supports asymmetric PoP keys (no HSxxx, repo rule).
type Confirmation struct {
	COSEKey *COSEKey
	KID     []byte
}

// COSEKey is an EC2 public key as defined by RFC 8747 section 3.2 and
// RFC 9050 COSE_Key: kty=EC2, crv=P-256, x and y coordinates; kid is
// optional.
type COSEKey struct {
	Crv int64
	X   []byte
	Y   []byte
	KID []byte
}

// EncodeCnfCOSEKey builds a cnf carrying an asymmetric PoP key by value
// (RFC 8747 section 3.2).
func EncodeCnfCOSEKey(key *COSEKey) *Confirmation {
	return &Confirmation{COSEKey: key}
}

// EncodeCnfKid builds a cnf carrying a PoP key by reference (RFC 8747
// section 3.4.1).
func EncodeCnfKid(kid []byte) *Confirmation {
	return &Confirmation{KID: kid}
}

// encode renders the confirmation as the nested CBOR map value of the
// cnf key (8, RFC 9200 Tables 5/6) or req_cnf key (4, Table 5) in an
// ACE payload.
func (c *Confirmation) encode() map[int]any {
	if c == nil {
		return nil
	}
	if c.COSEKey != nil {
		k := map[int]any{
			CoseKeyKty: KtyEC2,
			CoseEC2Crv: CoseCrvP256,
			CoseEC2X:   c.COSEKey.X,
			CoseEC2Y:   c.COSEKey.Y,
		}
		if len(c.COSEKey.KID) > 0 {
			k[CoseKeyKid] = c.COSEKey.KID
		}
		return map[int]any{CnfCoseKey: k}
	}
	return map[int]any{CnfKid: c.KID}
}

// decodeConfirmation extracts a cnf value decoded by the package decoder
// mode: all maps, nested included, are map[int]any. Unknown members are
// ignored per RFC 8747 section 3.1 (confirmation members not understood
// MUST be ignored).
func decodeConfirmation(v any) (*Confirmation, bool) {
	cnf, ok := v.(map[int]any)
	if !ok {
		return nil, false
	}
	if raw, ok := cnf[CnfCoseKey].(map[int]any); ok {
		res := &Confirmation{COSEKey: &COSEKey{Crv: CoseCrvP256}}
		if x, ok := raw[CoseEC2X].([]byte); ok {
			res.COSEKey.X = x
		}
		if y, ok := raw[CoseEC2Y].([]byte); ok {
			res.COSEKey.Y = y
		}
		if kid, ok := raw[CoseKeyKid].([]byte); ok {
			res.COSEKey.KID = kid
		}
		return res, true
	}
	if kid, ok := cnf[CnfKid].([]byte); ok {
		return &Confirmation{KID: kid}, true
	}
	return nil, false
}
