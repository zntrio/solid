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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/sdk/types"
)

// X509ThumbprintS256 computes the RFC 8705 section 3.1 "x5t#S256" value:
// base64url-encoded SHA-256 digest of the DER encoding of the certificate,
// with padding omitted.
func X509ThumbprintS256(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	h := sha256.Sum256(cert.Raw) // cert.Raw is the DER encoding
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// CertificateBound verifies an RFC 8705 section 3 certificate binding:
// a confirmation carrying "x5t#S256" only matches when the request was
// made over mutual TLS and the presented peer certificate thumbprint is
// equal to the confirmation value. An empty confirmation never binds.
func CertificateBound(confirmation *tokenv1.TokenConfirmation, peerCerts []*x509.Certificate) bool {
	if confirmation == nil || confirmation.X5TS256 == "" {
		return false
	}
	if len(peerCerts) == 0 {
		return false
	}
	return types.SecureCompareString(X509ThumbprintS256(peerCerts[0]), confirmation.X5TS256)
}
