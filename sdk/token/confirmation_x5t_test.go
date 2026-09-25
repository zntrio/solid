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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
)

// rfc8705AppendixACertPEM is the client certificate of RFC 8705,
// Appendix A, Figure 6.
const rfc8705AppendixACertPEM = `-----BEGIN CERTIFICATE-----
MIIBBjCBrAIBAjAKBggqhkjOPQQDAjAPMQ0wCwYDVQQDDARtdGxzMB4XDTE4MTAx
ODEyMzcwOVoXDTIyMDUwMjEyMzcwOVowDzENMAsGA1UEAwwEbXRsczBZMBMGByqG
SM49AgEGCCqGSM49AwEHA0IABNcnyxwqV6hY8QnhxxzFQ03C7HKW9OylMbnQZjjJ
/Au08/coZwxS7LfA4vOLS9WuneIXhbGGWvsDSb0tH6IxLm8wCgYIKoZIzj0EAwID
SQAwRgIhAP0RC1E+vwJD/D1AGHGzuri+hlV/PpQEKTWUVeORWz83AiEA5x2eXZOV
bUlJSGQgjwD5vaUaKlLR50Q2DmFfQj1L+SY=
-----END CERTIFICATE-----`

// rfc8705AppendixAThumbprint is the "x5t#S256" value of RFC 8705,
// Appendix A, Figure 5, for the certificate of Figure 6.
const rfc8705AppendixAThumbprint = "A4DtL2JmUMhAsvJj5tKyn64SqzmuXbMrJa0n761y5v0"

func TestX509ThumbprintS256_RFC8705AppendixA(t *testing.T) {
	block, _ := pem.Decode([]byte(rfc8705AppendixACertPEM))
	require.NotNil(t, block, "fixture PEM must decode")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	// RFC 8705 Appendix A: Figure 6 certificate must yield the
	// Figure 5 thumbprint.
	assert.Equal(t, rfc8705AppendixAThumbprint, X509ThumbprintS256(cert))
}

func TestX509ThumbprintS256_Nil(t *testing.T) {
	assert.Empty(t, X509ThumbprintS256(nil))
}

func TestCertificateBound(t *testing.T) {
	// Build a fresh certificate to bind.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "client.example.org"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	otherDER, err := x509.CreateCertificate(rand.Reader, template, template, &other.PublicKey, other)
	require.NoError(t, err)
	otherCert, err := x509.ParseCertificate(otherDER)
	require.NoError(t, err)

	thumbprint := X509ThumbprintS256(cert)
	confirmation := &tokenv1.TokenConfirmation{X5TS256: thumbprint}

	assert.True(t, CertificateBound(confirmation, []*x509.Certificate{cert}))
	assert.False(t, CertificateBound(confirmation, []*x509.Certificate{otherCert}), "foreign certificate must not match")
	assert.False(t, CertificateBound(confirmation, nil), "no peer certificate must fail closed")
	assert.False(t, CertificateBound(&tokenv1.TokenConfirmation{X5TS256: ""}, []*x509.Certificate{cert}), "empty binding never binds")
	assert.False(t, CertificateBound(nil, []*x509.Certificate{cert}), "nil confirmation never binds")
	assert.False(t, CertificateBound(&tokenv1.TokenConfirmation{Jkt: "abc"}, []*x509.Certificate{cert}), "jkt-only confirmation is not certificate-bound")
}
