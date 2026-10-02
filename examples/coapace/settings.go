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

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"time"
)

// settings carries the ephemeral PKI material shared by the three roles
// of the demo (AS, RS, client): one CA and one ES256 P-256 leaf key pair
// per role, generated at boot with crypto/rand. Nothing is persisted.
type settings struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPool *x509.CertPool
	asCert tlsCertificate
	rsCert tlsCertificate
	client tlsCertificate
}

// tlsCertificate bundles a leaf certificate with its private key.
type tlsCertificate struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// newSettings generates the ephemeral demo PKI: a self-signed CA and
// three leaf certificates (AS, RS, client), all ES256 on P-256 — the
// CoAP sample algorithm posture (no RSA, repo rule).
func newSettings() (*settings, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "coap-ace-demo-ca"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)
	asCert, err := newLeaf(caCert, caKey, &pkix.Name{CommonName: "coap-ace-as"}, []net.IP{net.ParseIP("127.0.0.1")}, "")
	if err != nil {
		return nil, err
	}
	rsCert, err := newLeaf(caCert, caKey, &pkix.Name{CommonName: "coap-ace-rs"}, []net.IP{net.ParseIP("127.0.0.1")}, rsSanURI)
	if err != nil {
		return nil, err
	}

	clientCert, err := newLeaf(caCert, caKey, &pkix.Name{CommonName: "coap-ace-client"}, nil, clientSanURI)
	if err != nil {
		return nil, err
	}

	return &settings{
		caCert: caCert,
		caKey:  caKey,
		caPool: caPool,
		asCert: asCert,
		rsCert: rsCert,
		client: clientCert,
	}, nil
}

// newLeaf issues an ES256 P-256 leaf certificate under the demo CA.
func newLeaf(ca *x509.Certificate, caKey *ecdsa.PrivateKey, subject *pkix.Name, ips []net.IP, sanURI string) (tlsCertificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tlsCertificate{}, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      *subject,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		IPAddresses:  ips,
	}
	if sanURI != "" {
		u, parseErr := url.Parse(sanURI)
		if parseErr != nil {
			return tlsCertificate{}, parseErr
		}
		template.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		return tlsCertificate{}, err
	}
	cert, parseErr := x509.ParseCertificate(der)
	if parseErr != nil {
		return tlsCertificate{}, parseErr
	}
	return tlsCertificate{cert: cert, key: key}, nil
}

// randomSerial returns a random positive certificate serial number.
func randomSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		panic(err)
	}
	return n
}
