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

package clientauthentication

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	gomock "go.uber.org/mock/gomock"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/server/storage"
	storagemock "zntr.io/solid/server/storage/mock"
)

// witAttestation is a decodable (unverified) attestation JWT whose typ header
// selects the SPIFFE WIT processor.
const witAttestation = "eyJ0eXAiOiJ3aXQrand0IiwiYWxnIjoiRVMyNTYifQ." +
	"eyJpc3MiOiJjbGllbnQifQ." +
	"c2lnbmF0dXJl"

// plainAttestation carries no typ header: the client-attestation processor
// applies.
const plainAttestation = "eyJhbGciOiJFUzI1NiJ9." +
	"eyJpc3MiOiJjbGllbnQifQ." +
	"c2lnbmF0dXJl"

var errStorageGet = errors.New("storage error")

func TestProcessorSetSelect(t *testing.T) {
	tlsRegistered := &clientv1.Client{
		ClientId:                "tls-client",
		TokenEndpointAuthMethod: oidc.AuthMethodTLSClientAuth,
	}

	tests := []struct {
		name string
		// credential inputs
		authMethod     string
		attestation    string
		attestationPop string
		tlsClientCert  string
		clientIDParam  string
		storageClient  *clientv1.Client
		storageErr     error
		wantMethod     string
		wantProcessor  string
		wantOK         bool
	}{
		{
			name:          "spiffe jwt assertion type",
			authMethod:    oidc.AssertionTypeJWTSPIFFE,
			wantMethod:    oidc.AuthMethodSPIFFEJWT,
			wantProcessor: "SPIFFEJWT",
			wantOK:        true,
		},
		{
			name:          "jwt-bearer assertion type",
			authMethod:    oidc.AssertionTypeJWTBearer,
			wantMethod:    oidc.AuthMethodPrivateKeyJWT,
			wantProcessor: "PrivateKeyJWT",
			wantOK:        true,
		},
		{
			name:           "attestation pair, wit+jwt typ",
			attestation:    witAttestation,
			attestationPop: "pop",
			wantMethod:     oidc.AuthMethodSPIFFEWIT,
			wantProcessor:  "SPIFFEWIT",
			wantOK:         true,
		},
		{
			name:           "attestation pair, plain attestation",
			attestation:    plainAttestation,
			attestationPop: "pop",
			wantMethod:     oidc.AuthMethodClientAttestationJWT,
			wantProcessor:  "ClientAttestation",
			wantOK:         true,
		},
		{
			name:        "attestation without pop header",
			attestation: plainAttestation,
			wantOK:      false,
		},
		{
			name:       "unknown assertion type",
			authMethod: "urn:example:unknown",
			wantOK:     false,
		},
		{
			name:   "no inputs",
			wantOK: false,
		},
		{
			name:          "tls cert, client registered for tls_client_auth",
			tlsClientCert: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
			clientIDParam: "tls-client",
			storageClient: tlsRegistered,
			wantMethod:    oidc.AuthMethodTLSClientAuth,
			wantProcessor: "TLSClientAuth",
			wantOK:        true,
		},
		{
			name:          "tls cert, client not registered for tls_client_auth",
			tlsClientCert: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
			clientIDParam: "spiffe-client",
			storageClient: &clientv1.Client{
				ClientId:                "spiffe-client",
				TokenEndpointAuthMethod: oidc.AuthMethodSPIFFEX509,
			},
			wantMethod:    oidc.AuthMethodSPIFFEX509,
			wantProcessor: "SPIFFEX509",
			wantOK:        true,
		},
		{
			name:          "tls cert, no client_id parameter",
			tlsClientCert: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
			wantMethod:    oidc.AuthMethodSPIFFEX509,
			wantProcessor: "SPIFFEX509",
			wantOK:        true,
		},
		{
			name:          "tls cert, storage failure",
			tlsClientCert: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
			clientIDParam: "unknown",
			storageErr:    errStorageGet,
			// Fail-closed: an infrastructure error must not silently
			// re-route the request to the SPIFFE X.509-SVID path.
			wantMethod:    "",
			wantProcessor: "",
			wantOK:        false,
		},
		{
			name:          "tls cert, unknown client",
			tlsClientCert: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
			clientIDParam: "unknown",
			storageErr:    storage.ErrNotFound,
			wantMethod:    oidc.AuthMethodSPIFFEX509,
			wantProcessor: "SPIFFEX509",
			wantOK:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)

			ctrl := gomock.NewController(t)
			clients := storagemock.NewMockClientReader(ctrl)
			if tt.storageClient != nil || tt.storageErr != nil {
				clients.EXPECT().Get(gomock.Any(), gomock.Any()).
					Return(tt.storageClient, tt.storageErr).AnyTimes()
			}

			set := NewProcessorSet(clients, "https://issuer.example.com", []string{"ES256"}, nil, nil)
			proc, method, ok := set.Select(context.Background(), clients,
				tt.authMethod, tt.attestation, tt.attestationPop, tt.tlsClientCert, tt.clientIDParam)

			r.Equal(tt.wantOK, ok)
			if !tt.wantOK {
				r.Nil(proc)
				r.Empty(method)
				return
			}
			r.Equal(tt.wantMethod, method)
			r.Equal(tt.wantProcessor, processorName(set, proc))
		})
	}
}

// processorName maps a processor back to its set field name for assertions.
func processorName(set ProcessorSet, proc AuthenticationProcessor) string {
	switch proc {
	case set.PrivateKeyJWT:
		return "PrivateKeyJWT"
	case set.ClientAttestation:
		return "ClientAttestation"
	case set.SPIFFEJWT:
		return "SPIFFEJWT"
	case set.SPIFFEWIT:
		return "SPIFFEWIT"
	case set.SPIFFEX509:
		return "SPIFFEX509"
	case set.TLSClientAuth:
		return "TLSClientAuth"
	default:
		return "unknown"
	}
}
