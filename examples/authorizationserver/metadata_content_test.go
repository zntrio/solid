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
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMetadataDocumentAdvertisesCIMDSupport asserts the example's discovery
// document advertises client_id_metadata_document_supported, as REQUIRED by
// the OAuth Client ID Metadata Document draft
// (draft-ietf-oauth-client-id-metadata-document, section 5) for authorization
// servers publishing RFC 8414 metadata.
func TestMetadataDocumentAdvertisesCIMDSupport(t *testing.T) {
	md := metadataDocument("https://as.example.org")
	require.True(t, md.ClientIdMetadataDocumentSupported,
		"client_id_metadata_document_supported missing from discovery document")
}

// TestMetadataDocumentAdvertisesAuthorizationDetailsTypes asserts the
// example's discovery document advertises
// authorization_details_types_supported with the registered type
// (RFC 9396 section 10).
func TestMetadataDocumentAdvertisesAuthorizationDetailsTypes(t *testing.T) {
	md := metadataDocument("https://as.example.org")
	require.Equal(t, []string{"payment_initiation"}, md.AuthorizationDetailsTypesSupported,
		"authorization_details_types_supported must advertise the example's registered type")
}

// TestMetadataDocumentAdvertisesClientAttestationAlgorithms asserts the
// example's discovery document advertises
// client_attestation_signing_alg_values_supported and
// client_attestation_pop_signing_alg_values_supported, as REQUIRED by
// draft-ietf-oauth-attestation-based-client-auth-11 (section 8) when the
// Client Attestation PoP JWT mechanism is used.
func TestMetadataDocumentAdvertisesClientAttestationAlgorithms(t *testing.T) {
	md := metadataDocument("https://as.example.org")
	require.Equal(t, []string{"ML-DSA-65"}, md.ClientAttestationSigningAlgValuesSupported,
		"client_attestation_signing_alg_values_supported must advertise ML-DSA-65")
	require.Equal(t, []string{"ML-DSA-65"}, md.ClientAttestationPopSigningAlgValuesSupported,
		"client_attestation_pop_signing_alg_values_supported must advertise ML-DSA-65")
}

// TestMetadataDocumentAdvertisesAcrValuesSupported asserts the example's
// discovery document advertises acr_values_supported with the ACR the demo
// Basic login achieves (RFC 9470 section 7).
func TestMetadataDocumentAdvertisesAcrValuesSupported(t *testing.T) {
	md := metadataDocument("https://as.example.org")
	require.Equal(t, []string{"urn:solid:loa:1fa:any"}, md.AcrValuesSupported,
		"acr_values_supported must advertise the demo login's authentication context class reference")
}
