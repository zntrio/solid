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

package cimd

import (
	"encoding/json"
	"errors"
	"fmt"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/oidc"
)

// -----------------------------------------------------------------------------

// Document is the wire representation of a Client ID Metadata Document
// (draft-ietf-oauth-client-id-metadata-document, section 4). Property names
// are the RFC 7591 client-metadata JSON names.
type Document struct {
	ClientID                           string            `json:"client_id"`
	RedirectUris                       []string          `json:"redirect_uris"`
	TokenEndpointAuthMethod            string            `json:"token_endpoint_auth_method"`
	GrantTypes                         []string          `json:"grant_types"`
	ResponseTypes                      []string          `json:"response_types"`
	ClientName                         string            `json:"client_name"`
	ClientNameI18n                     map[string]string `json:"client_name_i18n"`
	ClientURI                          string            `json:"client_uri"`
	LogoURI                            string            `json:"logo_uri"`
	LogoURII18n                        map[string]string `json:"logo_uri_i18n"`
	Scope                              string            `json:"scope"`
	Contacts                           []string          `json:"contacts"`
	TosURI                             string            `json:"tos_uri"`
	TosURII18n                         map[string]string `json:"tos_uri_i18n"`
	PolicyURI                          string            `json:"policy_uri"`
	PolicyURII18n                      map[string]string `json:"policy_uri_i18n"`
	JwksURI                            string            `json:"jwks_uri"`
	Jwks                               json.RawMessage   `json:"jwks"`
	SoftwareID                         string            `json:"software_id"`
	SoftwareVersion                    string            `json:"software_version"`
	SoftwareStatement                  json.RawMessage   `json:"software_statement"`
	SubjectType                        string            `json:"subject_type"`
	SectorIdentifier                   string            `json:"sector_identifier"`
	ResponseModes                      []string          `json:"response_modes"`
	RequirePushedAuthorizationRequests bool              `json:"require_pushed_authorization_requests"`
	RequireSignedRequestObject         bool              `json:"require_signed_request_object"`
	DpopBoundAccessTokens              bool              `json:"dpop_bound_access_tokens"`
	// RFC 7662 section 2.1: client identifiers (including Client
	// Identifier URLs, draft-ietf-oauth-client-id-metadata-document
	// section 3) authorized to introspect this client's tokens.
	AuthorizedIntrospectionClients []string `json:"authorized_introspection_clients"`
	// draft-ietf-oauth-spiffe-client-auth-02 section 5.1.
	SpiffeID             string `json:"spiffe_id"`
	SpiffeBundleEndpoint string `json:"spiffe_bundle_endpoint"`
	// Parsed so the resolver can REJECT documents containing them (section 4.1).
	ClientSecret          string `json:"client_secret"`
	ClientSecretExpiresAt *int64 `json:"client_secret_expires_at"`
}

// DecodeDocument parses a raw Client ID Metadata Document JSON body.
func DecodeDocument(b []byte) (*Document, error) {
	var d Document
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("cimd: unable to decode document: %w", err)
	}
	return &d, nil
}

// -----------------------------------------------------------------------------

// ToClient maps the document to an internal Client representation, enforcing
// the credential and key material restrictions of section 4.1:
//
//   - token_endpoint_auth_method MUST NOT be a shared-secret method
//     (client_secret_post, client_secret_basic, client_secret_jwt)
//   - client_secret and client_secret_expires_at MUST NOT be used
//   - the jwks property MUST NOT contain private key material
//
// Defense posture: jwks_uri is carried on the resulting Client but is never
// dereferenced by the resolver (nothing in the AS dereferences client JWKs
// URIs today), so a CIMD client declaring only jwks_uri fails client
// authentication with "client jwks is nil". software_statement,
// software_id and software_version are dropped: the Client type has no
// corresponding fields and no software-statement verifier exists.
func (d *Document) ToClient() (*clientv1.Client, error) {
	if d == nil {
		return nil, errors.New("cimd: document is nil")
	}

	// Shared-secret client authentication is impossible without prior
	// registration (section 4.1).
	switch d.TokenEndpointAuthMethod {
	case oidc.AuthMethodClientSecretPost,
		oidc.AuthMethodClientSecretBasic,
		oidc.AuthMethodClientSecretJWT:
		return nil, fmt.Errorf("cimd: token_endpoint_auth_method %q is forbidden in client id metadata documents", d.TokenEndpointAuthMethod)
	}

	// No shared secret can be established (section 4.1).
	if d.ClientSecret != "" || d.ClientSecretExpiresAt != nil {
		return nil, errors.New("cimd: client_secret and client_secret_expires_at are forbidden in client id metadata documents")
	}

	// Private key material MUST NOT be published in the document (section 4.1).
	jwks := []byte(d.Jwks)
	if len(jwks) > 0 {
		if err := rejectPrivateJWKMaterial(jwks); err != nil {
			return nil, err
		}
	}

	// Confidential when the client authenticates with key material, public
	// otherwise.
	clientType := clientv1.ClientType_CLIENT_TYPE_PUBLIC
	if d.TokenEndpointAuthMethod != "" && d.TokenEndpointAuthMethod != oidc.AuthMethodNone && len(jwks) > 0 {
		clientType = clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL
	}

	return &clientv1.Client{
		ClientId:                           d.ClientID,
		ClientType:                         clientType,
		RedirectUris:                       d.RedirectUris,
		ResponseTypes:                      d.ResponseTypes,
		ResponseModes:                      d.ResponseModes,
		GrantTypes:                         d.GrantTypes,
		Contacts:                           d.Contacts,
		ClientName:                         d.ClientName,
		LogoUri:                            d.LogoURI,
		ClientUri:                          d.ClientURI,
		PolicyUri:                          d.PolicyURI,
		TosUri:                             d.TosURI,
		JwksUri:                            d.JwksURI,
		Jwks:                               jwks,
		SubjectType:                        d.SubjectType,
		SectorIdentifier:                   d.SectorIdentifier,
		TokenEndpointAuthMethod:            d.TokenEndpointAuthMethod,
		DpopBoundAccessTokens:              d.DpopBoundAccessTokens,
		AuthorizedIntrospectionClients:     d.AuthorizedIntrospectionClients,
		SpiffeId:                           d.SpiffeID,
		RequirePushedAuthorizationRequests: d.RequirePushedAuthorizationRequests,
		RequireSignedRequestObject:         d.RequireSignedRequestObject,
		SpiffeBundleEndpoint:               d.SpiffeBundleEndpoint,
	}, nil
}

// rawJWK carries the RFC 7517 JWK fields needed to detect private or
// symmetric key material.
type rawJWK struct {
	Kty string          `json:"kty"`
	K   json.RawMessage `json:"k"`
	D   json.RawMessage `json:"d"`
	P   json.RawMessage `json:"p"`
	Q   json.RawMessage `json:"q"`
	Dp  json.RawMessage `json:"dp"`
	Dq  json.RawMessage `json:"dq"`
	Qi  json.RawMessage `json:"qi"`
}

// rejectPrivateJWKMaterial fails when the JWK Set contains private key
// parameters: "d" for EC, OKP, and AKP (ML-DSA, draft-ietf-cose-dilithium)
// keys, RSA private parameters, or an octet key "k" (which is secret
// material by definition).
func rejectPrivateJWKMaterial(jwks []byte) error {
	var keySet struct {
		Keys []rawJWK `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &keySet); err != nil {
		return fmt.Errorf("cimd: unable to decode jwks: %w", err)
	}
	for i := range keySet.Keys {
		k := &keySet.Keys[i]
		switch k.Kty {
		case "EC", "OKP", "AKP":
			if len(k.D) > 0 {
				return fmt.Errorf("cimd: jwks key %d is a private %s key", i, k.Kty)
			}
		case "RSA":
			if len(k.D) > 0 || len(k.P) > 0 || len(k.Q) > 0 ||
				len(k.Dp) > 0 || len(k.Dq) > 0 || len(k.Qi) > 0 {
				return fmt.Errorf("cimd: jwks key %d is a private RSA key", i)
			}
		case "oct":
			return fmt.Errorf("cimd: jwks key %d is a symmetric key", i)
		default:
			return fmt.Errorf("cimd: jwks key %d has unsupported kty %q", i, k.Kty)
		}
	}
	return nil
}
