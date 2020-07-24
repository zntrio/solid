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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/imdario/mergo"
	"github.com/square/go-jose/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/api/oidc"
	"zntr.io/solid/pkg/authorizationserver"
	"zntr.io/solid/pkg/rfcerrors"
)

// DCR handles dynamic client registration.
func DCR(as authorizationserver.AuthorizationServer) http.Handler {

	const bodyLimiterSize = 5 << 20 // 5 Mb

	type request struct {
		ApplicationType         string              `json:"application_type,omitempty"`
		RedirectURIs            []string            `json:"redirect_uris,omitempty"`
		TokenEndpointAuthMethod string              `json:"token_endpoint_auth_method,omitempty"`
		GrantTypes              []string            `json:"grant_types,omitempty"`
		ResponseTypes           []string            `json:"response_types,omitempty"`
		ClientName              string              `json:"client_name,omitempty"`
		ClientURI               string              `json:"client_uri,omitempty"`
		LogoURI                 string              `json:"logo_uri,omitempty"`
		Scope                   string              `json:"scope,omitempty"`
		Contacts                []string            `json:"contacts,omitempty"`
		TosURI                  string              `json:"tos_uri,omitempty"`
		PolicyURI               string              `json:"policy_uri,omitempty"`
		JwksURI                 string              `json:"jwks_uri,omitempty"`
		JWKS                    *jose.JSONWebKeySet `json:"jwks,omitempty"`
		SoftwareID              string              `json:"software_id,omitempty"`
		SoftwareVersion         string              `json:"software_version,omitempty"`
		SoftwareStatement       string              `json:"software_statement,omitempty"`
	}

	toClientMeta := func(r *request) (*corev1.ClientMeta, error) {
		// Copy array
		meta := &corev1.ClientMeta{
			Contacts:      r.Contacts,
			GrantTypes:    r.GrantTypes,
			RedirectUris:  r.RedirectURIs,
			ResponseTypes: r.ResponseTypes,
		}

		// Process optional fields
		if r.ApplicationType != "" {
			meta.ApplicationType = &wrapperspb.StringValue{Value: r.ApplicationType}
		}
		if r.ClientName != "" {
			meta.ClientName = &wrapperspb.StringValue{Value: r.ClientName}
		}
		if r.ClientURI != "" {
			meta.ClientUri = &wrapperspb.StringValue{Value: r.ClientURI}
		}
		if r.JwksURI != "" {
			meta.JwkUri = &wrapperspb.StringValue{Value: r.JwksURI}
		}
		if r.LogoURI != "" {
			meta.LogoUri = &wrapperspb.StringValue{Value: r.LogoURI}
		}
		if r.PolicyURI != "" {
			meta.PolicyUri = &wrapperspb.StringValue{Value: r.PolicyURI}
		}
		if r.Scope != "" {
			meta.Scope = &wrapperspb.StringValue{Value: r.Scope}
		}
		if r.SoftwareID != "" {
			meta.SoftwareId = &wrapperspb.StringValue{Value: r.SoftwareID}
		}
		if r.SoftwareVersion != "" {
			meta.SoftwareVersion = &wrapperspb.StringValue{Value: r.SoftwareVersion}
		}
		if r.TokenEndpointAuthMethod != "" {
			meta.TokenEndpointAuthMethod = &wrapperspb.StringValue{Value: r.TokenEndpointAuthMethod}
		}
		if r.TosURI != "" {
			meta.TosUri = &wrapperspb.StringValue{Value: r.TosURI}
		}

		// JWKS
		if r.JWKS != nil {
			var buf bytes.Buffer
			if err := json.NewEncoder(&buf).Encode(r.JWKS); err != nil {
				return nil, fmt.Errorf("unable to encode JWK: %w", err)
			}

			// Set JWKS
			meta.Jwks = &wrappers.BytesValue{Value: buf.Bytes()}
		}

		// Merge with default values
		if err := mergo.Merge(meta, corev1.ClientMeta{
			GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
			ResponseTypes: []string{oidc.ResponseTypeCode},
			Scope:         &wrapperspb.StringValue{Value: "openid"},
		}); err != nil {
			return nil, fmt.Errorf("unable to merge with default values: %w", err)
		}

		// No error
		return meta, nil
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only POST verb
		if r.Method != http.MethodPost {
			withError(w, r, http.StatusMethodNotAllowed, rfcerrors.InvalidRequest().Build())
			return
		}

		// Decode body
		var reqw request
		if err := json.NewDecoder(io.LimitReader(r.Body, bodyLimiterSize)).Decode(&reqw); err != nil {
			log.Printf("unable to decode json request: %w", err)
			withError(w, r, http.StatusBadRequest, rfcerrors.InvalidRequest().Build())
			return
		}

		// Create request
		meta, err := toClientMeta(&reqw)
		if err != nil {
			log.Printf("unable to prepare meta: %w", err)
			withError(w, r, http.StatusBadRequest, rfcerrors.InvalidClientMetadata().Build())
			return
		}

		// Delegate message to reactor
		res, err := as.Do(r.Context(), &corev1.ClientRegistrationRequest{
			Metadata: meta,
		})
		dcrRes, ok := res.(*corev1.ClientRegistrationResponse)
		if !ok {
			withJSON(w, r, http.StatusInternalServerError, rfcerrors.ServerError().Build())
			return
		}
		if err != nil {
			log.Printf("unable to process registration request: %w", err)
			withError(w, r, http.StatusBadRequest, dcrRes.Error)
			return
		}

		// Send json reponse
		withJSON(w, r, http.StatusCreated, dcrRes.Client)
	})
}
