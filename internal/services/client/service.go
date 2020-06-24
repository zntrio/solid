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

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/square/go-jose/v3"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/api/oidc"
	"zntr.io/solid/internal/services"
	"zntr.io/solid/pkg/rfcerrors"
	"zntr.io/solid/pkg/storage"
	"zntr.io/solid/pkg/types"
)

type service struct {
	clients       storage.ClientWriter
	valueProvider ValueProvider
}

// New build and returns a client service implementation.
func New(clients storage.ClientWriter, valueProvider ValueProvider) services.Client {
	return &service{
		clients:       clients,
		valueProvider: valueProvider,
	}
}

// -----------------------------------------------------------------------------

func (s *service) Register(ctx context.Context, req *corev1.ClientRegistrationRequest) (*corev1.ClientRegistrationResponse, error) {
	res := &corev1.ClientRegistrationResponse{}

	// Check req nullity
	if req == nil {
		res.Error = rfcerrors.InvalidRequest("")
		return res, fmt.Errorf("unable to process nil request")
	}

	// Validate authorization request
	publicErr, err := s.validateRegistration(ctx, req)
	if err != nil {
		res.Error = publicErr
		return res, err
	}

	// Create client
	c := &corev1.Client{
		Contacts:      req.Metadata.Contacts,
		GrantTypes:    req.Metadata.GrantTypes,
		ResponseTypes: req.Metadata.ResponseTypes,
		RedirectUris:  req.Metadata.RedirectUris,
		Jwks:          req.Metadata.Jwks,
	}

	// Assign attributes
	if req.Metadata.ClientName != nil {
		c.ClientName = req.Metadata.ClientName.Value
	}
	if req.Metadata.ClientUri != nil {
		c.ClientUri = req.Metadata.ClientUri.Value
	}
	if req.Metadata.JwkUri != nil {
		c.JwksUri = req.Metadata.JwkUri.Value
	}
	if req.Metadata.PolicyUri != nil {
		c.PolicyUri = req.Metadata.PolicyUri.Value
	}
	if req.Metadata.TosUri != nil {
		c.TosUri = req.Metadata.TosUri.Value
	}
	if req.Metadata.LogoUri != nil {
		c.LogoUri = req.Metadata.LogoUri.Value
	}

	// Save client in persistence
	c.ClientId, err = s.clients.Register(ctx, c)
	if err != nil {
		res.Error = rfcerrors.ServerError("")
		return res, fmt.Errorf("unable to register client in persistence: %w", err)
	}

	// Assign client
	res.Client = c

	// No error
	return res, nil
}

// -----------------------------------------------------------------------------

func (s *service) validateRegistration(ctx context.Context, req *corev1.ClientRegistrationRequest) (*corev1.Error, error) {
	// Check nil
	if req == nil {
		return rfcerrors.InvalidRequest(""), fmt.Errorf("unable to process nil request")
	}
	if req.Metadata == nil {
		return rfcerrors.InvalidRequest(""), fmt.Errorf("unable to process nil metadata")
	}

	// Token endpoint auth methods
	if req.Metadata.TokenEndpointAuthMethod != nil {
		if !types.StringArray(s.valueProvider.TokenEndpointAuthMethodsSupported()).Contains(req.Metadata.TokenEndpointAuthMethod.Value) {
			return rfcerrors.InvalidRequest(""), fmt.Errorf("token_endpoint_auth_method is invalid: '%s'", req.Metadata.TokenEndpointAuthMethod.Value)
		}
	} else {
		return rfcerrors.InvalidRequest(""), fmt.Errorf("token_endpoint_auth_method should not be empty")
	}

	// Response Types
	if len(req.Metadata.ResponseTypes) > 0 {
		if !types.StringArray(s.valueProvider.ResponseTypesSupported()).HasAll(req.Metadata.ResponseTypes...) {
			return rfcerrors.InvalidRequest(""), fmt.Errorf("a response_types element is invalid: '%s'", req.Metadata.ResponseTypes)
		}
	} else {
		return rfcerrors.InvalidRequest(""), fmt.Errorf("response_types should not be empty")
	}

	// Grant types
	if len(req.Metadata.GrantTypes) > 0 {
		grantTypes := types.StringArray(req.Metadata.GrantTypes)

		// Supported grant_types
		if !types.StringArray(s.valueProvider.GrantTypesSupported()).HasAll(req.Metadata.GrantTypes...) {
			return rfcerrors.InvalidRequest(""), fmt.Errorf("a grant_types element is invalid: '%s'", req.Metadata.GrantTypes)
		}

		// Code must be specified with `authorization_code` grant type
		if grantTypes.Contains(oidc.GrantTypeAuthorizationCode) {
			// Response_types should contain `code`
			if !types.StringArray(req.Metadata.ResponseTypes).Contains(oidc.ResponseTypeCode) {
				return rfcerrors.InvalidRequest(""), fmt.Errorf("response_types should contain `code`")
			}

			// Validate redirect_uris
			if len(req.Metadata.RedirectUris) == 0 {
				return rfcerrors.InvalidRequest(""), fmt.Errorf("redirect_uris should not be empty for `authorization_code` grant type")
			}

			// Check redirect uris syntax
			for i := range req.Metadata.RedirectUris {
				// Prepare redirection uri
				_, err := url.ParseRequestURI(req.Metadata.RedirectUris[i])
				if err != nil {
					return rfcerrors.InvalidRedirectURI(), fmt.Errorf("redirect_uri has an invalid syntax: %w", err)
				}
			}

		}
	} else {
		return rfcerrors.InvalidRequest(""), fmt.Errorf("grant_types should not be empty")
	}

	// JWKS
	if len(req.Metadata.Jwks) > 0 {
		// Try to decode JWKS
		var jwks jose.JSONWebKeySet
		if err := json.NewDecoder(bytes.NewBuffer(req.Metadata.Jwks)).Decode(&jwks); err != nil {
			return rfcerrors.InvalidRequest(""), fmt.Errorf("jwks is invalid: %w", err)
		}

		// JWKS should contain keys
		if len(jwks.Keys) == 0 {
			return rfcerrors.InvalidRequest(""), fmt.Errorf("jwks is empty")
		}
	} else {
		// Check auth method
		if req.Metadata.TokenEndpointAuthMethod.Value == oidc.AuthMethodPrivateKeyJWT {
			return rfcerrors.InvalidRequest(""), fmt.Errorf("jwks is mandatory for `private_key_jwt` authentication")
		}
	}

	// Scope
	if req.Metadata.Scope != nil {
		// scope should contain valid scopes
		if !types.StringArray(s.valueProvider.Scopes()).HasAll(strings.Split(req.Metadata.Scope.Value, " ")...) {
			return rfcerrors.InvalidRequest(""), fmt.Errorf("scope contains unsupported scopes")
		}
	}

	// No error
	return nil, nil
}
