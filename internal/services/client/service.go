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

	"google.golang.org/protobuf/types/known/wrapperspb"
	"gopkg.in/square/go-jose.v2"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/api/oidc"
	"zntr.io/solid/internal/services"
	"zntr.io/solid/pkg/sdk/rfcerrors"
	"zntr.io/solid/pkg/sdk/types"
	"zntr.io/solid/pkg/server/profile"
	"zntr.io/solid/pkg/server/storage"
)

type service struct {
	clients       storage.ClientWriter
	serverProfile profile.Server
}

// New build and returns a client service implementation.
func New(clients storage.ClientWriter, serverProfile profile.Server) services.Client {
	return &service{
		clients:       clients,
		serverProfile: serverProfile,
	}
}

// -----------------------------------------------------------------------------

func (s *service) Register(ctx context.Context, req *corev1.ClientRegistrationRequest) (*corev1.ClientRegistrationResponse, error) {
	res := &corev1.ClientRegistrationResponse{}

	// Check req nullity
	if req == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process nil request")
	}
	if req.Metadata == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process nil metadata")
	}

	// Check application_type value
	if req.Metadata.ApplicationType == nil {
		// Default to web
		req.Metadata.ApplicationType = &wrapperspb.StringValue{Value: oidc.ApplicationTypeServerSideWeb}
	}

	// Validate authorization request
	publicErr, err := s.validateRegistration(ctx, req)
	if err != nil {
		res.Error = publicErr
		return res, err
	}

	// Create client
	c := &corev1.Client{
		ApplicationType:         req.Metadata.ApplicationType.Value,
		TokenEndpointAuthMethod: req.Metadata.TokenEndpointAuthMethod.Value,
		Contacts:                req.Metadata.Contacts,
		GrantTypes:              req.Metadata.GrantTypes,
		ResponseTypes:           req.Metadata.ResponseTypes,
		RedirectUris:            req.Metadata.RedirectUris,
	}

	// Assign attributes
	if err := s.applyRegistrationRequest(req, c, res); err != nil {
		return res, err
	}

	// Save client in persistence
	c.ClientId, err = s.clients.Register(ctx, c)
	if err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to register client in persistence: %w", err)
	}

	// Assign client
	res.Client = c

	// No error
	return res, nil
}

// -----------------------------------------------------------------------------

func (s *service) applyRegistrationRequest(req *corev1.ClientRegistrationRequest, c *corev1.Client, res *corev1.ClientRegistrationResponse) error {
	// Check arguments
	if req == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return fmt.Errorf("unable to process nil request")
	}
	if c == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return fmt.Errorf("unable to process nil request")
	}
	if res == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return fmt.Errorf("unable to process nil response")
	}

	if req.Metadata.ClientName != nil {
		// Assign to client
		c.ClientName = req.Metadata.ClientName.Value
	}
	if req.Metadata.ClientUri != nil {
		// Assign to client
		c.ClientUri = req.Metadata.ClientUri.Value
	}
	if req.Metadata.JwkUri != nil {
		// Assign to client
		c.JwksUri = req.Metadata.JwkUri.Value
	}
	if req.Metadata.PolicyUri != nil {
		// Assign to client
		c.PolicyUri = req.Metadata.PolicyUri.Value
	}
	if req.Metadata.TosUri != nil {
		// Assign to client
		c.TosUri = req.Metadata.TosUri.Value
	}
	if req.Metadata.LogoUri != nil {
		// Assign to client
		c.LogoUri = req.Metadata.LogoUri.Value
	}

	// JWKS
	if req.Metadata.Jwks != nil {
		// Assign to client
		c.Jwks = req.Metadata.Jwks.Value
	}

	// Subject type
	if req.Metadata.SubjectType != nil {
		subjectType := req.Metadata.SubjectType.Value

		// Check enumeration
		switch subjectType {
		case oidc.SubjectTypePublic, oidc.SubjectTypePairwise:
			c.SubjectType = subjectType
		default:
			res.Error = rfcerrors.InvalidClientMetadata().Build()
			return fmt.Errorf("subject_type contains invalid value")
		}

		// Sector identifier is mandatory with pairwise subject type
		if subjectType == oidc.SubjectTypePairwise {
			if req.Metadata.SectorIdentifier != nil {
				// Assign to client
				c.SectorIdentifier = req.Metadata.SectorIdentifier.Value
			} else {
				res.Error = rfcerrors.InvalidClientMetadata().Build()
				return fmt.Errorf("sector_identifier is mandatory with subject_type")
			}
		}
	} else {
		// Default to public
		c.SubjectType = oidc.SubjectTypePublic
	}

	// No error
	return nil
}

func (s *service) validateRegistration(ctx context.Context, req *corev1.ClientRegistrationRequest) (*corev1.Error, error) {
	// Check nil
	if req == nil {
		return rfcerrors.InvalidRequest().Build(), fmt.Errorf("unable to process nil request")
	}
	if req.Metadata == nil {
		return rfcerrors.InvalidRequest().Build(), fmt.Errorf("unable to process nil metadata")
	}
	if req.Metadata.ApplicationType == nil {
		return rfcerrors.InvalidRequest().Build(), fmt.Errorf("unable to process nil application type")
	}

	// Retrieve settings according to application type
	clientSettings, ok := s.serverProfile.ApplicationType(req.Metadata.ApplicationType.Value)
	if !ok {
		return rfcerrors.InvalidRequest().Description("application_type contains an invalid or unsupported value.").Build(), fmt.Errorf("server could not handle given application_type '%s'", req.Metadata.ApplicationType)
	}

	// Token endpoint auth methods
	if req.Metadata.TokenEndpointAuthMethod != nil {
		if !clientSettings.TokenEndpointAuthMethodsSupported().Contains(req.Metadata.TokenEndpointAuthMethod.Value) {
			return rfcerrors.InvalidClientMetadata().Description("token_endpoint_auth_method contains an invalid or unsupported value.").Build(), fmt.Errorf("token_endpoint_auth_method is invalid: '%s'", req.Metadata.TokenEndpointAuthMethod.Value)
		}
	} else {
		return rfcerrors.InvalidClientMetadata().Build(), fmt.Errorf("token_endpoint_auth_method should not be empty")
	}

	// Response Types
	if len(req.Metadata.ResponseTypes) > 0 {
		if !clientSettings.ResponseTypesSupported().HasAll(req.Metadata.ResponseTypes...) {
			return rfcerrors.InvalidClientMetadata().Description("response_types contains an invalid or unsupported value.").Build(), fmt.Errorf("a response_types element is invalid: '%s', supported '%s'", req.Metadata.ResponseTypes, clientSettings.ResponseTypesSupported())
		}
	} else {
		// Assign default response types
		req.Metadata.ResponseTypes = clientSettings.ResponseTypesSupported()
	}

	// Grant types
	if len(req.Metadata.GrantTypes) > 0 {
		grantTypes := types.StringArray(req.Metadata.GrantTypes)

		// Supported grant_types
		if !clientSettings.GrantTypesSupported().HasOneOf(req.Metadata.GrantTypes...) {
			return rfcerrors.InvalidClientMetadata().Description("grant_types contains an invalid or unsupported value.").Build(), fmt.Errorf("a grant_types element is invalid: '%s', supported '%s'", req.Metadata.GrantTypes, clientSettings.GrantTypesSupported())
		}

		// Code must be specified with `authorization_code` grant type
		if grantTypes.Contains(oidc.GrantTypeAuthorizationCode) {
			// Response_types should contain `code`
			if !types.StringArray(req.Metadata.ResponseTypes).Contains(oidc.ResponseTypeCode) {
				return rfcerrors.InvalidClientMetadata().Description("response_types contains an invalid or unsupported value for authorization code flow.").Build(), fmt.Errorf("response_types should contain `code`, supported '%s'", clientSettings.ResponseTypesSupported())
			}

			// Validate redirect_uris
			if len(req.Metadata.RedirectUris) == 0 {
				return rfcerrors.InvalidClientMetadata().Build(), fmt.Errorf("redirect_uris should not be empty for `authorization_code` grant type")
			}

			// Check redirect uris syntax
			for i := range req.Metadata.RedirectUris {
				// Prepare redirection uri
				_, err := url.ParseRequestURI(req.Metadata.RedirectUris[i])
				if err != nil {
					return rfcerrors.InvalidRedirectURI().Build(), fmt.Errorf("redirect_uri has an invalid syntax: %w", err)
				}
			}
		}

		// Code must be specified with `authorization_code` grant type
		if grantTypes.Contains(oidc.GrantTypeClientCredentials) || grantTypes.Contains(oidc.GrantTypeRefreshToken) {
			// Response_types should contain `code`
			if !types.StringArray(req.Metadata.ResponseTypes).HasAll(oidc.ResponseTypeToken) {
				return rfcerrors.InvalidClientMetadata().Description("response_types must contain `token` for compatible grant_types.").Build(), fmt.Errorf("response_types should contain `token` only")
			}
		}
	} else {
		// Assign default grant types
		req.Metadata.GrantTypes = clientSettings.GrantTypesSupported()
	}

	// JWKS
	if req.Metadata.Jwks != nil {
		// Try to decode JWKS
		var jwks jose.JSONWebKeySet
		if err := json.NewDecoder(bytes.NewBuffer(req.Metadata.Jwks.Value)).Decode(&jwks); err != nil {
			return rfcerrors.InvalidClientMetadata().Build(), fmt.Errorf("jwks is invalid: %w", err)
		}

		// JWKS should contain keys
		if len(jwks.Keys) == 0 {
			return rfcerrors.InvalidClientMetadata().Build(), fmt.Errorf("jwks is empty")
		}
	} else {
		// Check auth method
		if req.Metadata.TokenEndpointAuthMethod.Value == oidc.AuthMethodPrivateKeyJWT {
			return rfcerrors.InvalidClientMetadata().Build(), fmt.Errorf("jwks is mandatory for `private_key_jwt` authentication")
		}
	}

	if req.Metadata.Scope == nil {
		// Settings default scopes for client
		req.Metadata.Scope = &wrapperspb.StringValue{Value: strings.Join(clientSettings.DefaultScopes(), " ")}
	}

	// No error
	return nil, nil
}
