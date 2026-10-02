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

// Package clientregistration implements the RFC 7591 dynamic client
// registration protocol with a defensive posture: asymmetric client
// authentication methods only (no client secret is ever issued), the
// implemented grant-type allowlist, `code` response type only, and the
// loopback exception on redirect URI schemes. The Authorizer gate keeps
// the endpoint closed unless the deployment opts in.
package clientregistration

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"google.golang.org/protobuf/proto"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	corev1 "zntr.io/solid/api/oidc/core/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/random"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/server/services"
	"zntr.io/solid/server/storage"
)

// Authorizer gates dynamic client registration per deployment; nil denies
// all requests.
type Authorizer func(ctx context.Context, req *clientv1.RegisterRequest) bool

type clientRegistration struct {
	clients    storage.Client
	tokens     storage.Token
	authorizer Authorizer
}

// New returns a dynamic client registration service (RFC 7591 section
// 3.2.1) with its RFC 7592 management protocol (Read/Update/Delete
// authenticated by the per-client registration access token issued at
// registration time).
func New(clients storage.Client, tokens storage.Token, authorizer Authorizer) services.ClientRegistration {
	return &clientRegistration{
		clients:    clients,
		tokens:     tokens,
		authorizer: authorizer,
	}
}

// Register a client (RFC 7591 section 3.2.1).
func (s *clientRegistration) Register(ctx context.Context, req *clientv1.RegisterRequest) (*clientv1.RegisterResponse, error) {
	if req == nil || req.Metadata == nil {
		res := &clientv1.RegisterResponse{
			Error: rfcerrors.InvalidClientMetadata().Build(),
		}
		return res, fmt.Errorf("invalid_client_metadata: RFC 7591 section 2.3 metadata rejected")
	}

	// Dynamic client registration is a deployment-gated surface.
	if s.authorizer == nil || !s.authorizer(ctx, req) {
		res := &clientv1.RegisterResponse{
			Error: rfcerrors.AccessDenied().Build(),
		}
		return res, fmt.Errorf("access_denied: dynamic client registration is disabled")
	}

	client, err := s.validatedClient(req.Metadata)
	if err != nil {
		res := &clientv1.RegisterResponse{
			Error: rfcerrors.InvalidClientMetadata().Build(),
		}
		return res, err
	}

	if _, err := s.clients.Register(ctx, client); err != nil {
		res := &clientv1.RegisterResponse{
			Error: rfcerrors.ServerError().Build(),
		}
		return res, err
	}

	// RFC 7592 section 3: issue the per-client registration access token
	// used as sole credential on the management surface.
	registrationAccessToken := random.String(32)
	client.RegistrationAccessToken = &registrationAccessToken
	if err := s.clients.Update(ctx, client); err != nil {
		res := &clientv1.RegisterResponse{
			Error: rfcerrors.ServerError().Build(),
		}
		return res, err
	}

	// The bearer token never rides the Client payload returned to any
	// other surface; only the registration response carries it.
	public := proto.Clone(client).(*clientv1.Client)
	public.RegistrationAccessToken = nil

	return &clientv1.RegisterResponse{
		Client:                  public,
		RegistrationAccessToken: &registrationAccessToken,
	}, nil
}

// Read the current registration (RFC 7592 section 2.1).
func (s *clientRegistration) Read(ctx context.Context, req *clientv1.ReadRequest) (*clientv1.ReadResponse, error) {
	if req == nil {
		res := &clientv1.ReadResponse{
			Error: rfcerrors.InvalidRequest().Build(),
		}
		return res, fmt.Errorf("invalid_request: nil read request")
	}

	client, authErr := s.authorizeRegistrationToken(ctx, req.GetClientId(), req.GetRegistrationAccessToken())
	if authErr != nil {
		res := &clientv1.ReadResponse{
			Error: authErr,
		}
		return res, fmt.Errorf("invalid_token: registration access token rejected")
	}

	return &clientv1.ReadResponse{
		Client: withoutRegistrationToken(client),
	}, nil
}

// Update the registration (RFC 7592 section 2.2). The request metadata is
// a full replacement: omitted fields are removed from the registration.
func (s *clientRegistration) Update(ctx context.Context, req *clientv1.UpdateRequest) (*clientv1.UpdateResponse, error) {
	if req == nil || req.Metadata == nil {
		res := &clientv1.UpdateResponse{
			Error: rfcerrors.InvalidClientMetadata().Build(),
		}
		return res, fmt.Errorf("invalid_client_metadata: RFC 7592 section 2.2 metadata rejected")
	}

	stored, authErr := s.authorizeRegistrationToken(ctx, req.GetClientId(), req.GetRegistrationAccessToken())
	if authErr != nil {
		res := &clientv1.UpdateResponse{
			Error: authErr,
		}
		return res, fmt.Errorf("invalid_token: registration access token rejected")
	}

	// RFC 7592 section 2.2: the client identifier MUST equal the currently
	// issued one.
	if req.GetClientId() != stored.GetClientId() {
		res := &clientv1.UpdateResponse{
			Error: rfcerrors.InvalidClient().Build(),
		}
		return res, fmt.Errorf("invalid_client: client_id mismatch on update")
	}

	updated, err := s.validatedClient(req.Metadata)
	if err != nil {
		res := &clientv1.UpdateResponse{
			Error: rfcerrors.InvalidClientMetadata().Build(),
		}
		return res, err
	}

	// Preserve server-assigned fields: the client identifier is immutable
	// and the registration access token carries over so subsequent
	// management calls still authenticate (RFC 7592 section 5: the token
	// SHOULD NOT expire while the client remains active).
	updated.ClientId = stored.GetClientId()
	updated.RegistrationAccessToken = stored.RegistrationAccessToken

	if err := s.clients.Update(ctx, updated); err != nil {
		res := &clientv1.UpdateResponse{
			Error: rfcerrors.ServerError().Build(),
		}
		return res, err
	}

	return &clientv1.UpdateResponse{
		Client: withoutRegistrationToken(updated),
	}, nil
}

// Delete the registration (RFC 7592 section 2.3) and revoke every token
// issued to the client.
func (s *clientRegistration) Delete(ctx context.Context, req *clientv1.DeleteRequest) (*clientv1.DeleteResponse, error) {
	if req == nil {
		res := &clientv1.DeleteResponse{
			Error: rfcerrors.InvalidRequest().Build(),
		}
		return res, fmt.Errorf("invalid_request: nil delete request")
	}

	client, authErr := s.authorizeRegistrationToken(ctx, req.GetClientId(), req.GetRegistrationAccessToken())
	if authErr != nil {
		res := &clientv1.DeleteResponse{
			Error: authErr,
		}
		return res, fmt.Errorf("invalid_token: registration access token rejected")
	}

	// RFC 7592 section 2.3 SHOULD: deprovisioning invalidates every token
	// issued to the client.
	for _, t := range s.tokens.GetByClientID(ctx, client.GetClientId()) {
		if t == nil {
			continue
		}
		_ = s.tokens.Revoke(ctx, "", t.GetTokenId())
	}

	if err := s.clients.Delete(ctx, client.GetClientId()); err != nil {
		res := &clientv1.DeleteResponse{
			Error: rfcerrors.ServerError().Build(),
		}
		return res, err
	}

	return &clientv1.DeleteResponse{}, nil
}

// validatedClient applies the RFC 7591 section 2 metadata rules and
// assembles the resulting client record. It is shared by Register and the
// RFC 7592 update path so both surfaces enforce the same posture.
//
//nolint:gocyclo // ordered RFC 7591 section 2 metadata validation, one rule per branch
func (s *clientRegistration) validatedClient(metadata *clientv1.ClientMeta) (*clientv1.Client, error) {
	// RFC 7591 section 2.3: software statements require a trust framework
	// to validate them; none is deployed here, so they are rejected.
	if metadata.SoftwareStatement != nil {
		return nil, fmt.Errorf("invalid_client_metadata: RFC 7591 section 2.3 software statement rejected")
	}

	// Token-endpoint authentication method: default `private_key_jwt`,
	// asymmetric-only posture (no shared-secret methods accepted, no
	// secret is ever issued).
	authMethod := oidc.AuthMethodPrivateKeyJWT
	if metadata.TokenEndpointAuthMethod != nil {
		authMethod = metadata.GetTokenEndpointAuthMethod()
	}
	if !supportedAuthMethods[authMethod] {
		return nil, fmt.Errorf("invalid_client_metadata: RFC 7591 section 2.3 metadata rejected")
	}

	// Grant types: default `authorization_code`, restricted to the
	// implemented set.
	grantTypes := metadata.GetGrantTypes()
	if len(grantTypes) == 0 {
		grantTypes = []string{oidc.GrantTypeAuthorizationCode}
	}
	for _, g := range grantTypes {
		if !supportedGrantTypes[g] {
			return nil, fmt.Errorf("invalid_client_metadata: RFC 7591 section 2.3 metadata rejected")
		}
	}

	// Response types: default `code`, no implicit or hybrid flow.
	responseTypes := metadata.GetResponseTypes()
	if len(responseTypes) == 0 {
		responseTypes = []string{oidc.ResponseTypeCode}
	}
	for _, rt := range responseTypes {
		if rt != oidc.ResponseTypeCode {
			return nil, fmt.Errorf("invalid_client_metadata: RFC 7591 section 2.3 metadata rejected")
		}
	}

	// Redirect URIs are REQUIRED when the authorization code grant is
	// requested (RFC 7591 section 2).
	if contains(grantTypes, oidc.GrantTypeAuthorizationCode) && len(metadata.GetRedirectUris()) == 0 {
		return nil, fmt.Errorf("invalid_client_metadata: RFC 7591 section 2.3 metadata rejected")
	}
	for _, redirect := range metadata.GetRedirectUris() {
		if !validRedirectURI(redirect) {
			return nil, fmt.Errorf("invalid_client_metadata: RFC 7591 section 2.3 metadata rejected")
		}
	}

	// JWKS are REQUIRED for private_key_jwt: the assertion verification
	// needs the client public keys.
	jwks := metadata.GetJwks()
	if authMethod == oidc.AuthMethodPrivateKeyJWT && len(jwks) == 0 {
		return nil, fmt.Errorf("invalid_client_metadata: RFC 7591 section 2.3 metadata rejected")
	}
	if len(jwks) > 0 {
		if _, err := jwk.Parse(jwks); err != nil {
			return nil, fmt.Errorf("invalid_client_metadata: RFC 7591 section 2.3 metadata rejected")
		}
	}

	// Assemble the stored client from the validated metadata. The client
	// identifier is assigned by the storage layer.
	return &clientv1.Client{
		ClientType:                            clientTypeFor(authMethod),
		ApplicationType:                       metadata.GetApplicationType(),
		RedirectUris:                          metadata.RedirectUris,
		ResponseTypes:                         responseTypes,
		ResponseModes:                         metadata.ResponseModes,
		GrantTypes:                            grantTypes,
		Contacts:                              metadata.Contacts,
		ClientName:                            metadata.GetClientName(),
		LogoUri:                               metadata.GetLogoUri(),
		ClientUri:                             metadata.GetClientUri(),
		PolicyUri:                             metadata.GetPolicyUri(),
		TosUri:                                metadata.GetTosUri(),
		Jwks:                                  metadata.Jwks,
		JwksUri:                               metadata.GetJwkUri(),
		SubjectType:                           metadata.GetSubjectType(),
		SectorIdentifier:                      metadata.GetSectorIdentifier(),
		TokenEndpointAuthMethod:               authMethod,
		TlsClientAuthSubjectDn:                metadata.GetTlsClientAuthSubjectDn(),
		TlsClientAuthSanDns:                   metadata.GetTlsClientAuthSanDns(),
		TlsClientAuthSanUri:                   metadata.GetTlsClientAuthSanUri(),
		TlsClientAuthSanIp:                    metadata.GetTlsClientAuthSanIp(),
		TlsClientAuthSanEmail:                 metadata.GetTlsClientAuthSanEmail(),
		TlsClientCertificateBoundAccessTokens: metadata.GetTlsClientCertificateBoundAccessTokens(),
		RequirePushedAuthorizationRequests:    metadata.GetRequirePushedAuthorizationRequests(),
		RequireSignedRequestObject:            metadata.GetRequireSignedRequestObject(),
		DpopBoundAccessTokens:                 metadata.GetDpopBoundAccessTokens(),
		SpiffeId:                              metadata.GetSpiffeId(),
		SpiffeBundleEndpoint:                  metadata.GetSpiffeBundleEndpoint(),
	}, nil
}

// authorizeRegistrationToken validates the RFC 7592 section 2 bearer
// credential against the stored registration. On mismatch or unknown
// token, the stored registration access token is revoked (cleared) per
// RFC 7592 section 2.1/2.2. A non-nil second return value is the error
// payload to ride the caller's response.
func (s *clientRegistration) authorizeRegistrationToken(ctx context.Context, clientID, token string) (*clientv1.Client, *corev1.Error) {
	stored, err := s.clients.Get(ctx, clientID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, rfcerrors.InvalidToken().Build()
		}
		return nil, rfcerrors.ServerError().Build()
	}

	// Empty or mismatching token: invalid_token, and the stored token is
	// revoked so a guessing attempt burns the credential.
	if token == "" || stored.GetRegistrationAccessToken() == "" || token != stored.GetRegistrationAccessToken() {
		if stored.GetRegistrationAccessToken() != "" {
			cleared := proto.Clone(stored).(*clientv1.Client)
			cleared.RegistrationAccessToken = nil
			_ = s.clients.Update(ctx, cleared)
		}
		return nil, rfcerrors.InvalidToken().Build()
	}

	return stored, nil
}

// withoutRegistrationToken returns a response-safe copy of the client: the
// registration access token is a server-side record, never a read payload.
func withoutRegistrationToken(c *clientv1.Client) *clientv1.Client {
	public := proto.Clone(c).(*clientv1.Client)
	public.RegistrationAccessToken = nil
	return public
}

// supportedAuthMethods is the asymmetric-only token-endpoint authentication
// allowlist (solid security posture: no shared-secret method, no issued
// secret).
var supportedAuthMethods = map[string]bool{
	oidc.AuthMethodNone:                    true,
	oidc.AuthMethodPrivateKeyJWT:           true,
	oidc.AuthMethodClientAttestationJWT:    true,
	oidc.AuthMethodSPIFFEJWT:               true,
	oidc.AuthMethodSPIFFEWIT:               true,
	oidc.AuthMethodSPIFFEX509:              true,
	oidc.AuthMethodTLSClientAuth:           true,
	oidc.AuthMethodSelfSignedTLSClientAuth: true,
}

// supportedGrantTypes is the implemented grant-type allowlist.
var supportedGrantTypes = map[string]bool{
	oidc.GrantTypeAuthorizationCode: true,
	oidc.GrantTypeClientCredentials: true,
	oidc.GrantTypeRefreshToken:      true,
	oidc.GrantTypeDeviceCode:        true,
	oidc.GrantTypeTokenExchange:     true,
	oidc.GrantTypeJWTBearer:         true,
	oidc.GrantTypeCIBA:              true,
}

// clientTypeFor maps the authentication method to the client type: a client
// that authenticates with no credential is public, all others confidential.
func clientTypeFor(authMethod string) clientv1.ClientType {
	if authMethod == oidc.AuthMethodNone {
		return clientv1.ClientType_CLIENT_TYPE_PUBLIC
	}
	return clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL
}

// validRedirectURI enforces https redirect URIs, with the RFC 8252 section
// 7.3 loopback exception (http allowed on localhost, 127.0.0.1, ::1) and no
// fragment components.
func validRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" || u.Host == "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme == "http" && isLoopbackHost(u.Host) {
		return true
	}
	return false
}

// isLoopbackHost reports whether the URI host is an RFC 8252 section 7.3
// loopback address.
func isLoopbackHost(host string) bool {
	h := strings.ToLower(host)
	// Strip the port, keeping IPv6 literals bracketed.
	if i := strings.LastIndex(h, ":"); i > strings.LastIndex(h, "]") {
		h = h[:i]
	}
	h = strings.Trim(h, "[]")
	switch h {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
