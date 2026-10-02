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
// KIND, either express or implied. See the License for the
// specific language governing permissions and limitations
// under the License.

package grpckit

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/spiffe"
	"zntr.io/solid/server/profile"
	"zntr.io/solid/server/storage"
	"zntr.io/solid/server/storage/inmemory"
)

// newAuthnService builds the gRPC client-authentication adapter over the
// in-memory client registry, mirroring the grpcbackend example wiring.
func newAuthnService(t *testing.T) (clientv1.ClientAuthenticationServiceServer, storage.Client) {
	t.Helper()

	clients := inmemory.Clients()
	return ClientAuthentication(
		clients,
		testIssuer,
		[]string{"ES256"},
		spiffe.NewStaticBundleSource(nil),
		inmemory.DPoPProofs(),
		profile.Strict(),
	), clients
}

// TestClientAuthenticationAdapterNilRequest: no request at all maps to an
// invalid_request payload, not a transport failure.
func TestClientAuthenticationAdapterNilRequest(t *testing.T) {
	svc, _ := newAuthnService(t)

	res, err := svc.Authenticate(context.Background(), nil)
	require.NoError(t, err)
	require.Equal(t, "invalid_request", res.GetError().GetError())
}

// TestClientAuthenticationAdapterPublicClient: a bare client identifier
// resolves a public client; a confidential client without credentials is
// rejected (mirrors the httpkit middleware semantics).
func TestClientAuthenticationAdapterPublicClient(t *testing.T) {
	svc, clients := newAuthnService(t)
	ctx := context.Background()

	publicID, err := clients.Register(ctx, &clientv1.Client{
		ClientType: clientv1.ClientType_CLIENT_TYPE_PUBLIC,
		ClientName: "public-app",
	})
	require.NoError(t, err)

	confidentialID, err := clients.Register(ctx, &clientv1.Client{
		ClientType:              clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		ClientName:              "confidential-app",
		TokenEndpointAuthMethod: oidc.AuthMethodPrivateKeyJWT,
	})
	require.NoError(t, err)

	res, err := svc.Authenticate(ctx, &clientv1.AuthenticateRequest{ClientId: new(publicID)})
	require.NoError(t, err)
	require.Nil(t, res.GetError())
	require.Equal(t, publicID, res.GetClient().GetClientId())

	// Identifier-only access with a confidential client is a missing
	// credential, not a lookup miss.
	res, err = svc.Authenticate(ctx, &clientv1.AuthenticateRequest{ClientId: new(confidentialID)})
	require.NoError(t, err)
	require.Equal(t, "invalid_client", res.GetError().GetError())

	// Unknown client identifier.
	res, err = svc.Authenticate(ctx, &clientv1.AuthenticateRequest{ClientId: new("does-not-exist")})
	require.NoError(t, err)
	require.Equal(t, "invalid_client", res.GetError().GetError())
}

// TestClientAuthenticationAdapterUnselectableMethod: a non-empty
// client_assertion_type that no processor handles maps to invalid_request
// (processor-set Select dispatch).
func TestClientAuthenticationAdapterUnselectableMethod(t *testing.T) {
	svc, _ := newAuthnService(t)

	res, err := svc.Authenticate(context.Background(), &clientv1.AuthenticateRequest{
		ClientAssertionType: new("urn:ietf:params:oauth:client-assertion-type:unknown"),
		ClientAssertion:     new("whatever"),
	})
	require.NoError(t, err)
	require.Equal(t, "invalid_request", res.GetError().GetError())
}

// TestClientAuthenticationAdapterPrivateKeyJWTProfile: a server-side-web
// application client authenticating with private_key_jwt is within the
// strict web profile (the gRPC adapter must enforce the application-type
// profile on the resolved authentication method).
func TestClientAuthenticationAdapterProfileEnforcement(t *testing.T) {
	svc, clients := newAuthnService(t)
	ctx := context.Background()

	webID, err := clients.Register(ctx, &clientv1.Client{
		ClientType:              clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		ClientName:              "web-app",
		Jwks:                    clientJWKSWithSIG,
		ApplicationType:         oidc.ApplicationTypeServerSideWeb,
		TokenEndpointAuthMethod: oidc.AuthMethodPrivateKeyJWT,
		GrantTypes:              []string{oidc.GrantTypeClientCredentials},
	})
	require.NoError(t, err)

	res, err := svc.Authenticate(ctx, &clientv1.AuthenticateRequest{
		ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
		ClientAssertion:     new(clientAssertion(t, webID, testIssuer)),
		ClientId:            new(webID),
	})
	require.NoError(t, err)
	require.Nil(t, res.GetError(), "web client with private_key_jwt must authenticate: %v", res.GetError())
	require.Equal(t, webID, res.GetClient().GetClientId())
}

// TestClientAuthenticationAdapterServiceClientCredentialsProfile: a service
// application-type client authenticating with private_key_jwt is within
// the strict service profile.
func TestClientAuthenticationAdapterServiceClientCredentialsProfile(t *testing.T) {
	svc, clients := newAuthnService(t)
	ctx := context.Background()

	serviceID, err := clients.Register(ctx, &clientv1.Client{
		ClientType:              clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		ClientName:              "service-app",
		Jwks:                    clientJWKSWithSIG,
		ApplicationType:         oidc.ApplicationTypeService,
		TokenEndpointAuthMethod: oidc.AuthMethodPrivateKeyJWT,
		GrantTypes:              []string{oidc.GrantTypeClientCredentials},
	})
	require.NoError(t, err)

	res, err := svc.Authenticate(ctx, &clientv1.AuthenticateRequest{
		ClientAssertionType: new(oidc.AssertionTypeJWTBearer),
		ClientAssertion:     new(clientAssertion(t, serviceID, testIssuer)),
		ClientId:            new(serviceID),
	})
	require.NoError(t, err)
	require.Nil(t, res.GetError())
	require.Equal(t, serviceID, res.GetClient().GetClientId())
}

// requireGRPCCode is shared with adapters_test.go.
var _ = requireGRPCCode

// silence unused import when assertions shift.
var _ = status.Error(codes.Internal, "")
