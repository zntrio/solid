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
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/server/services"
)

// -----------------------------------------------------------------------------
// Adapters: partial assembly, nil-dependency and failure dispatch.

// The adapters allow partial assemblies: a nil dependency makes the
// corresponding RPC Unimplemented instead of panicking, and a service
// returning no response maps to Internal. These exercise each adapter's
// dispatch table without the full service stack (the end-to-end behaviour
// is covered by grpc_backend_test.go and integration/).

// nopAuthorization is a services.Authorization with programmable results.
type nopAuthorization struct {
	authorizeRes *flowv1.AuthorizeResponse
	authorizeErr error
	registerRes  *flowv1.RegistrationResponse
	registerErr  error
}

func (a *nopAuthorization) Authorize(context.Context, *flowv1.AuthorizeRequest) (*flowv1.AuthorizeResponse, error) {
	return a.authorizeRes, a.authorizeErr
}

func (a *nopAuthorization) Register(context.Context, *flowv1.RegistrationRequest) (*flowv1.RegistrationResponse, error) {
	return a.registerRes, a.registerErr
}

// nopToken is a services.Token with programmable results.
type nopToken struct {
	tokenRes      *flowv1.TokenResponse
	tokenErr      error
	introspectRes *tokenv1.IntrospectResponse
	introspectErr error
	revokeRes     *tokenv1.RevokeResponse
	revokeErr     error
}

func (t *nopToken) Token(context.Context, *flowv1.TokenRequest) (*flowv1.TokenResponse, error) {
	return t.tokenRes, t.tokenErr
}

func (t *nopToken) Introspect(context.Context, *tokenv1.IntrospectRequest) (*tokenv1.IntrospectResponse, error) {
	return t.introspectRes, t.introspectErr
}

func (t *nopToken) Revoke(context.Context, *tokenv1.RevokeRequest) (*tokenv1.RevokeResponse, error) {
	return t.revokeRes, t.revokeErr
}

// nopClientRegistration is a services.ClientRegistration with programmable
// results.
type nopClientRegistration struct {
	res *clientv1.RegisterResponse
	err error
}

func (r *nopClientRegistration) Register(context.Context, *clientv1.RegisterRequest) (*clientv1.RegisterResponse, error) {
	return r.res, r.err
}

func (r *nopClientRegistration) Read(context.Context, *clientv1.ReadRequest) (*clientv1.ReadResponse, error) {
	return nil, r.err
}

func (r *nopClientRegistration) Update(context.Context, *clientv1.UpdateRequest) (*clientv1.UpdateResponse, error) {
	return nil, r.err
}

func (r *nopClientRegistration) Delete(context.Context, *clientv1.DeleteRequest) (*clientv1.DeleteResponse, error) {
	return nil, r.err
}

// requireGRPCCode asserts the error carries the given gRPC status code.
func requireGRPCCode(t *testing.T, err error, want codes.Code, contains string) {
	t.Helper()
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok, "error must be a gRPC status, got %T", err)
	require.Equal(t, want, st.Code())
	require.Contains(t, st.Message(), contains)
}

func TestAuthorizationServiceAdapterDispatch(t *testing.T) {
	ctx := context.Background()

	t.Run("nil authorization dependency is Unimplemented", func(t *testing.T) {
		svc := AuthorizationService(nil, &nopToken{})
		_, err := svc.Authorize(ctx, &flowv1.AuthorizeRequest{})
		requireGRPCCode(t, err, codes.Unimplemented, "authorization service")
		_, err = svc.Register(ctx, &flowv1.RegistrationRequest{})
		requireGRPCCode(t, err, codes.Unimplemented, "authorization service")
	})

	t.Run("nil token dependency is Unimplemented", func(t *testing.T) {
		svc := AuthorizationService(&nopAuthorization{}, nil)
		_, err := svc.Token(ctx, &flowv1.TokenRequest{})
		requireGRPCCode(t, err, codes.Unimplemented, "token service")
	})

	t.Run("authorization error with response is propagated", func(t *testing.T) {
		svc := AuthorizationService(&nopAuthorization{
			authorizeRes: &flowv1.AuthorizeResponse{State: "ok"},
			authorizeErr: errors.New("boom"),
		}, nil)
		res, err := svc.Authorize(ctx, &flowv1.AuthorizeRequest{})
		require.NoError(t, err)
		require.Equal(t, "ok", res.GetState())
	})

	t.Run("authorization error without response is Internal", func(t *testing.T) {
		svc := AuthorizationService(&nopAuthorization{
			authorizeErr: errors.New("boom"),
		}, nil)
		_, err := svc.Authorize(ctx, &flowv1.AuthorizeRequest{})
		requireGRPCCode(t, err, codes.Internal, "no response")
		_, err = svc.Register(ctx, &flowv1.RegistrationRequest{})
		requireGRPCCode(t, err, codes.Internal, "no response")
	})

	t.Run("token error without response is Internal", func(t *testing.T) {
		svc := AuthorizationService(nil, &nopToken{tokenErr: errors.New("boom")})
		_, err := svc.Token(ctx, &flowv1.TokenRequest{})
		requireGRPCCode(t, err, codes.Internal, "no response")
	})
}

func TestClientRegistrationServiceAdapterDispatch(t *testing.T) {
	ctx := context.Background()

	t.Run("nil dependency is Unimplemented", func(t *testing.T) {
		svc := ClientRegistration(nil, "https://issuer.example")
		_, err := svc.Register(ctx, &clientv1.RegisterRequest{})
		requireGRPCCode(t, err, codes.Unimplemented, "client registration service")
	})

	t.Run("service error without response is Internal", func(t *testing.T) {
		svc := ClientRegistration(&nopClientRegistration{err: errors.New("boom")}, "https://issuer.example")
		_, err := svc.Register(ctx, &clientv1.RegisterRequest{})
		requireGRPCCode(t, err, codes.Internal, "no response")
	})

	t.Run("service response is returned with client configuration URI", func(t *testing.T) {
		svc := ClientRegistration(&nopClientRegistration{
			res: &clientv1.RegisterResponse{Client: &clientv1.Client{ClientId: "reg-1"}},
		}, "https://issuer.example")
		res, err := svc.Register(ctx, &clientv1.RegisterRequest{})
		require.NoError(t, err)
		require.Equal(t, "reg-1", res.GetClient().GetClientId())
		require.Equal(t, "https://issuer.example/register/reg-1", res.GetRegistrationClientUri())
	})
}

func TestIntrospectionServiceAdapterDispatch(t *testing.T) {
	ctx := context.Background()

	t.Run("nil dependency is Unimplemented", func(t *testing.T) {
		svc := IntrospectionService(nil)
		_, err := svc.Introspect(ctx, &tokenv1.IntrospectRequest{})
		requireGRPCCode(t, err, codes.Unimplemented, "introspection service")
	})

	t.Run("service error without response is Internal", func(t *testing.T) {
		svc := IntrospectionService(&nopToken{introspectErr: errors.New("boom")})
		_, err := svc.Introspect(ctx, &tokenv1.IntrospectRequest{})
		requireGRPCCode(t, err, codes.Internal, "no response")
	})
}

func TestRevocationServiceAdapterDispatch(t *testing.T) {
	ctx := context.Background()

	t.Run("nil dependency is Unimplemented", func(t *testing.T) {
		svc := RevocationService(nil)
		_, err := svc.Revoke(ctx, &tokenv1.RevokeRequest{})
		requireGRPCCode(t, err, codes.Unimplemented, "revocation service")
	})

	t.Run("service error without response is Internal", func(t *testing.T) {
		svc := RevocationService(&nopToken{revokeErr: errors.New("boom")})
		_, err := svc.Revoke(ctx, &tokenv1.RevokeRequest{})
		requireGRPCCode(t, err, codes.Internal, "no response")
	})
}

// Compile-time interface conformance of the fakes.
var (
	_ services.Authorization      = (*nopAuthorization)(nil)
	_ services.Token              = (*nopToken)(nil)
	_ services.ClientRegistration = (*nopClientRegistration)(nil)
)
