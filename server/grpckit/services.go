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

package grpckit

import (
	"context"
	"log"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/server/services"
)

// -----------------------------------------------------------------------------
// Client registration (RFC 7591) + management (RFC 7592)

type clientRegistrationService struct {
	clientv1.UnimplementedClientRegistrationServiceServer

	registrz services.ClientRegistration
	issuer   string
}

// ClientRegistration returns the gRPC adapter for the dynamic client
// registration service (RFC 7591 section 3.2.1). The issuer populates the
// RFC 7592 section 3 registration_client_uri on the response.
func ClientRegistration(registrz services.ClientRegistration, issuer string) clientv1.ClientRegistrationServiceServer {
	return &clientRegistrationService{
		registrz: registrz,
		issuer:   issuer,
	}
}

// Register a client (RFC 7591 section 3.2.1). The RFC error rides the
// response payload so the presentation layer can map it faithfully.
func (s *clientRegistrationService) Register(ctx context.Context, req *clientv1.RegisterRequest) (*clientv1.RegisterResponse, error) {
	res, err := adapt("grpc client registration service", s.registrz != nil, func() (*clientv1.RegisterResponse, error) {
		return s.registrz.Register(ctx, req)
	})
	if err != nil {
		return nil, err
	}

	// RFC 7592 section 3: the client configuration endpoint URI derives
	// from the issuer; the presentation layer owns the path shape.
	if res.GetClient() != nil {
		uri := s.issuer + "/register/" + res.GetClient().GetClientId()
		res.RegistrationClientUri = &uri
	}

	return res, nil
}

type clientRegistrationManagementService struct {
	clientv1.UnimplementedClientRegistrationManagementServiceServer

	registrz services.ClientRegistration
	issuer   string
}

// ClientRegistrationManagement returns the gRPC adapter for the RFC 7592
// client configuration endpoint.
func ClientRegistrationManagement(registrz services.ClientRegistration, issuer string) clientv1.ClientRegistrationManagementServiceServer {
	return &clientRegistrationManagementService{
		registrz: registrz,
		issuer:   issuer,
	}
}

// Read the current registration (RFC 7592 section 2.1).
func (s *clientRegistrationManagementService) Read(ctx context.Context, req *clientv1.ReadRequest) (*clientv1.ReadResponse, error) {
	return adapt("grpc client registration read service", s.registrz != nil, func() (*clientv1.ReadResponse, error) {
		return s.registrz.Read(ctx, req)
	})
}

// Update the registration (RFC 7592 section 2.2).
func (s *clientRegistrationManagementService) Update(ctx context.Context, req *clientv1.UpdateRequest) (*clientv1.UpdateResponse, error) {
	return adapt("grpc client registration update service", s.registrz != nil, func() (*clientv1.UpdateResponse, error) {
		return s.registrz.Update(ctx, req)
	})
}

// Delete the registration (RFC 7592 section 2.3).
func (s *clientRegistrationManagementService) Delete(ctx context.Context, req *clientv1.DeleteRequest) (*clientv1.DeleteResponse, error) {
	return adapt("grpc client registration delete service", s.registrz != nil, func() (*clientv1.DeleteResponse, error) {
		return s.registrz.Delete(ctx, req)
	})
}

// -----------------------------------------------------------------------------
// Introspection (RFC 7662)

type introspectionService struct {
	tokenv1.UnimplementedIntrospectionServiceServer

	tokenz services.Token
}

// IntrospectionService returns the gRPC adapter for the token
// introspection service (RFC 7662 section 2).
func IntrospectionService(tokenz services.Token) tokenv1.IntrospectionServiceServer {
	return &introspectionService{
		tokenz: tokenz,
	}
}

// Introspect a token (RFC 7662 section 2).
func (s *introspectionService) Introspect(ctx context.Context, req *tokenv1.IntrospectRequest) (*tokenv1.IntrospectResponse, error) {
	return adapt("grpc introspection service", s.tokenz != nil, func() (*tokenv1.IntrospectResponse, error) {
		return s.tokenz.Introspect(ctx, req)
	})
}

// -----------------------------------------------------------------------------
// Revocation (RFC 7009)

type revocationService struct {
	tokenv1.UnimplementedRevocationServiceServer

	tokenz services.Token
}

// RevocationService returns the gRPC adapter for the token revocation
// service (RFC 7009 section 2.1).
func RevocationService(tokenz services.Token) tokenv1.RevocationServiceServer {
	return &revocationService{
		tokenz: tokenz,
	}
}

// Revoke a token (RFC 7009 section 2.1).
func (s *revocationService) Revoke(ctx context.Context, req *tokenv1.RevokeRequest) (*tokenv1.RevokeResponse, error) {
	return adapt("grpc revocation service", s.tokenz != nil, func() (*tokenv1.RevokeResponse, error) {
		return s.tokenz.Revoke(ctx, req)
	})
}

// adapt runs the body shared by every gRPC service adapter: refuse a
// disabled service, delegate, log the cause of an error response, and
// guard against a nil service result (Internal).
func adapt[Res any, PRes interface{ *Res }](logName string, enabled bool, call func() (PRes, error)) (PRes, error) {
	if !enabled {
		return nil, status.Error(codes.Unimplemented, strings.TrimPrefix(logName, "grpc ")+" is not enabled")
	}
	res, err := call()
	if err != nil {
		log.Println(logName+":", err)
	}
	if res == nil {
		return nil, status.Error(codes.Internal, "no response")
	}
	return res, nil
}
