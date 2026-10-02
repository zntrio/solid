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
	if s.registrz == nil {
		return nil, status.Error(codes.Unimplemented, "client registration service is not enabled")
	}

	res, err := s.registrz.Register(ctx, req)
	if err != nil {
		log.Println("grpc client registration:", err)
	}
	if res == nil {
		return nil, status.Error(codes.Internal, "no response")
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
	if s.registrz == nil {
		return nil, status.Error(codes.Unimplemented, "client registration service is not enabled")
	}

	res, err := s.registrz.Read(ctx, req)
	if err != nil {
		log.Println("grpc client registration read:", err)
	}
	if res == nil {
		return nil, status.Error(codes.Internal, "no response")
	}
	return res, nil
}

// Update the registration (RFC 7592 section 2.2).
func (s *clientRegistrationManagementService) Update(ctx context.Context, req *clientv1.UpdateRequest) (*clientv1.UpdateResponse, error) {
	if s.registrz == nil {
		return nil, status.Error(codes.Unimplemented, "client registration service is not enabled")
	}

	res, err := s.registrz.Update(ctx, req)
	if err != nil {
		log.Println("grpc client registration update:", err)
	}
	if res == nil {
		return nil, status.Error(codes.Internal, "no response")
	}
	return res, nil
}

// Delete the registration (RFC 7592 section 2.3).
func (s *clientRegistrationManagementService) Delete(ctx context.Context, req *clientv1.DeleteRequest) (*clientv1.DeleteResponse, error) {
	if s.registrz == nil {
		return nil, status.Error(codes.Unimplemented, "client registration service is not enabled")
	}

	res, err := s.registrz.Delete(ctx, req)
	if err != nil {
		log.Println("grpc client registration delete:", err)
	}
	if res == nil {
		return nil, status.Error(codes.Internal, "no response")
	}
	return res, nil
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
	if s.tokenz == nil {
		return nil, status.Error(codes.Unimplemented, "introspection service is not enabled")
	}

	res, err := s.tokenz.Introspect(ctx, req)
	if err != nil {
		log.Println("grpc introspection:", err)
	}
	if res == nil {
		return nil, status.Error(codes.Internal, "no response")
	}
	return res, nil
}

// -----------------------------------------------------------------------------
// Revocation (RFC 7009)

type revocationService struct {
	tokenv1.UnimplementedRevocatonServiceServer

	tokenz services.Token
}

// RevocationService returns the gRPC adapter for the token revocation
// service (RFC 7009 section 2.1).
func RevocationService(tokenz services.Token) tokenv1.RevocatonServiceServer {
	return &revocationService{
		tokenz: tokenz,
	}
}

// Revoke a token (RFC 7009 section 2.1).
func (s *revocationService) Revoke(ctx context.Context, req *tokenv1.RevokeRequest) (*tokenv1.RevokeResponse, error) {
	if s.tokenz == nil {
		return nil, status.Error(codes.Unimplemented, "revocation service is not enabled")
	}

	res, err := s.tokenz.Revoke(ctx, req)
	if err != nil {
		log.Println("grpc revocation:", err)
	}
	if res == nil {
		return nil, status.Error(codes.Internal, "no response")
	}
	return res, nil
}
