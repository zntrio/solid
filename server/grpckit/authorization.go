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

	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	"zntr.io/solid/server/services"
)

type authorizationService struct {
	flowv1.UnimplementedAuthorizationServiceServer

	authz  services.Authorization
	tokenz services.Token
}

// AuthorizationService returns the gRPC adapter for the authorization
// service (authorization endpoint, PAR registration, token endpoint).
// A nil dependency makes the corresponding method return Unimplemented so
// assemblies can expose a partial surface.
func AuthorizationService(authz services.Authorization, tokenz services.Token) flowv1.AuthorizationServiceServer {
	return &authorizationService{
		authz:  authz,
		tokenz: tokenz,
	}
}

// Authorize handles an authorization request (RFC 6749 section 3.1).
func (s *authorizationService) Authorize(ctx context.Context, req *flowv1.AuthorizeRequest) (*flowv1.AuthorizeResponse, error) {
	if s.authz == nil {
		return nil, status.Error(codes.Unimplemented, "authorization service is not enabled")
	}

	res, err := s.authz.Authorize(ctx, req)
	if err != nil {
		log.Println("grpc authorization:", err)
	}
	if res == nil {
		return nil, status.Error(codes.Internal, "no response")
	}
	return res, nil
}

// Register handles a pushed authorization request registration (RFC 9126
// section 2). The presentation layer has already decoded the JAR request
// object and verified the DPoP proof: the resolved request and confirmation
// ride the proto fields.
func (s *authorizationService) Register(ctx context.Context, req *flowv1.RegistrationRequest) (*flowv1.RegistrationResponse, error) {
	if s.authz == nil {
		return nil, status.Error(codes.Unimplemented, "authorization service is not enabled")
	}

	res, err := s.authz.Register(ctx, req)
	if err != nil {
		log.Println("grpc PAR registration:", err)
	}
	if res == nil {
		return nil, status.Error(codes.Internal, "no response")
	}
	return res, nil
}

// Token handles a token request (RFC 6749 section 3.2). The presentation
// layer has already authenticated the client: the resolved client, DPoP
// token confirmation and mTLS certificate thumbprint ride the proto fields.
func (s *authorizationService) Token(ctx context.Context, req *flowv1.TokenRequest) (*flowv1.TokenResponse, error) {
	if s.tokenz == nil {
		return nil, status.Error(codes.Unimplemented, "token service is not enabled")
	}

	res, err := s.tokenz.Token(ctx, req)
	if err != nil {
		log.Println("grpc token:", err)
	}
	if res == nil {
		return nil, status.Error(codes.Internal, "no response")
	}
	return res, nil
}
