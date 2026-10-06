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
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/spiffe"
	"zntr.io/solid/server/clientauthentication"
	"zntr.io/solid/server/profile"
	"zntr.io/solid/server/services/msgval"
	"zntr.io/solid/server/storage"
)

type clientAuthenticationService struct {
	clientv1.UnimplementedClientAuthenticationServiceServer

	clients  storage.ClientReader
	procs    clientauthentication.ProcessorSet
	profiles profile.Server
}

// ClientAuthentication returns the gRPC adapter for the client
// authentication service. It mirrors the httpkit middleware: the
// presentation layer forwards the credential inputs extracted from its own
// request encoding (client assertion, attestation pair, TLS client
// certificate, receiving endpoint), and the adapter enforces the
// authentication semantics. The spiffeBundles source provides the
// trust-domain signing keys for the SPIFFE methods
// (draft-ietf-oauth-spiffe-client-auth-02); dpopProofs is the shared DPoP
// proof (jti) store.
func ClientAuthentication(clients storage.ClientReader, issuer string,
	supportedAlgorithms []string, spiffeBundles spiffe.BundleSource,
	dpopProofs storage.DPoP, profiles profile.Server,
) clientv1.ClientAuthenticationServiceServer {
	return &clientAuthenticationService{
		clients:  clients,
		procs:    clientauthentication.NewProcessorSet(clients, issuer, supportedAlgorithms, spiffeBundles, dpopProofs),
		profiles: profiles,
	}
}

// Authenticate resolves the client from the credential inputs
// (RFC 8705 section 2.1, draft-ietf-oauth-spiffe-client-auth-02
// sections 3.2/3.3, draft-ietf-oauth-attestation-based-client-auth-11).
// The result — resolved client or RFC error — rides the response payload;
// transport status only signals adapter-level failures.
//
//nolint:gocyclo // linear credential dispatch mirroring the httpkit middleware
func (s *clientAuthenticationService) Authenticate(ctx context.Context, req *clientv1.AuthenticateRequest) (*clientv1.AuthenticateResponse, error) {
	if req == nil {
		return &clientv1.AuthenticateResponse{
			Error: rfcerrors.InvalidRequest().Build(),
		}, nil
	}
	if publicErr := msgval.ValidateOrError(req); publicErr != nil {
		return &clientv1.AuthenticateResponse{
			Error: publicErr,
		}, nil
	}

	// Public-client path: only the client identifier is carried, no
	// credential inputs. A confidential client presenting its identifier
	// without credentials is rejected (mirrors the httpkit middleware).
	if req.GetClientAssertionType() == "" && req.GetClientAssertion() == "" &&
		req.GetClientAttestation() == "" && req.GetClientAttestationPop() == "" &&
		req.GetTlsClientCert() == "" {
		client, err := s.clients.Get(ctx, req.GetClientId())
		if err != nil {
			log.Println("grpc client authentication: unable to retrieve client:", err)
			return &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidClient().Build(),
			}, nil
		}
		if client.GetClientType() != clientv1.ClientType_CLIENT_TYPE_PUBLIC {
			log.Println("grpc client authentication: missing client credentials")
			return &clientv1.AuthenticateResponse{
				Error: rfcerrors.InvalidClient().Build(),
			}, nil
		}
		return &clientv1.AuthenticateResponse{
			Client: client,
		}, nil
	}

	// Credential path: resolve the applicable processor from the inputs.
	authenticator, methodID, ok := s.procs.Select(ctx, s.clients,
		req.GetClientAssertionType(), req.GetClientAttestation(), req.GetClientAttestationPop(),
		req.GetTlsClientCert(), req.GetClientId())
	if !ok {
		return &clientv1.AuthenticateResponse{
			Error: rfcerrors.InvalidRequest().Build(),
		}, nil
	}

	res, err := authenticator.Authenticate(ctx, req)
	if err != nil {
		log.Println("grpc client authentication:", err)
	}
	if res == nil {
		return nil, status.Error(codes.Internal, "no response")
	}

	// Enforce the application-type profile, when the resolved client
	// carries a known application type: the resolved authentication method
	// must be part of the profile's token-endpoint auth methods.
	if res.GetClient() != nil {
		if prof, okProfile := s.profiles.ApplicationType(res.GetClient().GetApplicationType()); okProfile {
			if !prof.TokenEndpointAuthMethodsSupported().Contains(methodID) {
				return &clientv1.AuthenticateResponse{
					Error: rfcerrors.InvalidClient().Build(),
				}, nil
			}
		}
	}

	return res, nil
}
