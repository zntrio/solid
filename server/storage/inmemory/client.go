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

package inmemory

import (
	"context"
	"strings"

	"github.com/dchest/uniuri"

	corev1 "zntr.io/solid/api/oidc/core/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/server/storage"
)

type clientStorage struct {
	backend map[string]*corev1.Client
}

// Clients returns a client manager.
func Clients() storage.Client {
	return &clientStorage{
		backend: map[string]*corev1.Client{
			"6779ef20e75817b79602": {
				ClientId:        "6779ef20e75817b79602",
				ClientType:      corev1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
				ApplicationType: "web",
				ClientName:      "foo-test-client",
				GrantTypes: []string{
					oidc.GrantTypeAuthorizationCode, // User interaction
					oidc.GrantTypeClientCredentials, // Machine-to-machine
					oidc.GrantTypeDeviceCode,        // Device-to-service
					oidc.GrantTypeRefreshToken,      // Act as user
					oidc.GrantTypeTokenExchange,
				},
				ResponseTypes: []string{
					"code",
				},
				ResponseModes: []string{
					oidc.ResponseModeQueryJWT,
				},
				RedirectUris: []string{
					"http://127.0.0.1:8085/oidc/as/127.0.0.1",
				},
				Contacts: []string{
					"foo@bar.com",
				},
				// Authentication RSA public key
				Jwks: []byte(`{
					"keys": [
						{
							"kid": "6779ef20e75817b79602",
							"kty": "EC",
							"use": "sig",
							"crv": "P-384",
							"x": "m2NDaWfRRGlCkUa4FK949uLtMqitX1lYgi8UCIMtsuR60ux3d00XBlsC6j_YDOTe",
							"y": "6vxuUq3V1aoWi4FQ_h9ZNwUsmcGP8Uuqq_YN5dhP0U8lchdmZJbLF9mPiimo_6p4",
							"alg": "ES384"
						}
					]
				}`),
				// Pairwise sector identitier
				SubjectType:      oidc.SubjectTypePairwise,
				SectorIdentifier: "http://127.0.0.1:8085",
			},
			"public-client": {
				ClientId:        "public-client",
				ClientType:      corev1.ClientType_CLIENT_TYPE_PUBLIC,
				ApplicationType: "cli",
				ClientName:      "cli-public-client",
				GrantTypes: []string{
					oidc.GrantTypeDeviceCode,   // Device-to-service
					oidc.GrantTypeRefreshToken, // Act as user
				},
				Contacts: []string{
					"foo@bar.com",
				},
				// Pairwise sector identitier
				SubjectType:      oidc.SubjectTypePairwise,
				SectorIdentifier: "http://127.0.0.1:8085",
			},
		},
	}
}

// -----------------------------------------------------------------------------

func (s *clientStorage) Get(ctx context.Context, id string) (*corev1.Client, error) {
	// Check is client exists
	client, ok := s.backend[id]
	if !ok {
		return nil, storage.ErrNotFound
	}

	// No error
	return client, nil
}

func (s *clientStorage) GetByName(ctx context.Context, name string) (*corev1.Client, error) {
	// Iterate over bakend map
	for _, c := range s.backend {
		if strings.EqualFold(c.ClientName, name) {
			return c, nil
		}
	}

	// Not found
	return nil, storage.ErrNotFound
}

// -----------------------------------------------------------------------------

func (s *clientStorage) Register(ctx context.Context, c *corev1.Client) (string, error) {
	// Assign client id
	c.ClientId = uniuri.NewLen(16)

	// Assign to storage
	s.backend[c.ClientId] = c

	// No error
	return c.ClientId, nil
}
