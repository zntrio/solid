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

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
	"go.zenithar.org/solid/api/oidc"
	"go.zenithar.org/solid/pkg/storage"
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
				},
				ResponseTypes: []string{
					"code",
				},
				RedirectUris: []string{
					"http://localhost:8080/cb",
				},
				Contacts: []string{
					"foo@bar.com",
				},
				// Authentication RSA public key
				Jwks: []byte(`{"keys": [{"kty": "EC","use": "sig","crv": "P-256","x": "h6jud8ozOJ93MvHZCxvGZnOVHLeTX-3K9LkAvKy1RSs","y": "yY0UQDLFPM8OAgkOYfotwzXCGXtBYinBk1EURJQ7ONk","alg": "ES256"}]}`),
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
