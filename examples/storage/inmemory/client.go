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

	"github.com/golang/protobuf/ptypes/wrappers"

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
			"6779ef20e75817b79602": &corev1.Client{
				ClientId:   "6779ef20e75817b79602",
				ClientType: corev1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
				ApplicationType: &wrappers.StringValue{
					Value: "web",
				},
				ClientName: &wrappers.StringValue{
					Value: "foo-test-client",
				},
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
				Jwks: &wrappers.BytesValue{
					Value: []byte(`{"keys":[{"kty":"RSA","kid":"P5sIiu4hoe66dwCLLUZA3gnSsV7QCldlcU4NTSNoF7I=","n":"yCLi3sNbEIkHJkaIwHQfCqJ77KsiNYfy8tgjGKuXVdve317xCCnlgORUN0QpiYU04OKmUbg6MO3sJsv3qVRol0A7feWD6cfmCus9kcU4Pq26RE03Hy5h6g1G4Z08OSAa4TVdcsH2RF4c85xFRjT2Dii90HJYLXPH7un86RLC3i3ClEch5sg5hKFn0ncSZyHm_qaciGTDcC-8GOLx4w5FfD8qMIMjS_Wt5v1pe8lNewCgXPTWnGGFniq6f1dmASYHyi5BOWDiLUKC1sGL_9CXDi520hseYfe3HK9qenJPwE3hzMw6oUN5-bT3FptwAe9iIYoDpliPeHGTY56t0tcQzQ","e":"AQAB"}]}`),
				},
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
