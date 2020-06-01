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
	"fmt"
	"time"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/pkg/storage"

	"github.com/dchest/uniuri"
	"github.com/patrickmn/go-cache"
)

type authorizationRequestStorage struct {
	backend *cache.Cache
}

// AuthorizationRequests returns an authorization request manager.
func AuthorizationRequests() storage.AuthorizationRequest {
	// Initialize in-memory caches
	backendCache := cache.New(1*time.Minute, 10*time.Minute)

	return &authorizationRequestStorage{
		backend: backendCache,
	}
}

// -----------------------------------------------------------------------------

func (s *authorizationRequestStorage) Register(ctx context.Context, req *corev1.AuthorizationRequest) (string, error) {
	// Generate request uri
	requestURI := fmt.Sprintf("urn:solid:%s", uniuri.NewLen(32))

	// Insert in cache
	s.backend.Set(requestURI, req, cache.DefaultExpiration)

	// No error
	return requestURI, nil
}

func (s *authorizationRequestStorage) Delete(ctx context.Context, requestURI string) error {
	s.backend.Delete(requestURI)
	// No error
	return nil
}

func (s *authorizationRequestStorage) Get(ctx context.Context, requestURI string) (*corev1.AuthorizationRequest, error) {
	// Retrieve from cache
	if x, found := s.backend.Get(requestURI); found {
		req := x.(*corev1.AuthorizationRequest)
		return req, nil
	}

	return nil, storage.ErrNotFound
}
