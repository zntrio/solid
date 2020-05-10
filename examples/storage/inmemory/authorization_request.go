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

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
	"go.zenithar.org/solid/pkg/storage"

	"github.com/allegro/bigcache"
	"github.com/dchest/uniuri"
	"google.golang.org/protobuf/proto"
)

type authorizationRequestStorage struct {
	backend *bigcache.BigCache
}

// AuthorizationRequests returns an authorization request manager.
func AuthorizationRequests() storage.AuthorizationRequest {
	// Initialize in-memory caches
	backendCache, err := bigcache.NewBigCache(bigcache.DefaultConfig(2 * time.Minute))
	if err != nil {
		panic(err)
	}

	return &authorizationRequestStorage{
		backend: backendCache,
	}
}

// -----------------------------------------------------------------------------

func (s *authorizationRequestStorage) Register(ctx context.Context, req *corev1.AuthorizationRequest) (string, error) {
	// Generate request uri
	requestURI := fmt.Sprintf("urn:solid:%s", uniuri.NewLen(32))

	// Marshall proto
	body, err := proto.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("unable to marshal authorization request: %w", err)
	}

	// Insert in cache
	if err := s.backend.Set(requestURI, body); err != nil {
		return "", fmt.Errorf("unable to set authorization request cache: %w", err)
	}

	// No error
	return requestURI, nil
}

func (s *authorizationRequestStorage) Delete(ctx context.Context, requestURI string) error {
	if err := s.backend.Delete(requestURI); err != nil {
		return fmt.Errorf("unable to remove '%s': %w", requestURI, err)
	}

	// No error
	return nil
}

func (s *authorizationRequestStorage) Get(ctx context.Context, requestURI string) (*corev1.AuthorizationRequest, error) {
	// Retrieve from cache
	body, err := s.backend.Get(requestURI)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve '%s' from cache: %w", requestURI, err)
	}

	// Unmarshal message
	var m corev1.AuthorizationRequest
	if err := proto.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("unable to unmarshal '%s' from cache: %w", requestURI, err)
	}

	// No error
	return &m, nil
}
