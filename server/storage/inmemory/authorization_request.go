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

	"github.com/patrickmn/go-cache"
	"golang.org/x/crypto/blake2b"

	corev1 "zntr.io/solid/api/oidc/core/v1"
	"zntr.io/solid/server/storage"
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

func (s *authorizationRequestStorage) Register(ctx context.Context, issuer, requestURI string, req *corev1.AuthorizationRequest) (uint64, error) {
	// Insert in cache
	s.backend.Set(s.deriveKey(issuer, requestURI), req, cache.DefaultExpiration)

	// No error
	return 60, nil
}

func (s *authorizationRequestStorage) Delete(ctx context.Context, issuer, requestURI string) error {
	s.backend.Delete(s.deriveKey(issuer, requestURI))
	// No error
	return nil
}

func (s *authorizationRequestStorage) Get(ctx context.Context, issuer, requestURI string) (*corev1.AuthorizationRequest, error) {
	// Retrieve from cache
	if x, found := s.backend.Get(s.deriveKey(issuer, requestURI)); found {
		req := x.(*corev1.AuthorizationRequest)
		return req, nil
	}

	return nil, storage.ErrNotFound
}

// -----------------------------------------------------------------------------

func (s *authorizationRequestStorage) deriveKey(issuer, requestURI string) string {
	// Create hasher
	h, err := blake2b.New256([]byte("!|XH/CNMA8WSlN*;*UKL!0tW[CU17EB4A.a)[WZbvKSl;F?G#PxjijvtFWS0C=T"))
	if err != nil {
		panic(err)
	}

	h.Write([]byte("solid:authorization-requests:v1"))
	h.Write([]byte(issuer))
	h.Write([]byte(requestURI))

	return fmt.Sprintf("%x", h.Sum(nil))
}
