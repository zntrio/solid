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
	"time"

	"github.com/dchest/uniuri"
	"github.com/patrickmn/go-cache"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/server/storage"
)

type sessionStorage struct {
	backend *cache.Cache
}

// AuthorizationCodeSessions returns an authorization session manager.
func AuthorizationCodeSessions() storage.AuthorizationCodeSession {
	// Initialize in-memory caches
	backendCache := cache.New(1*time.Minute, 10*time.Minute)

	return &sessionStorage{
		backend: backendCache,
	}
}

// -----------------------------------------------------------------------------

func (s *sessionStorage) Register(ctx context.Context, req *corev1.AuthorizationCodeSession) (string, uint64, error) {
	// Authorization Code Generator
	code := uniuri.NewLen(32)

	// Insert in cache
	s.backend.Set(code, req, cache.DefaultExpiration)

	// No error
	return code, uint64(60), nil
}

func (s *sessionStorage) Delete(ctx context.Context, code string) error {
	s.backend.Delete(code)
	// No error
	return nil
}

func (s *sessionStorage) Get(ctx context.Context, code string) (*corev1.AuthorizationCodeSession, error) {
	// Retrieve from cache
	if x, found := s.backend.Get(code); found {
		req := x.(*corev1.AuthorizationCodeSession)
		return req, nil
	}

	return nil, storage.ErrNotFound
}
