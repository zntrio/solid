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

type sessionStorage struct {
	backend *bigcache.BigCache
}

// Sessions returns an authorization session manager.
func Sessions() storage.Session {
	// Initialize in-memory caches
	backendCache, err := bigcache.NewBigCache(bigcache.DefaultConfig(30 * time.Second))
	if err != nil {
		panic(err)
	}

	return &sessionStorage{
		backend: backendCache,
	}
}

// -----------------------------------------------------------------------------

func (s *sessionStorage) Register(ctx context.Context, req *corev1.Session) (string, error) {
	// Authorization Code Generator
	code := uniuri.NewLen(16)

	// Marshall proto
	body, err := proto.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("unable to marshal authorization session: %w", err)
	}

	// Insert in cache
	if err := s.backend.Set(code, body); err != nil {
		return "", fmt.Errorf("unable to set authorization session cache: %w", err)
	}

	// No error
	return code, nil
}

func (s *sessionStorage) Delete(ctx context.Context, code string) error {
	if err := s.backend.Delete(code); err != nil {
		return fmt.Errorf("unable to remove '%s': %w", code, err)
	}

	// No error
	return nil
}

func (s *sessionStorage) Get(ctx context.Context, code string) (*corev1.Session, error) {
	// Retrieve from cache
	body, err := s.backend.Get(code)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve '%s' from cache: %w", code, err)
	}

	// Unmarshal message
	var m corev1.Session
	if err := proto.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("unable to unmarshal '%s' from cache: %w", code, err)
	}

	// No error
	return &m, nil
}
