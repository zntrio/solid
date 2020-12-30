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

	"github.com/patrickmn/go-cache"

	"zntr.io/solid/pkg/server/storage"
)

type proofCache struct {
	backend *cache.Cache
}

// DPoPProofs returns an dpop proof cache.
func DPoPProofs() storage.DPoP {
	// Initialize in-memory caches
	backendCache := cache.New(1*time.Minute, 10*time.Minute)

	return &proofCache{
		backend: backendCache,
	}
}

// -----------------------------------------------------------------------------

func (s *proofCache) Register(ctx context.Context, id string) error {
	// Insert in cache
	s.backend.Set(id, id, cache.DefaultExpiration)
	// No error
	return nil
}

func (s *proofCache) Delete(ctx context.Context, id string) error {
	s.backend.Delete(id)
	// No error
	return nil
}

func (s *proofCache) Exists(ctx context.Context, id string) (bool, error) {
	// Retrieve from cache
	if _, found := s.backend.Get(id); found {
		return found, nil
	}
	return false, nil
}
