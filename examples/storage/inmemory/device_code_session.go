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
	"zntr.io/solid/pkg/sdk/generator"
	"zntr.io/solid/pkg/server/storage"

	"github.com/dchest/uniuri"
	"github.com/patrickmn/go-cache"
)

type deviceCodeSessionStorage struct {
	backend   *cache.Cache
	userCodes generator.DeviceUserCode
}

// DeviceCodeSessions returns a device authorization session manager.
func DeviceCodeSessions(userCodes generator.DeviceUserCode) storage.DeviceCodeSession {
	// Initialize in-memory caches
	backendCache := cache.New(2*time.Minute, 10*time.Minute)

	return &deviceCodeSessionStorage{
		userCodes: userCodes,
		backend:   backendCache,
	}
}

// -----------------------------------------------------------------------------

func (s *deviceCodeSessionStorage) Register(ctx context.Context, req *corev1.DeviceCodeSession) (string, string, uint64, error) {
	// Authorization Code Generator
	deviceCode := uniuri.NewLen(32)

	// Generate user code
	userCode, err := s.userCodes.Generate(ctx)
	if err != nil {
		return "", "", uint64(0), fmt.Errorf("unable to generate user_code: %w", err)
	}

	// Assign to session
	req.UserCode = userCode

	// Insert in cache
	s.backend.Set(userCode, req, cache.DefaultExpiration)

	// No error
	return deviceCode, userCode, uint64(60), nil
}

func (s *deviceCodeSessionStorage) Delete(ctx context.Context, code string) error {
	s.backend.Delete(code)
	// No error
	return nil
}

func (s *deviceCodeSessionStorage) Get(ctx context.Context, code string) (*corev1.DeviceCodeSession, error) {
	// Retrieve from cache
	if x, found := s.backend.Get(code); found {
		req := x.(*corev1.DeviceCodeSession)
		return req, nil
	}

	return nil, storage.ErrNotFound
}
