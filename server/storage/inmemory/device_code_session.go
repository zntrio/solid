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
	"errors"
	"fmt"
	"time"

	"github.com/dchest/uniuri"
	"github.com/patrickmn/go-cache"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/sdk/generator"
	"zntr.io/solid/server/storage"
)

type deviceCodeSessionStorage struct {
	userCodeIndex   *cache.Cache
	deviceCodeIndex *cache.Cache
	userCodes       generator.DeviceUserCode
}

// DeviceCodeSessions returns a device authorization session manager.
func DeviceCodeSessions(userCodes generator.DeviceUserCode) storage.DeviceCodeSession {
	// Initialize in-memory caches
	userCodeCache := cache.New(2*time.Minute, 10*time.Minute)
	deviceCodeCache := cache.New(2*time.Minute, 10*time.Minute)

	return &deviceCodeSessionStorage{
		userCodes:       userCodes,
		userCodeIndex:   userCodeCache,
		deviceCodeIndex: deviceCodeCache,
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
	req.ExpiresAt = uint64(time.Now().Add(120 * time.Second).Unix())
	req.Status = corev1.DeviceCodeStatus_DEVICE_CODE_STATUS_AUTHORIZATION_PENDING

	// Insert in cache
	s.userCodeIndex.Set(userCode, req, cache.DefaultExpiration)
	s.deviceCodeIndex.Set(deviceCode, req, cache.DefaultExpiration)

	// No error
	return deviceCode, userCode, uint64(120), nil
}

func (s *deviceCodeSessionStorage) Delete(ctx context.Context, code string) error {
	s.userCodeIndex.Delete(code)
	// No error
	return nil
}

func (s *deviceCodeSessionStorage) GetByDeviceCode(ctx context.Context, deviceCode string) (*corev1.DeviceCodeSession, error) {
	// Retrieve from cache
	if x, found := s.deviceCodeIndex.Get(deviceCode); found {
		req := x.(*corev1.DeviceCodeSession)
		return req, nil
	}

	return nil, storage.ErrNotFound
}

func (s *deviceCodeSessionStorage) GetByUserCode(ctx context.Context, userCode string) (*corev1.DeviceCodeSession, error) {
	// Retrieve from cache
	if x, found := s.userCodeIndex.Get(userCode); found {
		req := x.(*corev1.DeviceCodeSession)
		return req, nil
	}

	return nil, storage.ErrNotFound
}

func (s *deviceCodeSessionStorage) Authorize(ctx context.Context, userCode, subject string) error {
	// Check arguments
	if userCode == "" {
		return errors.New("unable to proceed with blank user_code")
	}
	if subject == "" {
		return errors.New("unable to proceed with blank subject")
	}

	// Get by user code
	session, err := s.GetByUserCode(ctx, userCode)
	if err != nil {
		return err
	}

	// Update user sndex
	session.Status = corev1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED
	session.Subject = subject

	// Insert in cache
	s.userCodeIndex.Set(userCode, session, cache.DefaultExpiration)
	s.deviceCodeIndex.Set(session.DeviceCode, session, cache.DefaultExpiration)

	// No error
	return nil
}
