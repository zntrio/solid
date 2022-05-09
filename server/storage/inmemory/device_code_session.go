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

type deviceCodeSessionStorage struct {
	userCodeIndex   *cache.Cache
	deviceCodeIndex *cache.Cache
}

// DeviceCodeSessions returns a device authorization session manager.
func DeviceCodeSessions() storage.DeviceCodeSession {
	// Initialize in-memory caches
	userCodeCache := cache.New(2*time.Minute, 10*time.Minute)
	deviceCodeCache := cache.New(2*time.Minute, 10*time.Minute)

	return &deviceCodeSessionStorage{
		userCodeIndex:   userCodeCache,
		deviceCodeIndex: deviceCodeCache,
	}
}

// -----------------------------------------------------------------------------

func (s *deviceCodeSessionStorage) Register(ctx context.Context, issuer, userCode string, req *corev1.DeviceCodeSession) (uint64, error) {
	// Insert in cache
	s.userCodeIndex.Set(s.deriveUserCode(req.Issuer, userCode), req, cache.DefaultExpiration)
	s.deviceCodeIndex.Set(s.deriveDeviceCode(req.Issuer, req.DeviceCode), req, cache.DefaultExpiration)

	// No error
	return uint64(120), nil
}

func (s *deviceCodeSessionStorage) Delete(ctx context.Context, issuer, code string) error {
	s.userCodeIndex.Delete(s.deriveUserCode(issuer, code))
	// No error
	return nil
}

func (s *deviceCodeSessionStorage) GetByDeviceCode(ctx context.Context, issuer, deviceCode string) (*corev1.DeviceCodeSession, error) {
	// Retrieve from cache
	if x, found := s.deviceCodeIndex.Get(s.deriveDeviceCode(issuer, deviceCode)); found {
		req := x.(*corev1.DeviceCodeSession)
		return req, nil
	}

	return nil, storage.ErrNotFound
}

func (s *deviceCodeSessionStorage) GetByUserCode(ctx context.Context, issuer, userCode string) (*corev1.DeviceCodeSession, error) {
	// Retrieve from cache
	if x, found := s.userCodeIndex.Get(s.deriveUserCode(issuer, userCode)); found {
		req := x.(*corev1.DeviceCodeSession)
		return req, nil
	}

	return nil, storage.ErrNotFound
}

func (s *deviceCodeSessionStorage) Validate(ctx context.Context, issuer, userCode string, req *corev1.DeviceCodeSession) error {
	// Insert in cache
	s.userCodeIndex.Set(s.deriveUserCode(req.Issuer, userCode), req, cache.DefaultExpiration)
	s.deviceCodeIndex.Set(s.deriveDeviceCode(req.Issuer, req.DeviceCode), req, cache.DefaultExpiration)

	// No error
	return nil
}

// -----------------------------------------------------------------------------

func (s *deviceCodeSessionStorage) deriveUserCode(issuer, code string) string {
	// Create hasher
	h, err := blake2b.New256([]byte(`bA(0Kq#UT>42Va[MEFs[M%owo8|jiTbf!SVr1h0RaT~$a6?L\rqeB$q>fSDLz0:`))
	if err != nil {
		panic(err)
	}

	h.Write([]byte("solid:device-authorization-user-code:v1"))
	h.Write([]byte(issuer))
	h.Write([]byte(code))

	return fmt.Sprintf("%x", h.Sum(nil))
}

func (s *deviceCodeSessionStorage) deriveDeviceCode(issuer, code string) string {
	// Create hasher
	h, err := blake2b.New256([]byte(`bA(0Kq#UT>42Va[MEFs[M%owo8|jiTbf!SVr1h0RaT~$a6?L\rqeB$q>fSDLz0:`))
	if err != nil {
		panic(err)
	}

	h.Write([]byte("solid:device-authorization-device-code:v1"))
	h.Write([]byte(issuer))
	h.Write([]byte(code))

	return fmt.Sprintf("%x", h.Sum(nil))
}
