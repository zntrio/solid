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

	sessionv1 "zntr.io/solid/api/oidc/session/v1"
	"zntr.io/solid/server/storage"
)

type DeviceCodeSessionStorage struct {
	userCodeIndex   *ttlCache
	deviceCodeIndex *ttlCache
	derive          *deriveHasher
}

// DeviceCodeSessions returns a device authorization session manager.
func DeviceCodeSessions(secretKey []byte) *DeviceCodeSessionStorage {
	// The cache TTL only bounds storage residency: it must outlive the
	// protocol-level expiry (session.ExpiresAt) so the token grant can
	// distinguish an expired session (expired_token, RFC 8628 section
	// 3.5) from a purged one.
	userCodeCache := newTTLCache(10 * time.Minute)
	deviceCodeCache := newTTLCache(10 * time.Minute)

	return &DeviceCodeSessionStorage{
		userCodeIndex:   userCodeCache,
		deviceCodeIndex: deviceCodeCache,
		derive:          newDeriveHasher(secretKey),
	}
}

// Stop terminates the background janitor goroutines. Calling Stop more than
// once is safe and cheap.
func (s *DeviceCodeSessionStorage) Stop() {
	s.userCodeIndex.Stop()
	s.deviceCodeIndex.Stop()
}

// -----------------------------------------------------------------------------

func (s *DeviceCodeSessionStorage) Register(ctx context.Context, issuer, userCode string, req *sessionv1.DeviceCodeSession) (uint64, error) {
	// Insert in cache
	s.userCodeIndex.Set(s.deriveUserCode(req.Issuer, userCode), req)
	s.deviceCodeIndex.Set(s.deriveDeviceCode(req.Issuer, req.DeviceCode), req)

	// No error
	return uint64(120), nil
}

func (s *DeviceCodeSessionStorage) Delete(ctx context.Context, issuer, code string) error {
	s.userCodeIndex.Delete(s.deriveUserCode(issuer, code))
	// No error
	return nil
}

func (s *DeviceCodeSessionStorage) GetByDeviceCode(ctx context.Context, issuer, deviceCode string) (*sessionv1.DeviceCodeSession, error) {
	// Retrieve from cache
	if x, found := s.deviceCodeIndex.Get(s.deriveDeviceCode(issuer, deviceCode)); found {
		req := x.(*sessionv1.DeviceCodeSession)
		return req, nil
	}

	return nil, storage.ErrNotFound
}

func (s *DeviceCodeSessionStorage) GetByUserCode(ctx context.Context, issuer, userCode string) (*sessionv1.DeviceCodeSession, error) {
	// Retrieve from cache
	if x, found := s.userCodeIndex.Get(s.deriveUserCode(issuer, userCode)); found {
		req := x.(*sessionv1.DeviceCodeSession)
		return req, nil
	}

	return nil, storage.ErrNotFound
}

func (s *DeviceCodeSessionStorage) Validate(ctx context.Context, issuer, userCode string, req *sessionv1.DeviceCodeSession) error {
	// Insert in cache
	s.userCodeIndex.Set(s.deriveUserCode(req.Issuer, userCode), req)
	s.deviceCodeIndex.Set(s.deriveDeviceCode(req.Issuer, req.DeviceCode), req)

	// No error
	return nil
}

// UpdateByDeviceCode persists a mutated device code session (poll timing state).
func (s *DeviceCodeSessionStorage) UpdateByDeviceCode(ctx context.Context, issuer, deviceCode string, r *sessionv1.DeviceCodeSession) error {
	// Both indexes hold the same *sessionv1.DeviceCodeSession pointer; the
	// user-code index sees the mutation through the shared pointer. The
	// user-code index key is not recoverable from the session, so only the
	// device-code index needs re-keying here.
	s.deviceCodeIndex.Set(s.deriveDeviceCode(issuer, deviceCode), r)
	return nil
}

// DeleteAndGetByDeviceCode atomically consumes a validated device code session,
// enforcing one-time use (RFC 10027 section 6.1.3).
func (s *DeviceCodeSessionStorage) DeleteAndGetByDeviceCode(ctx context.Context, issuer, deviceCode string) (*sessionv1.DeviceCodeSession, error) {
	if x, ok := s.deviceCodeIndex.DeleteAndGet(s.deriveDeviceCode(issuer, deviceCode)); ok {
		return x.(*sessionv1.DeviceCodeSession), nil
	}
	return nil, storage.ErrNotFound
}

// -----------------------------------------------------------------------------

func (s *DeviceCodeSessionStorage) deriveUserCode(issuer, code string) string {
	return s.derive.deriveHex("solid:device-authorization-user-code:v1", issuer, code)
}

func (s *DeviceCodeSessionStorage) deriveDeviceCode(issuer, code string) string {
	return s.derive.deriveHex("solid:device-authorization-device-code:v1", issuer, code)
}
