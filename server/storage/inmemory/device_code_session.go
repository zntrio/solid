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

	"golang.org/x/crypto/blake2b"

	sessionv1 "zntr.io/solid/api/oidc/session/v1"
	"zntr.io/solid/server/storage"
)

type deviceCodeSessionStorage struct {
	userCodeIndex   *ttlCache
	deviceCodeIndex *ttlCache
	secretKey       []byte
}

// DeviceCodeSessions returns a device authorization session manager.
func DeviceCodeSessions(secretKey []byte) storage.DeviceCodeSession {
	// The cache TTL only bounds storage residency: it must outlive the
	// protocol-level expiry (session.ExpiresAt) so the token grant can
	// distinguish an expired session (expired_token, RFC 8628 section
	// 3.5) from a purged one.
	userCodeCache := newTTLCache(10 * time.Minute)
	deviceCodeCache := newTTLCache(10 * time.Minute)

	return &deviceCodeSessionStorage{
		userCodeIndex:   userCodeCache,
		deviceCodeIndex: deviceCodeCache,
		secretKey:       secretKey,
	}
}

// -----------------------------------------------------------------------------

func (s *deviceCodeSessionStorage) Register(ctx context.Context, issuer, userCode string, req *sessionv1.DeviceCodeSession) (uint64, error) {
	// Insert in cache
	s.userCodeIndex.Set(s.deriveUserCode(req.Issuer, userCode), req)
	s.deviceCodeIndex.Set(s.deriveDeviceCode(req.Issuer, req.DeviceCode), req)

	// No error
	return uint64(120), nil
}

func (s *deviceCodeSessionStorage) Delete(ctx context.Context, issuer, code string) error {
	s.userCodeIndex.Delete(s.deriveUserCode(issuer, code))
	// No error
	return nil
}

func (s *deviceCodeSessionStorage) GetByDeviceCode(ctx context.Context, issuer, deviceCode string) (*sessionv1.DeviceCodeSession, error) {
	// Retrieve from cache
	if x, found := s.deviceCodeIndex.Get(s.deriveDeviceCode(issuer, deviceCode)); found {
		req := x.(*sessionv1.DeviceCodeSession)
		return req, nil
	}

	return nil, storage.ErrNotFound
}

func (s *deviceCodeSessionStorage) GetByUserCode(ctx context.Context, issuer, userCode string) (*sessionv1.DeviceCodeSession, error) {
	// Retrieve from cache
	if x, found := s.userCodeIndex.Get(s.deriveUserCode(issuer, userCode)); found {
		req := x.(*sessionv1.DeviceCodeSession)
		return req, nil
	}

	return nil, storage.ErrNotFound
}

func (s *deviceCodeSessionStorage) Validate(ctx context.Context, issuer, userCode string, req *sessionv1.DeviceCodeSession) error {
	// Insert in cache
	s.userCodeIndex.Set(s.deriveUserCode(req.Issuer, userCode), req)
	s.deviceCodeIndex.Set(s.deriveDeviceCode(req.Issuer, req.DeviceCode), req)

	// No error
	return nil
}

// UpdateByDeviceCode persists a mutated device code session (poll timing state).
func (s *deviceCodeSessionStorage) UpdateByDeviceCode(ctx context.Context, issuer, deviceCode string, r *sessionv1.DeviceCodeSession) error {
	// Both indexes hold the same *sessionv1.DeviceCodeSession pointer; the
	// user-code index sees the mutation through the shared pointer. The
	// user-code index key is not recoverable from the session, so only the
	// device-code index needs re-keying here.
	s.deviceCodeIndex.Set(s.deriveDeviceCode(issuer, deviceCode), r)
	return nil
}

// DeleteAndGetByDeviceCode atomically consumes a validated device code session,
// enforcing one-time use (RFC 10027 section 6.1.3).
func (s *deviceCodeSessionStorage) DeleteAndGetByDeviceCode(ctx context.Context, issuer, deviceCode string) (*sessionv1.DeviceCodeSession, error) {
	if x, ok := s.deviceCodeIndex.DeleteAndGet(s.deriveDeviceCode(issuer, deviceCode)); ok {
		return x.(*sessionv1.DeviceCodeSession), nil
	}
	return nil, storage.ErrNotFound
}

// -----------------------------------------------------------------------------

func (s *deviceCodeSessionStorage) deriveUserCode(issuer, code string) string {
	// Create hasher
	h, err := blake2b.New256(s.secretKey)
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
	h, err := blake2b.New256(s.secretKey)
	if err != nil {
		panic(err)
	}

	h.Write([]byte("solid:device-authorization-device-code:v1"))
	h.Write([]byte(issuer))
	h.Write([]byte(code))

	return fmt.Sprintf("%x", h.Sum(nil))
}
