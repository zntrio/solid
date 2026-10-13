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

	"google.golang.org/protobuf/proto"

	sessionv1 "zntr.io/solid/api/oidc/session/v1"
	"zntr.io/solid/server/storage"
)

type AuthorizationCodeSessionStorage struct {
	backend *ttlCache
	derive  *deriveHasher
}

// AuthorizationCodeSessions returns an authorization session manager.
func AuthorizationCodeSessions(secretKey []byte) *AuthorizationCodeSessionStorage {
	// Initialize in-memory caches
	backendCache := newTTLCache(1 * time.Minute)

	return &AuthorizationCodeSessionStorage{
		backend: backendCache,
		derive:  newDeriveHasher(secretKey),
	}
}

// Stop terminates the background janitor goroutine. Calling Stop more than
// once is safe and cheap.
func (s *AuthorizationCodeSessionStorage) Stop() {
	s.backend.Stop()
}

// -----------------------------------------------------------------------------

func (s *AuthorizationCodeSessionStorage) Register(ctx context.Context, issuer, code string, req *sessionv1.AuthorizationCodeSession) (uint64, error) {
	// Insert in cache
	s.backend.Set(s.deriveKey(issuer, code), req)

	// No error
	return uint64(60), nil
}

func (s *AuthorizationCodeSessionStorage) Delete(ctx context.Context, issuer, code string) error {
	s.backend.Delete(s.deriveKey(issuer, code))
	// No error
	return nil
}

func (s *AuthorizationCodeSessionStorage) Get(ctx context.Context, issuer, code string) (*sessionv1.AuthorizationCodeSession, error) {
	// Retrieve from cache
	if x, found := s.backend.Get(s.deriveKey(issuer, code)); found {
		req := x.(*sessionv1.AuthorizationCodeSession)
		return req, nil
	}

	return nil, storage.ErrNotFound
}

func (s *AuthorizationCodeSessionStorage) DeleteAndGet(ctx context.Context, issuer, code string) (*sessionv1.AuthorizationCodeSession, error) {
	// Atomically consume the code session from cache. The returned session is
	// a detached clone stamped with the terminal CONSUMED status (defense in
	// depth on top of the sdk/session state machine: a CONSUMED session can
	// never be re-registered as a fresh ACTIVE one).
	if x, found := s.backend.DeleteAndGet(s.deriveKey(issuer, code)); found {
		session := proto.Clone(x.(*sessionv1.AuthorizationCodeSession)).(*sessionv1.AuthorizationCodeSession)
		session.Status = sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED
		return session, nil
	}

	return nil, storage.ErrNotFound
}

// -----------------------------------------------------------------------------

func (s *AuthorizationCodeSessionStorage) deriveKey(issuer, code string) string {
	return s.derive.deriveHex("solid:authorization-code-sessions:v1", issuer, code)
}
