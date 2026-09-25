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
	"google.golang.org/protobuf/proto"

	sessionv1 "zntr.io/solid/api/oidc/session/v1"
	"zntr.io/solid/server/storage"
)

type sessionStorage struct {
	backend   *ttlCache
	secretKey []byte
}

// AuthorizationCodeSessions returns an authorization session manager.
func AuthorizationCodeSessions(secretKey []byte) storage.AuthorizationCodeSession {
	// Initialize in-memory caches
	backendCache := newTTLCache(1 * time.Minute)

	return &sessionStorage{
		backend:   backendCache,
		secretKey: secretKey,
	}
}

// -----------------------------------------------------------------------------

func (s *sessionStorage) Register(ctx context.Context, issuer, code string, req *sessionv1.AuthorizationCodeSession) (uint64, error) {
	// Insert in cache
	s.backend.Set(s.deriveKey(issuer, code), req)

	// No error
	return uint64(60), nil
}

func (s *sessionStorage) Delete(ctx context.Context, issuer, code string) error {
	s.backend.Delete(s.deriveKey(issuer, code))
	// No error
	return nil
}

func (s *sessionStorage) Get(ctx context.Context, issuer, code string) (*sessionv1.AuthorizationCodeSession, error) {
	// Retrieve from cache
	if x, found := s.backend.Get(s.deriveKey(issuer, code)); found {
		req := x.(*sessionv1.AuthorizationCodeSession)
		return req, nil
	}

	return nil, storage.ErrNotFound
}

func (s *sessionStorage) DeleteAndGet(ctx context.Context, issuer, code string) (*sessionv1.AuthorizationCodeSession, error) {
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

func (s *sessionStorage) deriveKey(issuer, code string) string {
	// Create hasher
	h, err := blake2b.New256(s.secretKey)
	if err != nil {
		panic(err)
	}

	h.Write([]byte("solid:authorization-code-sessions:v1"))
	h.Write([]byte(issuer))
	h.Write([]byte(code))

	return fmt.Sprintf("%x", h.Sum(nil))
}
