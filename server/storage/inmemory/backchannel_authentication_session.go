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

type backchannelAuthenticationSessionStorage struct {
	authReqIDIndex *ttlCache
	secretKey      []byte
}

// BackchannelAuthenticationSessions returns a backchannel authentication
// session manager (OpenID CIBA Core 1.0).
func BackchannelAuthenticationSessions(secretKey []byte) storage.BackchannelAuthenticationSession {
	// The cache TTL only bounds storage residency: it must outlive the
	// protocol-level expiry (session.ExpiresAt) so the token grant can
	// distinguish an expired session (expired_token, CIBA section 11)
	// from a purged one.
	authReqIDCache := newTTLCache(10 * time.Minute)

	return &backchannelAuthenticationSessionStorage{
		authReqIDIndex: authReqIDCache,
		secretKey:      secretKey,
	}
}

// -----------------------------------------------------------------------------

func (s *backchannelAuthenticationSessionStorage) Register(ctx context.Context, issuer, authReqID string, req *sessionv1.BackchannelAuthenticationSession) (uint64, error) {
	// Insert in cache
	s.authReqIDIndex.Set(s.deriveAuthReqID(req.Issuer, authReqID), req)

	// No error
	return uint64(120), nil
}

// Delete purges the session from the end-user approval channel: the
// auth_req_id index survives so the client's token-endpoint poll can still
// resolve and consume the session (mirroring the device storage, where the
// user-code index is dropped but the device-code index persists until the
// grant consumes it).
func (s *backchannelAuthenticationSessionStorage) Delete(ctx context.Context, issuer, authReqID string) error {
	// No error
	return nil
}

func (s *backchannelAuthenticationSessionStorage) GetByAuthReqID(ctx context.Context, issuer, authReqID string) (*sessionv1.BackchannelAuthenticationSession, error) {
	// Retrieve from cache
	if x, found := s.authReqIDIndex.Get(s.deriveAuthReqID(issuer, authReqID)); found {
		req := x.(*sessionv1.BackchannelAuthenticationSession)
		return req, nil
	}

	return nil, storage.ErrNotFound
}

func (s *backchannelAuthenticationSessionStorage) Validate(ctx context.Context, issuer, authReqID string, req *sessionv1.BackchannelAuthenticationSession) error {
	// Insert in cache
	s.authReqIDIndex.Set(s.deriveAuthReqID(req.Issuer, authReqID), req)

	// No error
	return nil
}

// UpdateByAuthReqID persists a mutated backchannel authentication session
// (poll timing state).
func (s *backchannelAuthenticationSessionStorage) UpdateByAuthReqID(ctx context.Context, issuer, authReqID string, r *sessionv1.BackchannelAuthenticationSession) error {
	s.authReqIDIndex.Set(s.deriveAuthReqID(issuer, authReqID), r)
	return nil
}

// DeleteAndGetByAuthReqID atomically consumes a validated backchannel
// authentication session, enforcing one-time use of the auth_req_id.
func (s *backchannelAuthenticationSessionStorage) DeleteAndGetByAuthReqID(ctx context.Context, issuer, authReqID string) (*sessionv1.BackchannelAuthenticationSession, error) {
	if x, ok := s.authReqIDIndex.DeleteAndGet(s.deriveAuthReqID(issuer, authReqID)); ok {
		return x.(*sessionv1.BackchannelAuthenticationSession), nil
	}
	return nil, storage.ErrNotFound
}

// -----------------------------------------------------------------------------

func (s *backchannelAuthenticationSessionStorage) deriveAuthReqID(issuer, authReqID string) string {
	// Create hasher
	h, err := blake2b.New256(s.secretKey)
	if err != nil {
		panic(err)
	}

	h.Write([]byte("solid:backchannel-authentication-auth-req-id:v1"))
	h.Write([]byte(issuer))
	h.Write([]byte(authReqID))

	return fmt.Sprintf("%x", h.Sum(nil))
}
