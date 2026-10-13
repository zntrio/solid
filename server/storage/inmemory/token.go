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
	"sync"

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/server/storage"
)

type tokenStorage struct {
	idIndex    sync.Map
	valueIndex sync.Map
	derive     *deriveHasher
}

// Tokens returns a token manager.
// Tokens returns an in-memory token storage keyed by the given secret key.
// This implementation is intended for examples and tests only.
func Tokens(secretKey []byte) storage.Token {
	return &tokenStorage{
		idIndex:    sync.Map{},
		valueIndex: sync.Map{},
		derive:     newDeriveHasher(secretKey),
	}
}

// -----------------------------------------------------------------------------

func (s *tokenStorage) Create(ctx context.Context, issuer string, t *tokenv1.Token) error {
	// Check parameters
	if t == nil {
		return fmt.Errorf("unable to store nil token")
	}

	// Clone the token object
	tCopy := t.CloneVT()

	// Compute token value hash
	tCopy.Value = s.deriveValue(issuer, tCopy.Value)

	s.idIndex.Store(tCopy.TokenId, tCopy)
	s.valueIndex.Store(tCopy.Value, tCopy)

	// No error
	return nil
}

func (s *tokenStorage) GetByValue(ctx context.Context, issuer, value string) (*tokenv1.Token, error) {
	// Check is client exists
	client, ok := s.valueIndex.Load(s.deriveValue(issuer, value))
	if !ok {
		return nil, storage.ErrNotFound
	}

	// No error
	return client.(*tokenv1.Token), nil
}

func (s *tokenStorage) GetByGrantID(ctx context.Context, issuer, grantID string) []*tokenv1.Token {
	// Collect every token bound to the grant family.
	result := []*tokenv1.Token{}
	s.idIndex.Range(func(_, v any) bool {
		t, ok := v.(*tokenv1.Token)
		if !ok || t.Metadata == nil || t.Metadata.GrantId != grantID {
			return true
		}
		result = append(result, t)
		return true
	})

	// No error
	return result
}

func (s *tokenStorage) GetByClientID(ctx context.Context, clientID string) []*tokenv1.Token {
	// Collect every token issued to the client.
	result := []*tokenv1.Token{}
	s.idIndex.Range(func(_, v any) bool {
		t, ok := v.(*tokenv1.Token)
		if !ok || t.Metadata == nil || t.Metadata.ClientId != clientID {
			return true
		}
		result = append(result, t)
		return true
	})

	// No error
	return result
}

func (s *tokenStorage) Revoke(ctx context.Context, issuer, id string) error {
	// Retrieve token
	x, ok := s.idIndex.Load(id)
	if !ok {
		return storage.ErrNotFound
	}
	t, ok := x.(*tokenv1.Token)
	if !ok {
		return storage.ErrNotFound
	}

	// Set as revoked
	t.Status = tokenv1.TokenStatus_TOKEN_STATUS_REVOKED

	// Update maps
	s.idIndex.Store(t.TokenId, t)
	s.valueIndex.Store(t.Value, t)

	// No error
	return nil
}

// consumeMu serializes refresh-token consumption: the compare-and-set on
// the two sync.Maps must be a single critical section (the sync.Map
// LoadOrStore primitive alone cannot guard the value→id pair transition).
var consumeMu sync.Mutex

// ConsumeIfActive atomically transitions the refresh token addressed by
// value from ACTIVE to CONSUMED (RFC 9700 section 4.14.2): a single
// critical-section compare-and-set over the value and id indexes, so two
// concurrent refresh requests presenting the same token cannot both win —
// the loser observes the CONSUMED state and reports a replay.
func (s *tokenStorage) ConsumeIfActive(ctx context.Context, issuer, value string) (*tokenv1.Token, error) {
	derived := s.deriveValue(issuer, value)

	consumeMu.Lock()
	defer consumeMu.Unlock()

	// Resolve by value.
	x, ok := s.valueIndex.Load(derived)
	if !ok {
		return nil, storage.ErrNotFound
	}
	t, ok := x.(*tokenv1.Token)
	if !ok {
		return nil, storage.ErrNotFound
	}

	// Snapshot the pre-transition state for the caller: ACTIVE means this
	// call won the race and may rotate the family.
	snapshot := t.CloneVT()

	// Compare-and-set: only an ACTIVE token transitions. An already
	// CONSUMED or REVOKED token is returned as-is (the caller reports the
	// replay / revocation outcome).
	if t.Status == tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE {
		t.Status = tokenv1.TokenStatus_TOKEN_STATUS_CONSUMED
		s.idIndex.Store(t.TokenId, t)
		s.valueIndex.Store(derived, t)
	}

	return snapshot, nil
}

// -----------------------------------------------------------------------------

func (s *tokenStorage) deriveValue(issuer, value string) string {
	return s.derive.deriveHex("solid:token:v1", issuer, value)
}
