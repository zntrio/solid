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

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
	"go.zenithar.org/solid/pkg/storage"
)

type tokenStorage struct {
	idIndex    map[string]*corev1.Token
	valueIndex map[string]*corev1.Token
	mutex      sync.RWMutex
}

// Tokens returns a token manager.
func Tokens() storage.Token {
	return &tokenStorage{
		idIndex:    map[string]*corev1.Token{},
		valueIndex: map[string]*corev1.Token{},
	}
}

// -----------------------------------------------------------------------------

func (s *tokenStorage) Create(ctx context.Context, t *corev1.Token) error {
	// Check parameters
	if t == nil {
		return fmt.Errorf("unable to store nil token")
	}

	s.mutex.Lock()
	s.idIndex[t.TokenId] = t
	s.valueIndex[t.Value] = t
	s.mutex.Unlock()

	// No error
	return nil
}

func (s *tokenStorage) Get(ctx context.Context, id string) (*corev1.Token, error) {
	// Check is client exists
	client, ok := s.idIndex[id]
	if !ok {
		return nil, storage.ErrNotFound
	}

	// No error
	return client, nil
}

func (s *tokenStorage) GetByValue(ctx context.Context, value string) (*corev1.Token, error) {
	// Check is client exists
	client, ok := s.valueIndex[value]
	if !ok {
		return nil, storage.ErrNotFound
	}

	// No error
	return client, nil
}

func (s *tokenStorage) Delete(ctx context.Context, id string) error {

	// Retrieve token
	t, err := s.Get(ctx, id)
	if err != nil {
		return err
	}

	s.mutex.Lock()
	delete(s.idIndex, t.TokenId)
	delete(s.idIndex, t.Value)
	s.mutex.Unlock()

	// No error
	return nil
}

func (s *tokenStorage) Revoke(ctx context.Context, id string) error {
	// Retrieve token
	t, err := s.Get(ctx, id)
	if err != nil {
		return err
	}

	// Set as revoked
	t.Status = corev1.TokenStatus_TOKEN_STATUS_REVOKED

	// Update maps
	s.mutex.Lock()
	s.idIndex[t.TokenId] = t
	s.valueIndex[t.Value] = t
	s.mutex.Unlock()

	// No error
	return nil
}
