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

	"golang.org/x/crypto/blake2b"
	"google.golang.org/protobuf/proto"

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/server/storage"
)

type tokenStorage struct {
	idIndex    sync.Map
	valueIndex sync.Map
}

// Tokens returns a token manager.
func Tokens() storage.Token {
	return &tokenStorage{
		idIndex:    sync.Map{},
		valueIndex: sync.Map{},
	}
}

// -----------------------------------------------------------------------------

func (s *tokenStorage) Create(ctx context.Context, issuer string, t *tokenv1.Token) error {
	// Check parameters
	if t == nil {
		return fmt.Errorf("unable to store nil token")
	}

	// Clone the token object
	tCopy := proto.Clone(t).(*tokenv1.Token)

	// Compute token value hash
	tCopy.Value = s.deriveValue(issuer, tCopy.Value)

	s.idIndex.Store(tCopy.TokenId, tCopy)
	s.valueIndex.Store(tCopy.Value, tCopy)

	// No error
	return nil
}

func (s *tokenStorage) Get(ctx context.Context, issuer, id string) (*tokenv1.Token, error) {
	// Check is client exists
	client, ok := s.idIndex.Load(id)
	if !ok {
		return nil, storage.ErrNotFound
	}

	// No error
	return client.(*tokenv1.Token), nil
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

func (s *tokenStorage) Delete(ctx context.Context, issuer, id string) error {
	// Retrieve token
	t, err := s.Get(ctx, issuer, id)
	if err != nil {
		return err
	}

	s.idIndex.Delete(t.TokenId)
	s.valueIndex.Delete(t.Value)

	// No error
	return nil
}

func (s *tokenStorage) Revoke(ctx context.Context, issuer, id string) error {
	// Retrieve token
	t, err := s.Get(ctx, issuer, id)
	if err != nil {
		return err
	}

	// Set as revoked
	t.Status = tokenv1.TokenStatus_TOKEN_STATUS_REVOKED

	// Update maps
	s.idIndex.Store(t.TokenId, t)
	s.valueIndex.Store(t.Value, t)

	// No error
	return nil
}

// -----------------------------------------------------------------------------

func (s *tokenStorage) deriveValue(issuer, value string) string {
	// Create hasher
	h, err := blake2b.New256([]byte(`%JwQL_C=w^R@9?{J,=;LHe=&n0L1P{QrS=MsA}7H]V3fHd8&$noL&"hZH;&Uw)3`))
	if err != nil {
		panic(err)
	}

	h.Write([]byte("solid:token:v1"))
	h.Write([]byte(issuer))
	h.Write([]byte(value))

	return fmt.Sprintf("%x", h.Sum(nil))
}
