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
	"testing"

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/server/storage"
)

func Test_tokenStorage(t *testing.T) {
	ctx := context.Background()

	t.Run("same instance round-trips by value", func(t *testing.T) {
		s := Tokens([]byte("0123456789abcdef0123456789abcdef"))
		tok := &tokenv1.Token{
			TokenId: "id-1",
			Value:   "value-1",
			Status:  tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
			Issuer:  "https://honest.as.example",
		}
		if err := s.Create(ctx, "https://honest.as.example", tok); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		got, err := s.GetByValue(ctx, "https://honest.as.example", "value-1")
		if err != nil {
			t.Fatalf("GetByValue() error = %v", err)
		}
		if got.TokenId != "id-1" {
			t.Errorf("GetByValue() = %v, want id-1", got)
		}
	})

	t.Run("different keys index independently", func(t *testing.T) {
		s1 := Tokens([]byte("0123456789abcdef0123456789abcdef"))
		s2 := Tokens([]byte("fedcba9876543210fedcba9876543210"))
		tok := &tokenv1.Token{
			TokenId: "id-2",
			Value:   "value-2",
			Status:  tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
			Issuer:  "https://honest.as.example",
		}
		if err := s1.Create(ctx, "https://honest.as.example", tok); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		if _, err := s2.GetByValue(ctx, "https://honest.as.example", "value-2"); err != storage.ErrNotFound {
			t.Errorf("GetByValue() across differently-keyed instances: err = %v, want ErrNotFound", err)
		}
	})

	t.Run("missing token returns ErrNotFound", func(t *testing.T) {
		s := Tokens([]byte("0123456789abcdef0123456789abcdef"))
		if _, err := s.GetByValue(ctx, "https://honest.as.example", "nope"); err != storage.ErrNotFound {
			t.Errorf("GetByValue() err = %v, want ErrNotFound", err)
		}
	})
}
