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
	"errors"
	"testing"

	"go.uber.org/mock/gomock"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	cimdmock "zntr.io/solid/sdk/cimd/mock"
	"zntr.io/solid/server/storage"
	"zntr.io/solid/server/storage/mock"
)

const (
	testURLClientID     = "https://client.example.org/cimd.json"
	testNonURLClientID  = "my-registered-client"
	testPrimaryClientID = "pre-registered-client"
)

func testClient(id string) *clientv1.Client {
	return &clientv1.Client{ClientId: id}
}

func TestClientReader(t *testing.T) {
	ctx := context.Background()

	t.Run("PreRegisteredWins", func(t *testing.T) {
		primary := mock.NewMockClientReader(gomockCtrl(t))
		resolver := cimdmock.NewMockResolver(gomockCtrl(t))

		primary.EXPECT().Get(ctx, testPrimaryClientID).Return(testClient(testPrimaryClientID), nil)
		resolver.EXPECT().Resolve(ctx, testPrimaryClientID).Times(0)

		r := NewClientReader(primary, resolver)
		c, err := r.Get(ctx, testPrimaryClientID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.ClientId != testPrimaryClientID {
			t.Errorf("client_id = %q", c.ClientId)
		}
	})

	t.Run("PreRegisteredURLShapedIDWins", func(t *testing.T) {
		primary := mock.NewMockClientReader(gomockCtrl(t))
		resolver := cimdmock.NewMockResolver(gomockCtrl(t))

		// Draft section 7.1: even a URL-shaped identifier resolves from the
		// primary store when pre-registered there.
		primary.EXPECT().Get(ctx, testURLClientID).Return(testClient(testURLClientID), nil)
		resolver.EXPECT().Resolve(ctx, testURLClientID).Times(0)

		r := NewClientReader(primary, resolver)
		if _, err := r.Get(ctx, testURLClientID); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("MissURLShapedIDResolvesViaCIMD", func(t *testing.T) {
		primary := mock.NewMockClientReader(gomockCtrl(t))
		resolver := cimdmock.NewMockResolver(gomockCtrl(t))

		primary.EXPECT().Get(ctx, testURLClientID).Return(nil, storage.ErrNotFound)
		resolver.EXPECT().Resolve(ctx, testURLClientID).Return(testClient(testURLClientID), nil)

		r := NewClientReader(primary, resolver)
		c, err := r.Get(ctx, testURLClientID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.ClientId != testURLClientID {
			t.Errorf("client_id = %q", c.ClientId)
		}
	})

	t.Run("MissNonURLReturnsNotFound", func(t *testing.T) {
		primary := mock.NewMockClientReader(gomockCtrl(t))
		resolver := cimdmock.NewMockResolver(gomockCtrl(t))

		primary.EXPECT().Get(ctx, testNonURLClientID).Return(nil, storage.ErrNotFound)
		resolver.EXPECT().Resolve(ctx, testNonURLClientID).Times(0)

		r := NewClientReader(primary, resolver)
		_, err := r.Get(ctx, testNonURLClientID)
		if !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("expected storage.ErrNotFound, got %v", err)
		}
	})

	t.Run("ResolverErrorBecomesNotFound", func(t *testing.T) {
		primary := mock.NewMockClientReader(gomockCtrl(t))
		resolver := cimdmock.NewMockResolver(gomockCtrl(t))

		primary.EXPECT().Get(ctx, testURLClientID).Return(nil, storage.ErrNotFound)
		resolver.EXPECT().Resolve(ctx, testURLClientID).Return(nil, errors.New("fetch failed"))

		r := NewClientReader(primary, resolver)
		_, err := r.Get(ctx, testURLClientID)
		if !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("expected storage.ErrNotFound, got %v", err)
		}
	})

	t.Run("PrimaryNonNotFoundErrorSurfaces", func(t *testing.T) {
		primary := mock.NewMockClientReader(gomockCtrl(t))
		resolver := cimdmock.NewMockResolver(gomockCtrl(t))

		primaryErr := errors.New("database down")
		primary.EXPECT().Get(ctx, testURLClientID).Return(nil, primaryErr)
		resolver.EXPECT().Resolve(ctx, testURLClientID).Times(0)

		r := NewClientReader(primary, resolver)
		_, err := r.Get(ctx, testURLClientID)
		if !errors.Is(err, primaryErr) {
			t.Errorf("expected primary error to surface, got %v", err)
		}
	})

	t.Run("GetByNameDelegates", func(t *testing.T) {
		primary := mock.NewMockClientReader(gomockCtrl(t))
		resolver := cimdmock.NewMockResolver(gomockCtrl(t))

		primary.EXPECT().GetByName(ctx, "example").Return(testClient(testPrimaryClientID), nil)

		r := NewClientReader(primary, resolver)
		c, err := r.GetByName(ctx, "example")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.ClientId != testPrimaryClientID {
			t.Errorf("client_id = %q", c.ClientId)
		}
	})

	t.Run("ImplementsClientReader", func(t *testing.T) {
		var _ storage.ClientReader = NewClientReader(mock.NewMockClientReader(gomockCtrl(t)), cimdmock.NewMockResolver(gomockCtrl(t)))
	})
}

// gomockCtrl builds a gomock controller bound to the test.
func gomockCtrl(t *testing.T) *gomock.Controller {
	return gomock.NewController(t)
}
