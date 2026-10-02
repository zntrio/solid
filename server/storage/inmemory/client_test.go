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

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/server/storage"
)

func Test_clientStorage(t *testing.T) {
	ctx := context.Background()

	t.Run("Update replaces a registered client", func(t *testing.T) {
		s := Clients()
		c := &clientv1.Client{ClientName: "before"}
		id, err := s.Register(ctx, c)
		if err != nil {
			t.Fatalf("Register() error = %v", err)
		}

		updated := &clientv1.Client{ClientId: id, ClientName: "after"}
		if err := s.Update(ctx, updated); err != nil {
			t.Fatalf("Update() error = %v", err)
		}

		got, err := s.Get(ctx, id)
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if got.GetClientName() != "after" {
			t.Errorf("Get() name = %q, want %q", got.GetClientName(), "after")
		}
	})

	t.Run("Update of missing client returns ErrNotFound", func(t *testing.T) {
		s := Clients()
		if err := s.Update(ctx, &clientv1.Client{ClientId: "no-such-client"}); err != storage.ErrNotFound {
			t.Errorf("Update() err = %v, want ErrNotFound", err)
		}
	})

	t.Run("Delete removes a registered client", func(t *testing.T) {
		s := Clients()
		id, err := s.Register(ctx, &clientv1.Client{ClientName: "doomed"})
		if err != nil {
			t.Fatalf("Register() error = %v", err)
		}

		if err := s.Delete(ctx, id); err != nil {
			t.Fatalf("Delete() error = %v", err)
		}

		if _, err := s.Get(ctx, id); err != storage.ErrNotFound {
			t.Errorf("Get() after Delete() err = %v, want ErrNotFound", err)
		}
	})

	t.Run("Delete of missing client returns ErrNotFound", func(t *testing.T) {
		s := Clients()
		if err := s.Delete(ctx, "no-such-client"); err != storage.ErrNotFound {
			t.Errorf("Delete() err = %v, want ErrNotFound", err)
		}
	})
}
