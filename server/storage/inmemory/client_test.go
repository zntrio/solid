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
	"sync"
	"testing"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
)

// TestClientStorageConcurrentAccess exercises concurrent readers and writers
// on the shared client store; run with -race it fails on the unsynchronized
// map implementation and passes with the RWMutex-guarded one.
func TestClientStorageConcurrentAccess(t *testing.T) {
	store := clientStorage{backend: map[string]*clientv1.Client{}}
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(3)
		go func(i int) {
			defer wg.Done()
			id, err := store.Register(ctx, &clientv1.Client{ClientName: "race-client"})
			if err != nil {
				t.Errorf("register: %v", err)
			}
			_ = id
		}(i)
		go func(i int) {
			defer wg.Done()
			if _, err := store.Get(ctx, "t8p9duw4n2klximkv3kagaud796ul67g"); err == nil {
				// fixture may or may not exist; only the race matters
			}
		}(i)
		go func(i int) {
			defer wg.Done()
			if _, err := store.GetByName(ctx, "race-client"); err == nil {
				// may or may not be found; only the race matters
			}
		}(i)
	}
	wg.Wait()
}

// TestClientStorageGetReturnsCopy asserts the reader path hands out deep
// copies: mutating the returned client must not corrupt the stored record.
func TestClientStorageGetReturnsCopy(t *testing.T) {
	store := clientStorage{backend: map[string]*clientv1.Client{
		"client-a": {ClientId: "client-a", ClientName: "original"},
	}}
	ctx := context.Background()

	got, err := store.Get(ctx, "client-a")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	got.ClientName = "mutated"

	again, err := store.Get(ctx, "client-a")
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	if again.ClientName != "original" {
		t.Fatalf("stored record mutated through reader path: %q", again.ClientName)
	}
}
