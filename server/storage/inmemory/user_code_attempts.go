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
	"time"

	"zntr.io/solid/server/storage"
)

type userCodeAttemptEntry struct {
	count     uint64
	expiresAt time.Time
}

type userCodeAttemptsStorage struct {
	mu      sync.Mutex
	entries map[string]userCodeAttemptEntry
}

// UserCodeAttempts returns a user-code failure throttle store (RFC 8628
// section 5.1, RFC 10027 section 6.1.11).
func UserCodeAttempts() storage.UserCodeAttempts {
	return &userCodeAttemptsStorage{
		entries: make(map[string]userCodeAttemptEntry),
	}
}

func (s *userCodeAttemptsStorage) Failures(ctx context.Context, key string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return 0
	}
	return entry.count
}

func (s *userCodeAttemptsStorage) Fail(ctx context.Context, key string, window time.Duration) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	entry, ok := s.entries[key]
	if !ok || now.After(entry.expiresAt) {
		s.entries[key] = userCodeAttemptEntry{count: 1, expiresAt: now.Add(window)}
		return 1
	}
	entry.count++
	entry.expiresAt = now.Add(window)
	s.entries[key] = entry
	return entry.count
}

func (s *userCodeAttemptsStorage) Reset(ctx context.Context, key string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.entries, key)
}
