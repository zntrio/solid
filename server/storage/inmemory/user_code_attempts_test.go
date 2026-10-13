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
// KIND, either express or implied. See the License for the
// specific language governing permissions and limitations
// under the License.

package inmemory

import (
	"testing"
	"time"
)

func TestUserCodeAttemptsExpiredEntryPurgedOnRead(t *testing.T) {
	s := &userCodeAttemptsStorage{entries: make(map[string]userCodeAttemptEntry)}
	// Seed an expired entry directly (white-box).
	s.entries["expired-key"] = userCodeAttemptEntry{
		count:     3,
		expiresAt: time.Now().Add(-time.Second),
	}

	if got := s.Failures(t.Context(), "expired-key"); got != 0 {
		t.Fatalf("Failures on expired entry: want 0, got %d", got)
	}
	if len(s.entries) != 0 {
		t.Fatalf("expired entry not purged: map still holds %d entry(ies)", len(s.entries))
	}
}

func TestUserCodeAttemptsActiveEntryRetained(t *testing.T) {
	s := &userCodeAttemptsStorage{entries: make(map[string]userCodeAttemptEntry)}

	if got := s.Fail(t.Context(), "active-key", time.Minute); got != 1 {
		t.Fatalf("Fail: want 1, got %d", got)
	}
	if got := s.Failures(t.Context(), "active-key"); got != 1 {
		t.Fatalf("Failures on active entry: want 1, got %d", got)
	}
	if len(s.entries) != 1 {
		t.Fatalf("active entry must be retained: map holds %d entry(ies)", len(s.entries))
	}

	s.Reset(t.Context(), "active-key")
	if got := s.Failures(t.Context(), "active-key"); got != 0 {
		t.Fatalf("Failures after Reset: want 0, got %d", got)
	}
}
