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
	"time"
)

func TestUserCodeAttemptsFailIncrements(t *testing.T) {
	s := UserCodeAttempts()
	ctx := context.Background()

	for i := uint64(1); i <= 3; i++ {
		if got := s.Fail(ctx, "k", time.Minute); got != i {
			t.Fatalf("Fail() = %d, want %d", got, i)
		}
	}
	if got := s.Failures(ctx, "k"); got != 3 {
		t.Fatalf("Failures() = %d, want 3", got)
	}
}

func TestUserCodeAttemptsResetClears(t *testing.T) {
	s := UserCodeAttempts()
	ctx := context.Background()

	s.Fail(ctx, "k", time.Minute)
	s.Reset(ctx, "k")

	if got := s.Failures(ctx, "k"); got != 0 {
		t.Fatalf("Failures() after Reset = %d, want 0", got)
	}
}

func TestUserCodeAttemptsExpiry(t *testing.T) {
	s := UserCodeAttempts()
	ctx := context.Background()

	s.Fail(ctx, "k", 10*time.Millisecond)
	time.Sleep(20 * time.Millisecond)

	if got := s.Failures(ctx, "k"); got != 0 {
		t.Fatalf("Failures() after expiry = %d, want 0", got)
	}
	if got := s.Fail(ctx, "k", time.Minute); got != 1 {
		t.Fatalf("Fail() after expiry = %d, want 1 (fresh window)", got)
	}
}
