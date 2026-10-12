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

package token

import (
	"time"

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
)

// IsUsable check token usability constraint.
func IsUsable(t *tokenv1.Token) bool {
	// Check arguments
	if t == nil {
		return false
	}
	if t.Metadata == nil {
		return false
	}

	// Check expiration
	now := uint64(time.Now().Unix()) //nolint:gosec // Unix time is non-negative
	if t.Metadata.ExpiresAt < now {
		return false
	}
	if t.Metadata.NotBefore > now {
		return false
	}

	// No error
	return true
}

// JSONActor is the RFC 8693 section 4.4 "act" member entry: the acting
// party subject with a nested "act" chain of prior delegations.
type JSONActor struct {
	Sub string     `json:"sub"`
	Act *JSONActor `json:"act,omitempty"`
}

// ActorAsJSON converts the flat actor chain (immediate actor first, then
// prior delegations) into the nested RFC 8693 section 4.4 shape
// {"sub": ..., "act": {"sub": ...}}. It is nil-safe: an empty chain
// yields nil.
func ActorAsJSON(actors []*tokenv1.Actor) *JSONActor {
	if len(actors) == 0 {
		return nil
	}
	// Right fold: the last entry is the innermost delegation.
	chain := &JSONActor{Sub: actors[len(actors)-1].Subject}
	for i := len(actors) - 2; i >= 0; i-- {
		chain = &JSONActor{Sub: actors[i].Subject, Act: chain}
	}
	return chain
}
