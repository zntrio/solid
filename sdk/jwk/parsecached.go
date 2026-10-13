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

package jwk

import (
	"crypto/sha256"
	"sync"
)

// maxParsedSetCacheSize bounds the parsed-set cache. It is a defense
// against unbounded growth when an attacker feeds many distinct JWKS
// documents through a parse path protected by the cache (eviction is
// random, matching the attack being pure throughput).
const maxParsedSetCacheSize = 128

var parsedSetCache = struct {
	sync.Mutex
	entries map[[sha256.Size]byte]Set
}{
	entries: make(map[[sha256.Size]byte]Set),
}

// ParseCached behaves exactly like Parse but memoizes the result keyed by
// the SHA-256 of the document bytes: identical bytes always return the same
// parsed Set, different bytes always re-parse. There is no staleness window
// — key rotation changes the document, which changes the key, which misses
// the cache. Use it on hot paths that re-parse the same static JWKS
// documents (e.g. per-request client JWKS parsing); documents that vary
// per call (assertion cnf.jwk) must use Parse to avoid cache pollution.
func ParseCached(data []byte) (Set, error) {
	key := sha256.Sum256(data)

	parsedSetCache.Lock()
	set, hit := parsedSetCache.entries[key]
	parsedSetCache.Unlock()
	if hit {
		return set, nil
	}

	set, err := Parse(data)
	if err != nil {
		return nil, err
	}

	parsedSetCache.Lock()
	if len(parsedSetCache.entries) >= maxParsedSetCacheSize {
		// Random eviction keeps the defense cheap while leaving a
		// deterministic bound; a large synthetic miss stream cannot grow
		// the map beyond the cap.
		for k := range parsedSetCache.entries {
			delete(parsedSetCache.entries, k)
			break
		}
	}
	parsedSetCache.entries[key] = set
	parsedSetCache.Unlock()

	return set, nil
}
