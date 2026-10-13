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
	"fmt"
	"hash"
	"sync"

	"golang.org/x/crypto/blake2b"
)

// deriveHasher is a small pool of keyed BLAKE2b-256 hashers keyed with the
// storage secret. Deriving a storage key is the hottest allocation source
// in the in-memory backends (one fresh digest per lookup); pooling removes
// that per-lookup allocation while keeping the keyed construction cost at
// init time only.
type deriveHasher struct {
	pool sync.Pool
}

func newDeriveHasher(secretKey []byte) *deriveHasher {
	return &deriveHasher{
		pool: sync.Pool{
			New: func() any {
				h, err := blake2b.New256(secretKey)
				if err != nil {
					// blake2b.New256 only errors on an invalid key size;
					// the constructor contract makes that a programming
					// error surfaced at first use.
					panic(fmt.Errorf("unable to initialize storage key derivation: %w", err))
				}
				return h
			},
		},
	}
}

// deriveHex returns the keyed hexadecimal digest of domain, issuer and value.
func (d *deriveHasher) deriveHex(domain, issuer, value string) string {
	h := d.pool.Get().(hash.Hash) //nolint:forcetypeassert // New only stores hash.Hash
	h.Reset()

	h.Write([]byte(domain))
	h.Write([]byte(issuer))
	h.Write([]byte(value))

	sum := h.Sum(nil)
	d.pool.Put(h)

	return fmt.Sprintf("%x", sum)
}
