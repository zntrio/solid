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
	"sync"
	"time"
)

// ttlCache is a minimal thread-safe in-memory cache with per-entry TTL,
// built on the standard library only. It is a drop-in replacement for
// patrickmn/go-cache covering the subset of features used in this package.
type ttlCache struct {
	mu             sync.RWMutex
	items          map[string]ttlEntry
	defaultTTL     time.Duration
	cleanupStop    chan struct{}
	cleanupStopped sync.Once
}

type ttlEntry struct {
	value     any
	expiresAt time.Time
}

// newTTLCache returns a cache with the given default TTL and a background
// janitor purging expired entries at the given interval. The janitor is
// stopped when Stop is called; entries are also purged lazily on access.
// defaultCleanupInterval is the fixed TTL cache cleanup period.
const defaultCleanupInterval = 10 * time.Minute

func newTTLCache(defaultTTL time.Duration) *ttlCache {
	c := &ttlCache{
		items:       make(map[string]ttlEntry),
		defaultTTL:  defaultTTL,
		cleanupStop: make(chan struct{}),
	}
	go c.janitor(defaultCleanupInterval)
	return c
}

// Set stores the value under the key with the default TTL.
func (c *ttlCache) Set(key string, value any) {
	c.mu.Lock()
	c.items[key] = ttlEntry{value: value, expiresAt: time.Now().Add(c.defaultTTL)}
	c.mu.Unlock()
}

// Get returns the value stored under the key, and whether it was present
// and not expired.
func (c *ttlCache) Get(key string) (any, bool) {
	c.mu.RLock()
	entry, found := c.items[key]
	c.mu.RUnlock()

	if !found || time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.value, true
}

// Delete removes the value stored under the key, if any.
func (c *ttlCache) Delete(key string) {
	c.mu.Lock()
	delete(c.items, key)
	c.mu.Unlock()
}

// DeleteAndGet atomically removes and returns the value stored under the key.
// It behaves like a Get immediately followed by a Delete, without an
// interleaving window between the two operations.
func (c *ttlCache) DeleteAndGet(key string) (any, bool) {
	c.mu.Lock()
	entry, found := c.items[key]
	if found {
		delete(c.items, key)
	}
	c.mu.Unlock()

	if !found || time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.value, true
}

// Stop terminates the background janitor. Calling Stop more than once is
// safe and cheap.
func (c *ttlCache) Stop() {
	c.cleanupStopped.Do(func() { close(c.cleanupStop) })
}

func (c *ttlCache) janitor(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.cleanupStop:
			return
		case <-ticker.C:
			c.mu.Lock()
			now := time.Now()
			for key, entry := range c.items {
				if now.After(entry.expiresAt) {
					delete(c.items, key)
				}
			}
			c.mu.Unlock()
		}
	}
}
