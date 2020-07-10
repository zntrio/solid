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

package reactor

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	"zntr.io/solid/pkg/sdk/types"
)

type defaultReactor struct {
	name string

	locker   sync.Mutex
	handlers map[reflect.Type]Handler
}

// New instantiate a default reactor instance.
func New(name string) Reactor {
	return &defaultReactor{
		name:     name,
		handlers: map[reflect.Type]Handler{},
	}
}

// -----------------------------------------------------------------------------

func (r *defaultReactor) Send(ctx context.Context, req interface{}, cb Callback) error {
	// Check if request is nil
	if types.IsNil(req) {
		return fmt.Errorf("reactor(%s): request must not be nil", r.name)
	}

	// Request has registered handler ?
	h, ok := r.handlers[reflect.TypeOf(req)]
	if !ok {
		return fmt.Errorf("reactor(%s): unexpected msg type received (%T)", r.name, req)
	}

	// Fork as goroutine
	go func() {
		res, err := h.Handle(ctx, req)
		cb(ctx, res, err)
	}()

	// No error
	return nil
}

func (r *defaultReactor) Do(ctx context.Context, req interface{}) (interface{}, error) {
	// Check if request is nil
	if types.IsNil(req) {
		return nil, fmt.Errorf("reactor(%s): request must not be nil", r.name)
	}

	// Request has registered handler ?
	h, ok := r.handlers[reflect.TypeOf(req)]
	if !ok {
		return nil, fmt.Errorf("reactor(%s): unexpected msg type received (%T)", r.name, req)
	}

	// Delegate to handler
	return h.Handle(ctx, req)
}

func (r *defaultReactor) RegisterHandler(msg interface{}, fn Handler) {
	r.locker.Lock()
	r.handlers[reflect.TypeOf(msg)] = fn
	r.locker.Unlock()
}
