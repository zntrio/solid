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
)

// Handler describes a command handler
type Handler interface {
	Handle(ctx context.Context, req interface{}) (interface{}, error)
}

// -----------------------------------------------------------------------------

// HandlerFunc describes a function implementation.
type HandlerFunc func(context.Context, interface{}) (interface{}, error)

// Handle call the wrapped function
func (f HandlerFunc) Handle(ctx context.Context, req interface{}) (interface{}, error) {
	return f(ctx, req)
}

// -----------------------------------------------------------------------------

// Callback function for asynchronous event handling.
type Callback func(context.Context, interface{}, error)

// Reactor defines reactor contract.
type Reactor interface {
	// Send the reques to the reactor as an asynchronous call.
	Send(ctx context.Context, req interface{}, cb Callback) error
	// Do the request as a synchronous call.
	Do(ctx context.Context, req interface{}) (interface{}, error)
	// Register a message type handler
	RegisterHandler(msg interface{}, fn Handler)
}
