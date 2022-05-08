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

package rfcerrors

import (
	corev1 "zntr.io/solid/api/oidc/core/v1"
	"zntr.io/solid/sdk/types"
)

// -----------------------------------------------------------------------------

// ErrorBuilder describes error builder contract.
type ErrorBuilder interface {
	State(value string) ErrorBuilder
	Description(value string) ErrorBuilder
	Build() *corev1.Error
}

type defaultErrorBuilder struct {
	err              string
	errorDescription string
	errorURI         string
	state            string
}

func (eb *defaultErrorBuilder) State(value string) ErrorBuilder {
	eb.state = value
	return eb
}

func (eb *defaultErrorBuilder) Err(value string) ErrorBuilder {
	eb.err = value
	return eb
}

func (eb *defaultErrorBuilder) Description(value string) ErrorBuilder {
	eb.errorDescription = value
	return eb
}

func (eb *defaultErrorBuilder) ErrorURI(value string) ErrorBuilder {
	eb.errorURI = value
	return eb
}

func (eb *defaultErrorBuilder) Build() *corev1.Error {
	// Create error object
	err := &corev1.Error{
		Err:              eb.err,
		ErrorDescription: eb.errorDescription,
	}
	if eb.state != "" {
		err.State = types.StringRef(eb.state)
	}
	if eb.errorURI != "" {
		err.ErrorUri = types.StringRef(eb.errorURI)
	}

	// Return error instance
	return err
}
