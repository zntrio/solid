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

// Package msgval provides the shared syntactic validation level of every
// service: protovalidate rules declared on the protobuf messages (required
// fields, length bounds, uri/pattern syntax). Semantic rules (cross-field,
// storage, cryptography) belong to the business logic and are never
// expressed here.
package msgval

import (
	"errors"
	"fmt"
	"sync"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/reflect/protoreflect"

	corev1 "zntr.io/solid/api/oidc/core/v1"
	"zntr.io/solid/sdk/rfcerrors"
)

var (
	initOnce sync.Once

	validator protovalidate.Validator
	initErr   error

	// errNilMessage reports a nil message passed to Validate.
	errNilMessage = errors.New("msgval: nil message")
)

// Probe initializes the shared protovalidate evaluator and reports any
// environment-level failure. Constructors call it to fail fast on a
// misconfigured deployment; a working environment is a nil return.
func Probe() error {
	initOnce.Do(func() {
		validator, initErr = protovalidate.New()
	})
	if initErr != nil {
		return fmt.Errorf("unable to initialize the message validator: %w", initErr)
	}
	return nil
}

// Validate applies the protovalidate annotations of msg. A nil message
// reports errNilMessage.
func Validate(msg protoreflect.ProtoMessage) error {
	if err := Probe(); err != nil {
		return err
	}
	if msg == nil {
		return errNilMessage
	}
	return validator.Validate(msg)
}

// ValidateOrError applies Validate and maps a failure onto the RFC 6749
// invalid_request protocol error.
func ValidateOrError(msg protoreflect.ProtoMessage) *corev1.Error {
	if msg == nil {
		return rfcerrors.InvalidRequest().Description("request is nil").Build()
	}
	if err := Validate(msg); err != nil {
		return rfcerrors.InvalidRequest().Description(err.Error()).Build()
	}
	return nil
}
