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
	"fmt"

	"buf.build/go/protovalidate"

	corev1 "zntr.io/solid/api/oidc/core/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	"zntr.io/solid/sdk/rfcerrors"
)

// messageValidator applies the syntactic validation level: the protovalidate
// rules declared on the protobuf messages (required fields, length bounds,
// uri/pattern syntax). It intentionally excludes any semantic rule — those
// belong to the business logic.
type messageValidator struct {
	validator protovalidate.Validator
}

// newMessageValidator returns a messageValidator, or fails if the underlying
// protovalidate environment cannot be built.
func newMessageValidator() (*messageValidator, error) {
	v, err := protovalidate.New()
	if err != nil {
		return nil, fmt.Errorf("unable to initialize the message validator: %w", err)
	}
	return &messageValidator{validator: v}, nil
}

// ValidateTokenRequest applies syntactic validation rules to a TokenRequest.
// A nil request is reported as invalid_request, matching the previous
// hand-rolled behavior.
func (m *messageValidator) ValidateTokenRequest(req *flowv1.TokenRequest) *corev1.Error {
	if req == nil {
		return rfcerrors.InvalidRequest().Description("request is nil").Build()
	}

	if err := m.validator.Validate(req); err != nil {
		return rfcerrors.InvalidRequest().Description(err.Error()).Build()
	}

	return nil
}
