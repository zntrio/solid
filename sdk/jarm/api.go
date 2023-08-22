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

package jarm

import (
	"context"

	corev1 "zntr.io/solid/api/oidc/core/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
)

const (
	// HeaderType defines typ claim value
	HeaderType = "jarm+jwt"
)

// ResponseDecoder describes Authorization Response Decoder contract.
type ResponseDecoder interface {
	Decode(ctx context.Context, audience, response string) (*flowv1.AuthorizeResponse, error)
}

// ResponseEncoder describes Authorization Response Encoder contract.
type ResponseEncoder interface {
	Encode(ctx context.Context, issuer string, resp *flowv1.AuthorizeResponse) (string, error)
}

// Response repsents decoded JARM
type Response struct {
	Issuer    string
	Audience  string
	ExpiresAt uint64
	Code      string
	State     string
	Error     *corev1.Error
}
