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

package jwsreq

import (
	"context"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
)

const (
	//nolint:gosec // detected as hardcoded credentials
	tokenHdrType = "oauth.authz.req+jwt"
)

//go:generate mockgen -destination mock/authorization_decoder.gen.go -package mock zntr.io/solid/pkg/request AuthorizationDecoder

// AuthorizationDecoder describes authorization decoder contract.
type AuthorizationDecoder interface {
	Decode(ctx context.Context, value string) (*corev1.AuthorizationRequest, error)
}

//go:generate mockgen -destination mock/authorization_encoder.gen.go -package mock zntr.io/solid/pkg/request AuthorizationEncoder

// AuthorizationEncoder describes authorization encoder contract.
type AuthorizationEncoder interface {
	Encode(ctx context.Context, ar *corev1.AuthorizationRequest) (string, error)
}

//go:generate mockgen -destination mock/authorization.gen.go -package mock zntr.io/solid/pkg/request Authorization

// Authorization describes authorization request codec contract.
type Authorization interface {
	AuthorizationDecoder
	AuthorizationEncoder
}
