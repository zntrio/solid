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

package storage

import (
	"context"
	"errors"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
)

// ErrNotFound is returned when the query return no result.
var ErrNotFound = errors.New("no result found")

//go:generate mockgen -destination mock/clientreader.gen.go -package mock zntr.io/solid/pkg/storage ClientReader

// ClientReader defines client storage read-only operation contract.
type ClientReader interface {
	Get(ctx context.Context, id string) (*corev1.Client, error)
}

//go:generate mockgen -destination mock/client_writer.gen.go -package mock zntr.io/solid/pkg/storage ClientWriter

// ClientWriter describes client storage write-only operation contract.
type ClientWriter interface {
	Register(ctx context.Context, c *corev1.Client) (string, error)
}

//go:generate mockgen -destination mock/client.gen.go -package mock zntr.io/solid/pkg/storage Client

// Client describes complete client storage contract.
type Client interface {
	ClientReader
	ClientWriter
}

//go:generate mockgen -destination mock/authorization_request_reader.gen.go -package mock zntr.io/solid/pkg/storage AuthorizationRequestReader

// AuthorizationRequestReader describes authorization request storage read-only operation contract.
type AuthorizationRequestReader interface {
	Get(ctx context.Context, requestURI string) (*corev1.AuthorizationRequest, error)
}

//go:generate mockgen -destination mock/authorization_request_writer.gen.go -package mock zntr.io/solid/pkg/storage AuthorizationRequestWriter

// AuthorizationRequestWriter describes authorization request storage write-only operation contract.
type AuthorizationRequestWriter interface {
	Register(ctx context.Context, req *corev1.AuthorizationRequest) (string, uint64, error)
	Delete(ctx context.Context, requestURI string) error
}

//go:generate mockgen -destination mock/authorization_request.gen.go -package mock zntr.io/solid/pkg/storage AuthorizationRequest

// AuthorizationRequest describes complete authorization request storage operation contract.
type AuthorizationRequest interface {
	AuthorizationRequestReader
	AuthorizationRequestWriter
}

//go:generate mockgen -destination mock/token_reader.gen.go -package mock zntr.io/solid/pkg/storage TokenReader

// TokenReader describes accessToken read-only operation storage contract.
type TokenReader interface {
	Get(ctx context.Context, id string) (*corev1.Token, error)
	GetByValue(ctx context.Context, value string) (*corev1.Token, error)
}

//go:generate mockgen -destination mock/token_writer.gen.go -package mock zntr.io/solid/pkg/storage TokenWriter

// TokenWriter describes accessToken write-only operation contract.
type TokenWriter interface {
	Create(ctx context.Context, t *corev1.Token) error
	Delete(ctx context.Context, id string) error
	Revoke(ctx context.Context, id string) error
}

//go:generate mockgen -destination mock/token.gen.go -package mock zntr.io/solid/pkg/storage Token

// Token describes accessToken operation contract.
type Token interface {
	TokenReader
	TokenWriter
}

//go:generate mockgen -destination mock/authorization_code_session_reader.gen.go -package mock zntr.io/solid/pkg/storage AuthorizationCodeSessionReader

// AuthorizationCodeSessionReader describes read-only storage operation contract.
type AuthorizationCodeSessionReader interface {
	Get(ctx context.Context, code string) (*corev1.AuthorizationCodeSession, error)
}

//go:generate mockgen -destination mock/authorization_code_session_writer.gen.go -package mock zntr.io/solid/pkg/storage AuthorizationCodeSessionWriter

// AuthorizationCodeSessionWriter describes write-only operation contract.
type AuthorizationCodeSessionWriter interface {
	Register(ctx context.Context, s *corev1.AuthorizationCodeSession) (string, uint64, error)
	Delete(ctx context.Context, code string) error
}

//go:generate mockgen -destination mock/authorization_code_session.gen.go -package mock zntr.io/solid/pkg/storage AuthorizationCodeSession

// AuthorizationCodeSession describes user session operation contract.
type AuthorizationCodeSession interface {
	AuthorizationCodeSessionReader
	AuthorizationCodeSessionWriter
}

//go:generate mockgen -destination mock/device_code_session_writer.gen.go -package mock zntr.io/solid/pkg/storage DeviceCodeSessionWriter

// DeviceCodeSessionWriter describes deviceCode write-only operation contract.
type DeviceCodeSessionWriter interface {
	Register(ctx context.Context, r *corev1.DeviceCodeSession) (string, string, uint64, error)
	Delete(ctx context.Context, id string) error
}

//go:generate mockgen -destination mock/device_code_session_reader.gen.go -package mock zntr.io/solid/pkg/storage DeviceCodeSessionReader

// DeviceCodeSessionReader describes deviceCode read-only operation contract.
type DeviceCodeSessionReader interface {
	Get(ctx context.Context, id string) (*corev1.DeviceCodeSession, error)
}

//go:generate mockgen -destination mock/device_code_session.gen.go -package mock zntr.io/solid/pkg/storage DeviceCodeSession

// DeviceCodeSession describes deviceCode operation contract.
type DeviceCodeSession interface {
	DeviceCodeSessionReader
	DeviceCodeSessionWriter
}

//go:generate mockgen -destination mock/dpop.gen.go -package mock zntr.io/solid/pkg/storage DPoP

// DPoP describes dpop proof jti storage to prevent dpop replay attack.
type DPoP interface {
	Register(ctx context.Context, id string) error
	Delete(ctx context.Context, id string) error
	Exists(ctx context.Context, id string) (bool, error)
}
