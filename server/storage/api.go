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

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	resourcev1 "zntr.io/solid/api/oidc/resource/v1"
	sessionv1 "zntr.io/solid/api/oidc/session/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
)

// ErrNotFound is returned when the query return no result.
var ErrNotFound = errors.New("no result found")

//go:generate mockgen -destination mock/clientreader.gen.go -package mock zntr.io/solid/server/storage ClientReader

// ClientReader defines client storage read-only operation contract.
type ClientReader interface {
	Get(ctx context.Context, id string) (*clientv1.Client, error)
	GetByName(ctx context.Context, name string) (*clientv1.Client, error)
}

//go:generate mockgen -destination mock/client_writer.gen.go -package mock zntr.io/solid/server/storage ClientWriter

// ClientWriter describes client storage write-only operation contract.
type ClientWriter interface {
	Register(ctx context.Context, c *clientv1.Client) (string, error)
}

//go:generate mockgen -destination mock/client.gen.go -package mock zntr.io/solid/server/storage Client

// Client describes complete client storage contract.
type Client interface {
	ClientReader
	ClientWriter
}

//go:generate mockgen -destination mock/authorization_request_reader.gen.go -package mock zntr.io/solid/server/storage AuthorizationRequestReader

// AuthorizationRequestReader describes authorization request storage read-only operation contract.
type AuthorizationRequestReader interface {
	Get(ctx context.Context, issuer, requestURI string) (*flowv1.AuthorizationRequest, error)
}

//go:generate mockgen -destination mock/authorization_request_writer.gen.go -package mock zntr.io/solid/server/storage AuthorizationRequestWriter

// AuthorizationRequestWriter describes authorization request storage write-only operation contract.
type AuthorizationRequestWriter interface {
	Register(ctx context.Context, issuer, requestURI string, req *flowv1.AuthorizationRequest) (uint64, error)
	Delete(ctx context.Context, issuer, requestURI string) error
}

//go:generate mockgen -destination mock/authorization_request.gen.go -package mock zntr.io/solid/server/storage AuthorizationRequest

// AuthorizationRequest describes complete authorization request storage operation contract.
type AuthorizationRequest interface {
	AuthorizationRequestReader
	AuthorizationRequestWriter
}

//go:generate mockgen -destination mock/token_reader.gen.go -package mock zntr.io/solid/server/storage TokenReader

// TokenReader describes accessToken read-only operation storage contract.
type TokenReader interface {
	Get(ctx context.Context, issuer, id string) (*tokenv1.Token, error)
	GetByValue(ctx context.Context, issuer, value string) (*tokenv1.Token, error)
}

//go:generate mockgen -destination mock/token_writer.gen.go -package mock zntr.io/solid/server/storage TokenWriter

// TokenWriter describes accessToken write-only operation contract.
type TokenWriter interface {
	Create(ctx context.Context, issuer string, t *tokenv1.Token) error
	Delete(ctx context.Context, issuer, id string) error
	Revoke(ctx context.Context, issuer, id string) error
}

//go:generate mockgen -destination mock/token.gen.go -package mock zntr.io/solid/server/storage Token

// Token describes accessToken operation contract.
type Token interface {
	TokenReader
	TokenWriter
}

//go:generate mockgen -destination mock/authorization_code_session_reader.gen.go -package mock zntr.io/solid/server/storage AuthorizationCodeSessionReader

// AuthorizationCodeSessionReader describes read-only storage operation contract.
type AuthorizationCodeSessionReader interface {
	Get(ctx context.Context, issuer, code string) (*sessionv1.AuthorizationCodeSession, error)
}

//go:generate mockgen -destination mock/authorization_code_session_writer.gen.go -package mock zntr.io/solid/server/storage AuthorizationCodeSessionWriter

// AuthorizationCodeSessionWriter describes write-only operation contract.
type AuthorizationCodeSessionWriter interface {
	Register(ctx context.Context, issuer, code string, s *sessionv1.AuthorizationCodeSession) (uint64, error)
	Delete(ctx context.Context, issuer, code string) error
}

//go:generate mockgen -destination mock/authorization_code_session.gen.go -package mock zntr.io/solid/server/storage AuthorizationCodeSession

// AuthorizationCodeSession describes user session operation contract.
type AuthorizationCodeSession interface {
	AuthorizationCodeSessionReader
	AuthorizationCodeSessionWriter
}

//go:generate mockgen -destination mock/device_code_session_writer.gen.go -package mock zntr.io/solid/server/storage DeviceCodeSessionWriter

// DeviceCodeSessionWriter describes deviceCode write-only operation contract.
type DeviceCodeSessionWriter interface {
	Register(ctx context.Context, issuer, userCode string, r *sessionv1.DeviceCodeSession) (uint64, error)
	Delete(ctx context.Context, issuer, userCode string) error
	Validate(ctx context.Context, issuer, userCode string, r *sessionv1.DeviceCodeSession) error
}

//go:generate mockgen -destination mock/device_code_session_reader.gen.go -package mock zntr.io/solid/server/storage DeviceCodeSessionReader

// DeviceCodeSessionReader describes deviceCode read-only operation contract.
type DeviceCodeSessionReader interface {
	GetByDeviceCode(ctx context.Context, issuer, deviceCode string) (*sessionv1.DeviceCodeSession, error)
	GetByUserCode(ctx context.Context, issuer, userCode string) (*sessionv1.DeviceCodeSession, error)
}

//go:generate mockgen -destination mock/device_code_session.gen.go -package mock zntr.io/solid/server/storage DeviceCodeSession

// DeviceCodeSession describes deviceCode operation contract.
type DeviceCodeSession interface {
	DeviceCodeSessionReader
	DeviceCodeSessionWriter
}

//go:generate mockgen -destination mock/dpop.gen.go -package mock zntr.io/solid/server/storage DPoP

// DPoP describes dpop proof jti storage to prevent dpop replay attack.
type DPoP interface {
	Register(ctx context.Context, id string) error
	Delete(ctx context.Context, id string) error
	Exists(ctx context.Context, id string) (bool, error)
}

//go:generate mockgen -destination mock/resource_reader.gen.go -package mock zntr.io/solid/server/storage ResourceReader

// ResourceReader describes resource resolver contract.
type ResourceReader interface {
	GetByURI(ctx context.Context, urn string) (*resourcev1.Resource, error)
}

//go:generate mockgen -destination mock/resource.gen.go -package mock zntr.io/solid/server/storage Resource

type Resource interface {
	ResourceReader
}
