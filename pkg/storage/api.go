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

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"

	registrationv1 "go.zenithar.org/solid/api/gen/go/oidc/registration/v1"
)

// ErrNotFound is returned when the query return no result.
var ErrNotFound = errors.New("no result found")

//go:generate mockgen -destination mock/clientreader.gen.go -package mock go.zenithar.org/solid/pkg/storage ClientReader

// ClientReader defines client storage read-only operation contract.
type ClientReader interface {
	Get(ctx context.Context, id string) (*registrationv1.Client, error)
}

//go:generate mockgen -destination mock/client.gen.go -package mock go.zenithar.org/solid/pkg/storage Client

// Client describes complete client storage contract.
type Client interface {
	ClientReader
}

//go:generate mockgen -destination mock/authorization_request_reader.gen.go -package mock go.zenithar.org/solid/pkg/storage AuthorizationRequestReader

// AuthorizationRequestReader describes authorization request storage read-only operation contract.
type AuthorizationRequestReader interface {
	GetByRequestURI(ctx context.Context, requestURI string) (*corev1.AuthorizationRequest, error)
	GetByCode(ctx context.Context, code string) (*corev1.AuthorizationRequest, error)
}

//go:generate mockgen -destination mock/authorization_request_writer.gen.go -package mock go.zenithar.org/solid/pkg/storage AuthorizationRequestWriter

// AuthorizationRequestWriter describes authorization request storage write-only operation contract.
type AuthorizationRequestWriter interface {
	Register(ctx context.Context, req *corev1.AuthorizationRequest) (string, error)
	Delete(ctx context.Context, requestURI string) error
}
